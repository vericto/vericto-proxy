// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The database version the upstream reports, against the parser's (4.20.0).
//!
//! The engine parses PostgreSQL with `pg_query` (libpg_query), which carries
//! the grammar of one PostgreSQL major version. A database of a newer major
//! accepts syntax that grammar does not know: such a statement cannot be
//! parsed, and the proxy handles it as a parse error (`VERICTO-PARSE-ERROR`):
//! refused when parse errors fail closed (the workspace policy, or a `block` /
//! `mask` sensitive column, or an enforced agent allowlist), forwarded and
//! flagged under the fail-open default. Nothing here changes that; this module
//! only says when it can happen.
//!
//! - **PostgreSQL**: the server sends `server_version` in a ParameterStatus
//!   during startup. The relay hands it here once per connection (never per
//!   statement). When its major is newer than the parser's, one
//!   `alert = "upstream_newer_than_parser"` warning is logged per upstream
//!   target, and again only if a later connection reports a still newer major.
//!   An equal or older major is logged at debug; a version the proxy cannot
//!   read is logged at debug and ignored.
//! - **MySQL**: the server version of the handshake greeting is recorded and
//!   logged at debug when it first appears (or changes). `sqlparser` has no
//!   versioned grammar, so there is nothing to compare it with.
//!
//! What is recorded is exposed on the rule-sync heartbeat
//! (`telemetry::heartbeat`, field `upstream`) and on `/metrics`.
//!
//! **The parser's major version** is read from `pg_query` itself, not written
//! down here: every parse tree it returns carries the `PG_VERSION_NUM` its
//! libpg_query was built from (`ParseResult::protobuf.version`, e.g. 170007),
//! so it is parsed once, on first use, and follows any `pg_query` bump with no
//! constant to keep in step. The proxy and the engine resolve to one
//! `pg_query` (Cargo.toml; the test `one_pg_query_in_the_lock_file` fails if
//! that ever stops being true), so this is the engine's parser.
//!
//! Memory: one entry per upstream target (host:port; a proxy process has one),
//! at most [`MAX_TARGETS`], each with a version string of at most
//! [`MAX_VERSION_CHARS`].

use std::sync::{LazyLock, Mutex};

use serde::Serialize;

/// Upstream targets tracked per process. A proxy fronts one; the bound only
/// keeps a misuse from growing the table.
pub const MAX_TARGETS: usize = 16;

/// Longest server version kept (`16.4 (Debian 16.4-1.pgdg120+2)` is 30).
pub const MAX_VERSION_CHARS: usize = 64;

/// The process-wide table the sessions report to.
/// The unit tests start hundreds of scripted upstreams in one process, each
/// on its own port, and read this table back: there it holds more, so one test
/// never finds it filled by the others. The bound itself is tested on a table
/// of its own (`the_table_is_bounded`).
static UPSTREAM_VERSIONS: UpstreamVersions =
    UpstreamVersions::with_limit(if cfg!(test) { 1 << 16 } else { MAX_TARGETS });

/// The table the sessions of this process report to.
pub fn global() -> &'static UpstreamVersions {
    &UPSTREAM_VERSIONS
}

/// The PostgreSQL major version of the parser the engine uses, read once from
/// `pg_query` (see the module documentation). `None` only if `pg_query` cannot
/// parse `SELECT 1`, which would mean no statement is evaluated at all.
pub fn parser_pg_major() -> Option<u32> {
    static MAJOR: LazyLock<Option<u32>> = LazyLock::new(|| match pg_query::parse("SELECT 1") {
        Ok(parsed) => version_num_major(parsed.protobuf.version),
        Err(e) => {
            tracing::debug!(error = %e, "Could not read the parser's PostgreSQL version");
            None
        }
    });
    *MAJOR
}

/// The major of a `PG_VERSION_NUM` (`170007` → 17; since PostgreSQL 10 it is
/// `major * 10000 + minor`).
fn version_num_major(num: i32) -> Option<u32> {
    u32::try_from(num)
        .ok()
        .map(|n| n / 10_000)
        .filter(|m| *m > 0)
}

/// The major version in a PostgreSQL `server_version`: its leading digits.
/// `17.2` → 17, `18beta1` → 18, `16.4 (Debian 16.4-1.pgdg120+2)` → 16,
/// `9.6.24` → 9 (before 10 the major was two numbers; any of them is older
/// than the parser, which is all this is used for). `None` when it does not
/// start with a digit.
pub fn pg_server_major(server_version: &str) -> Option<u32> {
    let s = server_version.trim_start();
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    s[..digits].parse::<u32>().ok().filter(|m| *m > 0)
}

/// The value of a `server_version` ParameterStatus body (`name\0value\0`);
/// `None` for any other parameter or a malformed body.
pub fn server_version_parameter(body: &[u8]) -> Option<&[u8]> {
    let rest = body.strip_prefix(b"server_version\0")?;
    let end = rest.iter().position(|b| *b == 0)?;
    Some(&rest[..end])
}

/// Which wire protocol an upstream speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamDialect {
    Postgres,
    Mysql,
}

/// What the proxy knows about an upstream's version, as the heartbeat sends it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamVersionReport {
    pub dialect: UpstreamDialect,
    /// As the server reported it, printable ASCII, at most [`MAX_VERSION_CHARS`].
    pub server_version: String,
    /// PostgreSQL only; `None` when the version could not be read.
    pub server_major: Option<u32>,
    /// The parser's PostgreSQL major; `None` on MySQL.
    pub parser_major: Option<u32>,
    /// The server's major is newer than the parser's.
    pub newer_than_parser: bool,
}

/// What one report from a connection changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// A version not recorded for the target before (its first, or a
    /// different one): recorded. `warn`: its major is newer than the parser's
    /// and than any already warned about for this target.
    Recorded { warn: bool },
    /// The version already recorded for the target: nothing to do.
    Unchanged,
    /// The table is full and the target is not in it: not recorded.
    Untracked,
}

#[derive(Debug)]
struct Entry {
    target: String,
    report: UpstreamVersionReport,
    /// Highest server major warned about for this target (0: none).
    warned_major: u32,
    /// Warnings logged for this target (for the tests: at most one per major).
    warnings: u32,
}

/// The versions the upstream targets of this process reported.
#[derive(Debug)]
pub struct UpstreamVersions {
    entries: Mutex<Vec<Entry>>,
    limit: usize,
}

impl Default for UpstreamVersions {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamVersions {
    /// An empty table of at most [`MAX_TARGETS`] targets.
    pub const fn new() -> Self {
        Self::with_limit(MAX_TARGETS)
    }

    const fn with_limit(limit: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            limit,
        }
    }

    /// A PostgreSQL connection to `target` reported `server_version` (raw
    /// bytes of its ParameterStatus): recorded, and logged as the module
    /// documentation says. Never fails.
    pub fn observe_postgres(&self, target: &str, server_version: &[u8]) {
        let parser_major = parser_pg_major();
        let version = printable(server_version);
        let server_major = pg_server_major(&version);
        let warn = match self.record(target, UpstreamDialect::Postgres, &version, parser_major) {
            Observed::Recorded { warn } => warn,
            Observed::Unchanged => return,
            Observed::Untracked => return untracked(target, &version),
        };
        match (server_major, parser_major) {
            _ if warn => tracing::warn!(
                alert = "upstream_newer_than_parser",
                upstream = %target,
                server_version = %version,
                server_major = server_major.unwrap_or(0),
                parser_major = parser_major.unwrap_or(0),
                "The database runs a newer PostgreSQL major version than the proxy's SQL parser. \
                 Statements that use syntax added after the parser's version cannot be parsed and are \
                 handled as parse errors (VERICTO-PARSE-ERROR): refused when parse errors fail closed \
                 (the workspace policy, a block or mask sensitive column, or an enforced agent \
                 allowlist), forwarded and flagged otherwise. Every other statement is evaluated as \
                 before. A vericto-proxy release with a newer parser removes the gap"
            ),
            (None, _) => tracing::debug!(
                upstream = %target,
                server_version = %version,
                "Could not read a PostgreSQL major version from server_version; not compared with the parser"
            ),
            (Some(server), None) => tracing::debug!(
                upstream = %target,
                server_version = %version,
                server_major = server,
                "Upstream PostgreSQL version recorded; the parser's version is unknown"
            ),
            (Some(server), Some(parser)) => tracing::debug!(
                upstream = %target,
                server_version = %version,
                server_major = server,
                parser_major = parser,
                "Upstream PostgreSQL version is not newer than the proxy's SQL parser"
            ),
        }
    }

    /// A MySQL connection to `target` reported `server_version` in its
    /// handshake greeting: recorded, and logged at debug when it is new.
    pub fn observe_mysql(&self, target: &str, server_version: &[u8]) {
        let version = printable(server_version);
        match self.record(target, UpstreamDialect::Mysql, &version, None) {
            Observed::Recorded { .. } => tracing::debug!(
                upstream = %target,
                server_version = %version,
                "Upstream MySQL version recorded"
            ),
            Observed::Unchanged => {}
            Observed::Untracked => untracked(target, &version),
        }
    }

    /// Records `version` for `target`; the decision behind the logging.
    /// `parser_major` is the parser's PostgreSQL major (`None` on MySQL).
    fn record(
        &self,
        target: &str,
        dialect: UpstreamDialect,
        version: &str,
        parser_major: Option<u32>,
    ) -> Observed {
        // A poisoned lock still holds a consistent table (nothing panics while
        // it is held): keep using it rather than lose the observability.
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let index = match entries.iter().position(|e| e.target == target) {
            Some(i) if entries[i].report.server_version == version => return Observed::Unchanged,
            Some(i) => i,
            None if entries.len() >= self.limit => return Observed::Untracked,
            None => {
                entries.push(Entry {
                    target: target.to_string(),
                    report: UpstreamVersionReport {
                        dialect,
                        server_version: String::new(),
                        server_major: None,
                        parser_major: None,
                        newer_than_parser: false,
                    },
                    warned_major: 0,
                    warnings: 0,
                });
                entries.len() - 1
            }
        };
        let entry = &mut entries[index];
        let server_major = match dialect {
            UpstreamDialect::Postgres => pg_server_major(version),
            UpstreamDialect::Mysql => None,
        };
        let newer = matches!((server_major, parser_major), (Some(s), Some(p)) if s > p);
        let warn = newer && server_major.is_some_and(|s| s > entry.warned_major);
        if warn {
            entry.warned_major = server_major.unwrap_or(0);
            entry.warnings += 1;
        }
        entry.report = UpstreamVersionReport {
            dialect,
            server_version: version.to_string(),
            server_major,
            parser_major,
            newer_than_parser: newer,
        };
        Observed::Recorded { warn }
    }

    /// What to show for this process: the upstream newer than the parser if
    /// any, else the one with the newest major, else the first recorded.
    /// `None` before any connection reached an upstream.
    pub fn report(&self) -> Option<UpstreamVersionReport> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .enumerate()
            .max_by_key(|(i, e)| {
                (
                    e.report.newer_than_parser,
                    e.report.server_major,
                    std::cmp::Reverse(*i),
                )
            })
            .map(|(_, e)| e.report.clone())
    }

    /// The Prometheus text of [`report`](Self::report) (appended to
    /// `/metrics`): PostgreSQL upstreams only, nothing before the first.
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write as _;
        let Some(r) = self
            .report()
            .filter(|r| r.dialect == UpstreamDialect::Postgres)
        else {
            return String::new();
        };
        let p = crate::telemetry::metrics::PREFIX;
        let mut out = String::with_capacity(768);
        let _ = writeln!(
            out,
            "# HELP {p}upstream_newer_than_parser 1 when the database reports a newer PostgreSQL major version than the proxy's SQL parser (statements using newer syntax are parse errors).\n\
             # TYPE {p}upstream_newer_than_parser gauge\n\
             {p}upstream_newer_than_parser {}",
            u8::from(r.newer_than_parser)
        );
        for (name, help, value) in [
            (
                "upstream_server_major_version",
                "PostgreSQL major version the database reports (0 when it cannot be read).",
                r.server_major,
            ),
            (
                "parser_major_version",
                "PostgreSQL major version of the proxy's SQL parser.",
                r.parser_major,
            ),
        ] {
            let _ = writeln!(
                out,
                "# HELP {p}{name} {help}\n# TYPE {p}{name} gauge\n{p}{name} {}",
                value.unwrap_or(0)
            );
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn warnings(&self, target: &str) -> u32 {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .find(|e| e.target == target)
            .map_or(0, |e| e.warnings)
    }

    #[cfg(test)]
    pub(crate) fn report_for(&self, target: &str) -> Option<UpstreamVersionReport> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .find(|e| e.target == target)
            .map(|e| e.report.clone())
    }
}

/// The table is full (more than [`MAX_TARGETS`] upstreams in one process,
/// which a proxy never has): the version is not recorded, and says so.
fn untracked(target: &str, version: &str) {
    tracing::debug!(
        upstream = %target,
        server_version = %version,
        max_targets = MAX_TARGETS,
        "Upstream version not recorded: too many upstreams tracked"
    );
}

/// A server-supplied version as printable ASCII (anything else becomes `?`),
/// at most [`MAX_VERSION_CHARS`]: it goes to logs, an HTTP header and metrics.
fn printable(raw: &[u8]) -> String {
    raw.iter()
        .take(MAX_VERSION_CHARS)
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '?'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARSER: Option<u32> = Some(17);

    fn pg(table: &UpstreamVersions, target: &str, version: &str) -> Observed {
        table.record(target, UpstreamDialect::Postgres, version, PARSER)
    }

    #[test]
    fn server_majors_are_read_from_every_form_postgres_sends() {
        for (version, major) in [
            ("17.2", Some(17)),
            ("18.1", Some(18)),
            ("18beta1", Some(18)),
            ("18rc1", Some(18)),
            ("19devel", Some(19)),
            ("16.4 (Debian 16.4-1.pgdg120+2)", Some(16)),
            ("15.8 (Ubuntu 15.8-1.pgdg22.04+1)", Some(15)),
            ("9.6.24", Some(9)),
            ("  17.0", Some(17)),
            ("", None),
            ("abc", None),
            ("v17", None),
            ("0.1", None),
            (".17", None),
            ("99999999999999999999.1", None),
        ] {
            assert_eq!(pg_server_major(version), major, "{version:?}");
        }
    }

    #[test]
    fn the_parser_major_comes_from_pg_query() {
        let major = parser_pg_major().expect("pg_query reports its PG_VERSION_NUM");
        let num = pg_query::parse("SELECT 1").unwrap().protobuf.version;
        assert_eq!(major as i32, num / 10_000);
        // pg_query 6.x is libpg_query 17; a bump moves this, on purpose.
        assert!(major >= 17, "{major}");
        assert_eq!(version_num_major(170007), Some(17));
        assert_eq!(version_num_major(180001), Some(18));
        assert_eq!(version_num_major(0), None);
        assert_eq!(version_num_major(-1), None);
    }

    /// The parser read above is the engine's only if both resolve to one
    /// `pg_query` (Cargo.toml bumps the two together).
    #[test]
    fn one_pg_query_in_the_lock_file() {
        let lock = include_str!("../../Cargo.lock");
        assert_eq!(
            lock.matches("\nname = \"pg_query\"\n").count(),
            1,
            "the proxy and vericto-engine must resolve to the same pg_query"
        );
    }

    #[test]
    fn the_server_version_parameter_is_found_only_by_name() {
        assert_eq!(
            server_version_parameter(b"server_version\x0018.1\0"),
            Some(&b"18.1"[..])
        );
        assert_eq!(
            server_version_parameter(b"server_version\0\0"),
            Some(&b""[..])
        );
        assert_eq!(server_version_parameter(b"TimeZone\0UTC\0"), None);
        assert_eq!(
            server_version_parameter(b"server_version_num\x00180001\0"),
            None
        );
        assert_eq!(server_version_parameter(b"server_version\x0018.1"), None);
        assert_eq!(server_version_parameter(b""), None);
    }

    #[test]
    fn a_newer_major_warns_once_per_target() {
        let t = UpstreamVersions::new();
        assert_eq!(pg(&t, "db:5432", "18.1"), Observed::Recorded { warn: true });
        // Every later connection reports the same: nothing more.
        for _ in 0..100 {
            assert_eq!(pg(&t, "db:5432", "18.1"), Observed::Unchanged);
        }
        assert_eq!(t.warnings("db:5432"), 1);
        let r = t.report().unwrap();
        assert_eq!(r.server_version, "18.1");
        assert_eq!((r.server_major, r.parser_major), (Some(18), Some(17)));
        assert!(r.newer_than_parser);
        // A minor update or a beta of the same major: recorded, no new warning.
        assert_eq!(
            pg(&t, "db:5432", "18.2"),
            Observed::Recorded { warn: false }
        );
        assert_eq!(
            pg(&t, "db:5432", "18beta1"),
            Observed::Recorded { warn: false }
        );
        assert!(t.report_for("db:5432").unwrap().newer_than_parser);
        assert_eq!(t.warnings("db:5432"), 1);
    }

    #[test]
    fn each_target_is_warned_about_on_its_own() {
        let t = UpstreamVersions::new();
        assert_eq!(pg(&t, "a:5432", "18.1"), Observed::Recorded { warn: true });
        assert_eq!(pg(&t, "b:5432", "18.1"), Observed::Recorded { warn: true });
        assert_eq!((t.warnings("a:5432"), t.warnings("b:5432")), (1, 1));
    }

    #[test]
    fn equal_and_older_majors_never_warn() {
        let t = UpstreamVersions::new();
        for (target, version) in [
            ("eq", "17.2"),
            ("eq-beta", "17beta3"),
            ("old", "16.4 (Debian 16.4-1.pgdg120+2)"),
            ("older", "9.6.24"),
        ] {
            assert_eq!(pg(&t, target, version), Observed::Recorded { warn: false });
            let r = t.report_for(target).unwrap();
            assert!(!r.newer_than_parser, "{version}");
            assert_eq!(t.warnings(target), 0);
        }
        assert_eq!(t.report_for("eq").unwrap().server_major, Some(17));
    }

    #[test]
    fn an_unreadable_version_is_recorded_but_never_compared() {
        let t = UpstreamVersions::new();
        for version in ["", "abc", "devel", "\u{fffd}18"] {
            let target = format!("x-{version}");
            assert_eq!(pg(&t, &target, version), Observed::Recorded { warn: false });
            let r = t.report_for(&target).unwrap();
            assert_eq!(r.server_major, None);
            assert!(!r.newer_than_parser);
        }
        // An unknown parser version compares nothing either.
        assert_eq!(
            t.record("np", UpstreamDialect::Postgres, "18.1", None),
            Observed::Recorded { warn: false }
        );
        assert!(!t.report_for("np").unwrap().newer_than_parser);
    }

    #[test]
    fn an_upgrade_to_a_still_newer_major_warns_again_a_rollback_does_not() {
        let t = UpstreamVersions::new();
        assert_eq!(pg(&t, "db", "18.1"), Observed::Recorded { warn: true });
        assert_eq!(pg(&t, "db", "17.6"), Observed::Recorded { warn: false });
        assert!(!t.report_for("db").unwrap().newer_than_parser);
        // Back to 18 (a blue/green switch): already warned about.
        assert_eq!(pg(&t, "db", "18.1"), Observed::Recorded { warn: false });
        assert!(t.report_for("db").unwrap().newer_than_parser);
        assert_eq!(pg(&t, "db", "19.0"), Observed::Recorded { warn: true });
        assert_eq!(t.warnings("db"), 2);
    }

    #[test]
    fn the_table_is_bounded() {
        let t = UpstreamVersions::new();
        for i in 0..MAX_TARGETS {
            assert_eq!(
                pg(&t, &format!("t{i}"), "17.2"),
                Observed::Recorded { warn: false }
            );
        }
        assert_eq!(pg(&t, "one-more", "18.1"), Observed::Untracked);
        assert_eq!(pg(&t, "one-more", "18.1"), Observed::Untracked);
        assert_eq!(t.entries.lock().unwrap().len(), MAX_TARGETS);
        // Known targets still update.
        assert_eq!(pg(&t, "t0", "18.1"), Observed::Recorded { warn: true });
        // Versions are bounded and printable.
        let long = "1".repeat(500) + "\u{7}";
        assert_eq!(printable(long.as_bytes()).len(), MAX_VERSION_CHARS);
        assert_eq!(printable(b"18.1\x07\xff"), "18.1??");
    }

    #[test]
    fn mysql_versions_are_recorded_without_a_comparison() {
        let t = UpstreamVersions::new();
        let rec = |v: &str| t.record("my:3306", UpstreamDialect::Mysql, v, None);
        assert_eq!(rec("8.0.46"), Observed::Recorded { warn: false });
        assert_eq!(rec("8.0.46"), Observed::Unchanged);
        assert_eq!(rec("99.0.0"), Observed::Recorded { warn: false });
        let r = t.report().unwrap();
        assert_eq!(r.dialect, UpstreamDialect::Mysql);
        assert_eq!((r.server_major, r.parser_major), (None, None));
        assert!(!r.newer_than_parser);
        // Not a PostgreSQL upstream: no gauges.
        assert_eq!(t.render_prometheus(), "");
    }

    #[test]
    fn the_report_prefers_the_upstream_newer_than_the_parser() {
        let t = UpstreamVersions::new();
        assert_eq!(t.report(), None);
        assert_eq!(t.render_prometheus(), "");
        pg(&t, "a", "16.4");
        pg(&t, "b", "18.1");
        pg(&t, "c", "17.2");
        assert_eq!(t.report().unwrap().server_version, "18.1");
        let page = t.render_prometheus();
        assert!(
            page.contains("vericto_proxy_upstream_newer_than_parser 1\n"),
            "{page}"
        );
        assert!(
            page.contains("vericto_proxy_upstream_server_major_version 18\n"),
            "{page}"
        );
        assert!(
            page.contains("vericto_proxy_parser_major_version 17\n"),
            "{page}"
        );
        // No labels: the series are fixed whatever the database says.
        assert!(!page.contains('{'), "{page}");
        let json = serde_json::to_value(t.report().unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "dialect": "postgres", "server_version": "18.1", "server_major": 18,
                "parser_major": 17, "newer_than_parser": true
            })
        );
    }

    /// The public entry points log and never fail, whatever the server sent.
    #[test]
    fn observing_never_fails() {
        let t = UpstreamVersions::new();
        t.observe_postgres("p", b"18.1");
        t.observe_postgres("p", b"18.1");
        t.observe_postgres("q", b"\xff\xfe");
        t.observe_postgres("r", b"");
        t.observe_mysql("m", b"8.0.46");
        let parser = parser_pg_major().unwrap();
        let p = t.report_for("p").unwrap();
        assert_eq!(p.parser_major, Some(parser));
        assert_eq!(p.newer_than_parser, 18 > parser);
        assert_eq!(t.warnings("p"), u32::from(18 > parser));
        assert_eq!(t.report_for("q").unwrap().server_major, None);
        assert_eq!(t.report_for("m").unwrap().dialect, UpstreamDialect::Mysql);
    }
}
