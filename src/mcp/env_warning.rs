// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! "The agent may also have credentials" (design "MCP execution modes" §12.1,
//! T9). In stdio mode the server runs as the same OS user as the agent, with
//! the environment the agent host gave it: if that environment (or the user's
//! home) holds a database credential, the agent can run SQL around Vericto and
//! the exact-text guarantee does not hold. Vericto cannot prevent that from
//! inside the process; it says so at startup and in `whoami.warnings`.
//!
//! Only variable names and paths are reported, never a value.

use std::path::Path;

/// Variables (exact names) that carry a database credential.
const EXACT: &[&str] = &[
    "DATABASE_URL",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGSERVICE",
    "PGSERVICEFILE",
    "VERICTO_MCP_DATABASE_URL",
];

/// Prefixes of variables that carry one.
const PREFIXES: &[&str] = &[
    "DATABASE_URL_",
    "POSTGRES_URL",
    "POSTGRES_PASSWORD",
    "POSTGRES_PRISMA_URL",
    "SUPABASE_DB_",
    "NEON_",
    "PGPASSWORD_",
];

/// What the environment exposes: the names of the variables, `~/.pgpass`,
/// and a secret file other users can read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exposure {
    pub variables: Vec<String>,
    pub pgpass: bool,
    pub secret_file_readable_by_others: bool,
}

impl Exposure {
    pub fn any(&self) -> bool {
        !self.variables.is_empty() || self.pgpass || self.secret_file_readable_by_others
    }

    /// One line for the log and `whoami`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.variables.is_empty() {
            parts.push(format!(
                "environment variables {}",
                self.variables.join(", ")
            ));
        }
        if self.pgpass {
            parts.push("~/.pgpass".to_string());
        }
        if self.secret_file_readable_by_others {
            parts.push("a database secret file other users can read".to_string());
        }
        parts.join("; ")
    }
}

/// Inspects `vars` (name, value) and the files.
pub fn inspect(
    vars: impl IntoIterator<Item = (String, String)>,
    home: Option<&Path>,
    secret_file: Option<&Path>,
) -> Exposure {
    let mut variables: Vec<String> = vars
        .into_iter()
        .filter(|(k, v)| {
            !v.trim().is_empty()
                && (EXACT.contains(&k.as_str()) || PREFIXES.iter().any(|p| k.starts_with(p)))
        })
        .map(|(k, _)| k)
        .collect();
    variables.sort();
    variables.dedup();
    let pgpass = home.is_some_and(|h| h.join(".pgpass").exists());
    Exposure {
        variables,
        pgpass,
        secret_file_readable_by_others: secret_file.is_some_and(readable_by_others),
    }
}

#[cfg(unix)]
fn readable_by_others(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o044 != 0)
}

#[cfg(not(unix))]
fn readable_by_others(_: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn credential_variables_are_named_never_their_values() {
        let e = inspect(
            vars(&[
                ("DATABASE_URL", "postgres://u:hunter2@h/db"),
                ("SUPABASE_DB_PASSWORD", "x"),
                ("NEON_API_KEY", "y"),
                ("PATH", "/usr/bin"),
                ("PGPASSWORD", ""),
            ]),
            None,
            None,
        );
        assert_eq!(
            e.variables,
            vec!["DATABASE_URL", "NEON_API_KEY", "SUPABASE_DB_PASSWORD"]
        );
        assert!(e.any());
        assert!(!e.describe().contains("hunter2"));
        assert!(!inspect(vars(&[("HOME", "/h")]), None, None).any());
    }

    #[cfg(unix)]
    #[test]
    fn pgpass_and_a_world_readable_secret_file_are_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".pgpass"), "h:5432:*:u:p").unwrap();
        let secret = dir.path().join("db.url");
        std::fs::write(&secret, "postgres://u:p@h/d").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = inspect(Vec::new(), Some(dir.path()), Some(&secret));
        assert!(e.pgpass && e.secret_file_readable_by_others);
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let e = inspect(Vec::new(), None, Some(&secret));
        assert!(!e.secret_file_readable_by_others);
    }
}
