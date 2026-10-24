// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Business policy rules on the TCP path (design "Business policy rules",
//! Phase 1, milestone M2): who a session is (its principal), the context it
//! declares (ticket, tenant) and the compiled policy set its statements are
//! evaluated with.
//!
//! Everything here sits behind `VERICTO_POLICY_RULES` (default `off`). With
//! `off` none of it runs: the rule sync does not announce `cel/1`, nothing is
//! compiled, the StartupMessage and `SET vericto.*` are forwarded as they come,
//! statements are evaluated with `evaluate()` exactly as in 4.14.3, and
//! telemetry carries none of the new fields.
//!
//! * **Principal.** Resolved once per session from the `principals` section of
//!   `/sync/rules` and the session's signals (database user, `application_name`
//!   or MySQL `program_name`, listener), and again only when a sync swaps the
//!   section or a MySQL COM_CHANGE_USER changes the user. The strongest
//!   identifying signal wins; two principals at the same top trust are
//!   ambiguous and resolve to `unknown`, trust `weak` (fail closed).
//! * **Session context.** `vericto.ticket` and `vericto.tenant`, from the
//!   Postgres StartupMessage (`-c vericto.ticket=…` in `options`, or sent as a
//!   parameter), from MySQL connect attributes, or from a `SET vericto.ticket =
//!   '…'` sent alone as a simple query. The proxy consumes them: they never
//!   reach the database. Each is set once; a second `SET`, a `RESET` or a
//!   `set_config` of a key already set is blocked.
//! * **Policies.** `PolicySet::compile` over the synced rules, once per sync, in
//!   an `ArcSwap` next to the ruleset. `enforce` resolves statements with
//!   `evaluate_with_context`; `observe` keeps the verdict `evaluate()` gives and
//!   reports what the policies found as flags.
//!
//! No client address is captured or reported: `session.client_ip` stays unset
//! (owner decision pending; a later opt-in can fill it without a format change).

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;
use vericto_engine::Rule;
use vericto_engine::policy::{
    DbContext, EvalContext, HostMode, PolicySet, Principal, PrincipalType, SessionContext, Ticket,
    TimeContext, Trust,
};

/// The value of the `X-Vericto-Policy-Language` header the rule sync sends when
/// policy rules are on: the policy language this proxy evaluates (`cel/1`) and,
/// as comma-separated tokens, the optional features of it this proxy runs (the
/// engine's `POLICY_FEATURES`).
/// Since 4.17.0 (engine 4.5.0): `rewrite_limit`, which the control plane only
/// sends to a proxy that announces it (an older proxy blocked a rewrite that is
/// not a mask). Commas, not `;`: a control plane that only knows `cel/1` splits
/// the header on commas and still reads `cel/1`.
pub const POLICY_LANGUAGE_ANNOUNCEMENT: &str = "cel/1, rewrite_limit";
/// The header that announces it on `GET /sync/rules`.
pub const POLICY_LANGUAGE_HEADER: &str = "X-Vericto-Policy-Language";

/// Rule code of a blocked `SET vericto.*` (or startup setting): the session
/// context is set once, and only in the forms the proxy can consume.
pub const SESSION_CONTEXT_RULE_CODE: &str = "VERICTO-SESSION-CONTEXT";

/// Longest `vericto.ticket` / `vericto.tenant` value accepted, in characters.
pub const MAX_CONTEXT_VALUE_CHARS: usize = 128;
/// Longest `application_name` / `program_name` kept, in characters.
pub const MAX_APPLICATION_NAME_CHARS: usize = 256;
/// Longest principal id reported, in characters.
const MAX_PRINCIPAL_ID_CHARS: usize = 128;

// ── VERICTO_POLICY_RULES ─────────────────────────────────────────────────────

/// `VERICTO_POLICY_RULES`: whether business policies run on this proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyRulesMode {
    /// The default: exactly the 4.14.3 behaviour.
    #[default]
    Off,
    /// Principals, session context and policies are evaluated and reported,
    /// but a policy never blocks: what it would block is flagged. Every other
    /// verdict is the one `evaluate()` gives.
    Observe,
    /// Policies resolve the verdict (`evaluate_with_context`).
    Enforce,
}

impl PolicyRulesMode {
    /// Parses `VERICTO_POLICY_RULES`: `off` (also unset or empty), `observe` or
    /// `enforce`, in any case and with surrounding whitespace ignored. Any other
    /// value is a startup error, like `VERICTO_TELEMETRY_BUFFER`: a typo must not
    /// silently leave enforcement off, or turn it on.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim) {
            None | Some("") => Ok(Self::Off),
            Some(v) if v.eq_ignore_ascii_case("off") => Ok(Self::Off),
            Some(v) if v.eq_ignore_ascii_case("observe") => Ok(Self::Observe),
            Some(v) if v.eq_ignore_ascii_case("enforce") => Ok(Self::Enforce),
            Some(v) => Err(format!(
                "VERICTO_POLICY_RULES={v:?} is not supported: use `off` (the default), \
                 `observe` (policies flag, never block) or `enforce`"
            )),
        }
    }

    pub fn is_on(self) -> bool {
        self != Self::Off
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Observe => "observe",
            Self::Enforce => "enforce",
        }
    }
}

// ── The synced bundle ────────────────────────────────────────────────────────

/// What one `/sync/rules` response gives the policy path, swapped as a whole.
#[derive(Debug, Default)]
pub struct PolicyRules {
    /// The rules `policies` was compiled from: the same `Arc` the sync stored
    /// in the ruleset, so a statement never pairs a ruleset with the policy set
    /// of another sync. `None` until the first sync (the built-in ruleset, no
    /// policies).
    pub rules: Option<Arc<Vec<Rule>>>,
    pub policies: PolicySet,
    pub principals: PrincipalMap,
    /// The `version` of the response, reported as `policy_bundle_version`.
    pub version: Option<String>,
}

/// Shared, hot-swappable policy bundle.
pub type SharedPolicyRules = Arc<ArcSwap<PolicyRules>>;

/// The policy path's settings and live state, in the proxy config.
pub struct PolicyRulesRuntime {
    pub mode: PolicyRulesMode,
    pub bundle: SharedPolicyRules,
    /// The listener sessions arrive on (the bound address, e.g. `0.0.0.0:5433`):
    /// a weak identify / narrow signal.
    pub listener: String,
    /// The database this proxy fronts (`VERICTO_DATABASE_ID`): `db.id`.
    pub database_id: Option<String>,
}

impl Default for PolicyRulesRuntime {
    fn default() -> Self {
        Self {
            mode: PolicyRulesMode::Off,
            bundle: Arc::new(ArcSwap::from_pointee(PolicyRules::default())),
            listener: String::new(),
            database_id: None,
        }
    }
}

/// Builds the bundle of one sync. Compiles only when policy rules are on.
pub fn bundle_from_sync(
    mode: PolicyRulesMode,
    rules: Arc<Vec<Rule>>,
    principals: Option<serde_json::Value>,
    version: &str,
) -> PolicyRules {
    let policies = PolicySet::compile(&rules);
    for e in policies.errors() {
        tracing::warn!(
            rule_code = %e.rule_code,
            issues = e.issues.len(),
            "A business policy does not compile; it fails closed in its scope"
        );
    }
    let principals = PrincipalMap::from_sync(principals);
    tracing::debug!(
        mode = mode.as_str(),
        policies = policies.len(),
        principals = principals.entries.len(),
        "Policy bundle compiled"
    );
    PolicyRules {
        rules: Some(rules),
        policies,
        principals,
        version: Some(version.to_string()),
    }
}

// ── Principals ───────────────────────────────────────────────────────────────

/// The `principals` section of `/sync/rules` (contract M2 §2).
#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalMap {
    pub version: Option<String>,
    pub entries: Vec<PrincipalEntry>,
    /// The principal type of a session no entry matches (`unknown` by
    /// default). Its trust is always `weak`: a session nothing identified
    /// cannot be trusted more than its weakest signal.
    pub unmatched_type: PrincipalType,
}

impl Default for PrincipalMap {
    fn default() -> Self {
        Self {
            version: None,
            entries: Vec::new(),
            unmatched_type: PrincipalType::Unknown,
        }
    }
}

/// One principal the proxy can identify.
#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalEntry {
    /// The principal id; `{db_user}` is replaced by the session's user.
    pub id: String,
    pub principal_type: PrincipalType,
    pub owner: Option<String>,
    pub identify: Identify,
    pub narrow: Narrow,
    pub attrs: BTreeMap<String, String>,
}

/// Signals that identify (any one; the strongest that matches gives the trust).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Identify {
    /// medium, exact, case-sensitive.
    pub db_user: Option<String>,
    /// medium, glob (`*`, `?`), case-sensitive.
    pub db_user_pattern: Option<String>,
    /// weak, glob.
    pub application_name: Option<String>,
    /// weak, exact.
    pub listener: Option<String>,
}

/// Signals that must ALSO match (all present keys); they never raise trust.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Narrow {
    /// glob.
    pub application_name: Option<String>,
    /// any of.
    pub listener: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawMap {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    entries: Vec<serde_json::Value>,
    #[serde(default)]
    defaults: Option<RawDefaults>,
}

#[derive(Debug, Deserialize)]
struct RawDefaults {
    #[serde(default)]
    unmatched: Option<RawUnmatched>,
}

#[derive(Debug, Deserialize)]
struct RawUnmatched {
    #[serde(default, rename = "type")]
    principal_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    id: String,
    #[serde(rename = "type")]
    principal_type: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    identify: Identify,
    #[serde(default)]
    narrow: Narrow,
    #[serde(default)]
    attrs: BTreeMap<String, String>,
}

impl PrincipalMap {
    /// Reads the section fail-safe: absent or `null` is an empty map; a section
    /// that is not an object with an `entries` list is ignored as a whole (with
    /// a warning) instead of failing the sync, so every session is then the
    /// unmatched principal; an entry that does not parse, or has no signal the
    /// proxy can see, is skipped. Unknown keys are ignored (forward compatible).
    pub fn from_sync(raw: Option<serde_json::Value>) -> Self {
        let Some(raw) = raw.filter(|v| !v.is_null()) else {
            return Self::default();
        };
        let map: RawMap = match serde_json::from_value(raw) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "The principals section of /sync/rules is malformed; ignoring it (every session is unmatched)"
                );
                return Self::default();
            }
        };
        let mut entries = Vec::with_capacity(map.entries.len());
        for raw in map.entries {
            match serde_json::from_value::<RawEntry>(raw) {
                Ok(e) => {
                    let identify = e.identify;
                    if identify.db_user.is_none()
                        && identify.db_user_pattern.is_none()
                        && identify.application_name.is_none()
                        && identify.listener.is_none()
                    {
                        tracing::debug!(principal = %e.id, "Principal with no proxy signal; skipped");
                        continue;
                    }
                    entries.push(PrincipalEntry {
                        principal_type: PrincipalType::parse(&e.principal_type)
                            .unwrap_or(PrincipalType::Unknown),
                        id: e.id,
                        owner: e.owner,
                        identify,
                        narrow: e.narrow,
                        attrs: e.attrs,
                    });
                }
                Err(e) => tracing::warn!(error = %e, "Skipping a malformed principal entry"),
            }
        }
        let unmatched_type = map
            .defaults
            .and_then(|d| d.unmatched)
            .and_then(|u| u.principal_type)
            .and_then(|t| PrincipalType::parse(&t))
            .unwrap_or(PrincipalType::Unknown);
        Self {
            version: map.version,
            entries,
            unmatched_type,
        }
    }

    /// The principal of a session with these signals (contract M2 §3).
    pub fn resolve(&self, signals: &SessionSignals<'_>) -> Principal {
        let user = signals.db_user.unwrap_or("");
        let mut best: Option<(Trust, &'static str, &PrincipalEntry)> = None;
        let mut tied = false;
        for entry in &self.entries {
            let Some((trust, via)) = entry.identified_by(signals) else {
                continue;
            };
            if !entry.narrow.matches(signals) {
                continue;
            }
            match &best {
                Some((t, _, _)) if trust < *t => {}
                Some((t, _, _)) if trust == *t => tied = true,
                _ => {
                    best = Some((trust, via, entry));
                    tied = false;
                }
            }
        }
        match best {
            Some((trust, via, entry)) if !tied => {
                let id =
                    truncate_chars(&entry.id.replace("{db_user}", user), MAX_PRINCIPAL_ID_CHARS);
                let mut p = Principal::new(id, entry.principal_type, trust);
                p.via = Some(via.to_string());
                p.owner = entry.owner.clone();
                p.attrs = entry.attrs.clone();
                p
            }
            Some(_) => {
                tracing::debug!(
                    db_user = user,
                    "Two principals match this session at the same trust; it is unknown and weak"
                );
                Principal::new(
                    truncate_chars(user, MAX_PRINCIPAL_ID_CHARS),
                    PrincipalType::Unknown,
                    Trust::Weak,
                )
            }
            None => Principal::new(
                truncate_chars(user, MAX_PRINCIPAL_ID_CHARS),
                self.unmatched_type,
                Trust::Weak,
            ),
        }
    }
}

impl PrincipalEntry {
    /// The strongest identify signal of this entry the session matches.
    fn identified_by(&self, s: &SessionSignals<'_>) -> Option<(Trust, &'static str)> {
        let id = &self.identify;
        if let (Some(want), Some(user)) = (id.db_user.as_deref(), s.db_user)
            && want == user
        {
            return Some((Trust::Medium, "db_user"));
        }
        if let (Some(pattern), Some(user)) = (id.db_user_pattern.as_deref(), s.db_user)
            && glob(pattern, user)
        {
            return Some((Trust::Medium, "db_user_pattern"));
        }
        if let (Some(pattern), Some(app)) = (id.application_name.as_deref(), s.application_name)
            && glob(pattern, app)
        {
            return Some((Trust::Weak, "application_name"));
        }
        if let Some(want) = id.listener.as_deref()
            && want == s.listener
        {
            return Some((Trust::Weak, "listener"));
        }
        None
    }
}

impl Narrow {
    fn matches(&self, s: &SessionSignals<'_>) -> bool {
        if let Some(pattern) = self.application_name.as_deref()
            && !s.application_name.is_some_and(|a| glob(pattern, a))
        {
            return false;
        }
        if let Some(listeners) = &self.listener
            && !listeners.iter().any(|l| l == s.listener)
        {
            return false;
        }
        true
    }
}

/// What a session shows the principal map.
#[derive(Debug, Clone, Copy)]
pub struct SessionSignals<'a> {
    pub db_user: Option<&'a str>,
    pub application_name: Option<&'a str>,
    pub listener: &'a str,
}

/// `*` (any run, also empty) and `?` (one character); everything else literal,
/// case-sensitive.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

// ── Session context ──────────────────────────────────────────────────────────

/// The two context keys a session can set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextKey {
    Ticket,
    Tenant,
}

impl ContextKey {
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "vericto.ticket" => Some(Self::Ticket),
            "vericto.tenant" => Some(Self::Tenant),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ticket => "vericto.ticket",
            Self::Tenant => "vericto.tenant",
        }
    }
}

/// What a session told the proxy about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionDeclared {
    pub ticket: Option<String>,
    pub tenant: Option<String>,
    pub application_name: Option<String>,
}

impl SessionDeclared {
    /// Sets `key` once. `Err` with the reason when it is already set or the
    /// value is not acceptable.
    pub fn set(&mut self, key: ContextKey, value: &str) -> Result<(), String> {
        check_value(key, value)?;
        let slot = match key {
            ContextKey::Ticket => &mut self.ticket,
            ContextKey::Tenant => &mut self.tenant,
        };
        if slot.is_some() {
            return Err(format!(
                "{} is already set for this session and can be set only once",
                key.name()
            ));
        }
        *slot = Some(value.to_string());
        Ok(())
    }

    /// A startup setting (`-c vericto.x=…`, a StartupMessage parameter or a
    /// MySQL connect attribute). `Err` with the reason when it is not one of
    /// the known keys or its value is not acceptable.
    pub fn set_from_startup(&mut self, name: &str, value: &str) -> Result<(), String> {
        let key = ContextKey::parse(name).ok_or_else(|| unknown_key(name))?;
        check_value(key, value)?;
        // The server applies the startup settings in order, so a key sent twice
        // at startup takes its last value, as it would there.
        match key {
            ContextKey::Ticket => self.ticket = Some(value.to_string()),
            ContextKey::Tenant => self.tenant = Some(value.to_string()),
        }
        Ok(())
    }

    fn is_set(&self, key: ContextKey) -> bool {
        match key {
            ContextKey::Ticket => self.ticket.is_some(),
            ContextKey::Tenant => self.tenant.is_some(),
        }
    }
}

fn unknown_key(name: &str) -> String {
    format!(
        "{} is not a Vericto session setting (use vericto.ticket or vericto.tenant)",
        name.chars().take(64).collect::<String>()
    )
}

fn check_value(key: ContextKey, value: &str) -> Result<(), String> {
    let n = value.chars().count();
    if n == 0 || n > MAX_CONTEXT_VALUE_CHARS {
        return Err(format!(
            "{} must be 1 to {MAX_CONTEXT_VALUE_CHARS} characters",
            key.name()
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!(
            "{} must not contain control characters",
            key.name()
        ));
    }
    Ok(())
}

/// What the proxy does with a client statement about `vericto.*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextStatement {
    /// Not about `vericto.*`: evaluated and forwarded as usual.
    NotContext,
    /// Consumed: answered by the proxy as the server would answer a `SET`.
    Consumed,
    /// Refused with this reason; never forwarded.
    Blocked(String),
}

/// Handles `sql` if it sets or resets a `vericto.*` setting. `prepared` is a
/// Postgres Parse / MySQL COM_STMT_PREPARE: those are refused, as the proxy
/// would otherwise have to answer the whole extended sequence itself.
pub fn intercept_context_statement(
    sql: &str,
    prepared: bool,
    declared: &mut SessionDeclared,
) -> ContextStatement {
    if !mentions_context(sql) {
        return ContextStatement::NotContext;
    }
    if prepared {
        return ContextStatement::Blocked(
            "SET vericto.* is accepted only as a simple query sent on its own (or as a startup option)"
                .to_string(),
        );
    }
    match parse_context_statement(sql) {
        Some(Parsed::Set(name, value)) => {
            let Some(key) = ContextKey::parse(&name) else {
                return ContextStatement::Blocked(unknown_key(&name));
            };
            match declared.set(key, &value) {
                Ok(()) => ContextStatement::Consumed,
                Err(e) => ContextStatement::Blocked(e),
            }
        }
        Some(Parsed::Reset(name)) => match ContextKey::parse(&name) {
            None => ContextStatement::Blocked(unknown_key(&name)),
            Some(key) if declared.is_set(key) => ContextStatement::Blocked(format!(
                "{} is set for this session and cannot be reset",
                key.name()
            )),
            // Nothing to reset: the server would accept it, and nothing changes.
            Some(_) => ContextStatement::Consumed,
        },
        Some(Parsed::Local) => ContextStatement::Blocked(
            "SET LOCAL vericto.* is not supported: the session context is set once per session"
                .to_string(),
        ),
        None => ContextStatement::Blocked(
            "a statement that sets vericto.* must be `SET vericto.ticket = '…'` (or vericto.tenant), sent on its own"
                .to_string(),
        ),
    }
}

/// True when `sql` sets, resets or `set_config`s a `vericto.*` setting
/// anywhere in it (conservative: a match inside a string literal counts too).
fn mentions_context(sql: &str) -> bool {
    // Cheap pre-check: most statements never mention it.
    if !sql
        .as_bytes()
        .windows(8)
        .any(|w| w.eq_ignore_ascii_case(b"vericto."))
    {
        return false;
    }
    let lower = sql.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter(|w| !w.is_empty())
        .collect();
    words.iter().enumerate().any(|(i, w)| {
        let next_is_context = |j: usize| words.get(j).is_some_and(|n| n.starts_with("vericto."));
        match *w {
            "set" | "reset" => {
                next_is_context(i + 1)
                    || (matches!(words.get(i + 1), Some(&"session") | Some(&"local"))
                        && next_is_context(i + 2))
            }
            "set_config" => next_is_context(i + 1),
            _ => false,
        }
    })
}

enum Parsed {
    Set(String, String),
    Reset(String),
    Local,
}

/// `SET [SESSION] <name> {= | TO} <value>`, `SET <name> {= | TO} DEFAULT`,
/// `RESET <name>`, alone (one optional trailing `;`). The value is a
/// single-quoted string (`''` escapes a quote) or a bare word.
fn parse_context_statement(sql: &str) -> Option<Parsed> {
    let s = sql.trim();
    let s = s.strip_suffix(';').unwrap_or(s).trim_end();
    let (first, rest) = split_word(s)?;
    if first.eq_ignore_ascii_case("reset") {
        let (name, rest) = split_word(rest)?;
        return (rest.is_empty() && is_context_name(name)).then(|| Parsed::Reset(name.to_string()));
    }
    if !first.eq_ignore_ascii_case("set") {
        return None;
    }
    let (word, after) = split_word(rest)?;
    if word.eq_ignore_ascii_case("local") {
        return Some(Parsed::Local);
    }
    let rest = if word.eq_ignore_ascii_case("session") {
        after
    } else {
        rest
    };
    // The name runs to the first character that cannot be in it, so
    // `name='value'` needs no spaces.
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .unwrap_or(rest.len());
    let (name, rest) = rest.split_at(end);
    if !is_context_name(name) {
        return None;
    }
    let rest = rest.trim_start();
    let value = if let Some(v) = rest.strip_prefix('=') {
        v.trim_start()
    } else {
        let (to, v) = split_word(rest)?;
        if !to.eq_ignore_ascii_case("to") {
            return None;
        }
        v
    };
    let value = value.trim();
    if value.eq_ignore_ascii_case("default") {
        return Some(Parsed::Reset(name.to_string()));
    }
    let value = if let Some(inner) = value.strip_prefix('\'') {
        let inner = inner.strip_suffix('\'')?;
        // A lone quote inside means more than one literal: not a plain SET.
        if inner.replace("''", "").contains('\'') {
            return None;
        }
        inner.replace("''", "'")
    } else {
        if value.is_empty()
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
        {
            return None;
        }
        value.to_string()
    };
    Some(Parsed::Set(name.to_string(), value))
}

fn is_context_name(name: &str) -> bool {
    name.len() > 8
        && name[..8].eq_ignore_ascii_case("vericto.")
        && name[8..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn split_word(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Some((&s[..end], s[end..].trim_start()))
}

// ── Per session ──────────────────────────────────────────────────────────────

/// The policy fields of a telemetry event (contract M2 §5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyTelemetry {
    pub principal_id: Option<String>,
    pub principal_type: Option<String>,
    pub principal_trust: Option<String>,
    pub principal_via: Option<String>,
    pub application_name: Option<String>,
    pub policy_bundle_version: Option<String>,
    pub ticket_id: Option<String>,
    pub session_tenant: Option<String>,
}

/// One session's policy state: what it declared, and its principal resolved
/// against the bundle in force (cached; resolved again only when the bundle
/// or the user changes).
pub struct SessionPolicy {
    pub declared: SessionDeclared,
    cached: Option<Cached>,
}

struct Cached {
    bundle: Arc<PolicyRules>,
    user: Option<String>,
    declared: SessionDeclared,
    ctx: Arc<EvalContext>,
    telemetry: Arc<PolicyTelemetry>,
}

impl SessionPolicy {
    pub fn new(declared: SessionDeclared) -> Self {
        Self {
            declared,
            cached: None,
        }
    }

    /// The evaluation context (without `time`, which each statement sets) and
    /// the telemetry fields of this session under `bundle`.
    pub fn context(
        &mut self,
        user: Option<&str>,
        bundle: &Arc<PolicyRules>,
        runtime: &PolicyRulesRuntime,
    ) -> (Arc<EvalContext>, Arc<PolicyTelemetry>) {
        if let Some(c) = &self.cached
            && Arc::ptr_eq(&c.bundle, bundle)
            && c.user.as_deref() == user
            && c.declared == self.declared
        {
            return (Arc::clone(&c.ctx), Arc::clone(&c.telemetry));
        }
        let principal = bundle.principals.resolve(&SessionSignals {
            db_user: user,
            application_name: self.declared.application_name.as_deref(),
            listener: &runtime.listener,
        });
        let telemetry = Arc::new(PolicyTelemetry {
            principal_id: Some(principal.id.clone()),
            principal_type: Some(principal.principal_type.as_str().to_string()),
            principal_trust: Some(principal.trust.as_str().to_string()),
            principal_via: principal.via.clone(),
            application_name: self.declared.application_name.clone(),
            policy_bundle_version: bundle.version.clone(),
            ticket_id: self.declared.ticket.clone(),
            session_tenant: self.declared.tenant.clone(),
        });
        let mut session = SessionContext::new();
        session.tenant = self.declared.tenant.clone();
        session.application_name = self.declared.application_name.clone();
        session.listener = Some(runtime.listener.clone());
        let mut ctx = EvalContext::new()
            .with_mode(HostMode::Proxy)
            .with_principal(principal)
            .with_session(session);
        if let Some(id) = &runtime.database_id {
            ctx = ctx.with_db(DbContext::new().with_id(id.clone()));
        }
        if let Some(t) = &self.declared.ticket {
            ctx = ctx.with_ticket(Ticket::declared(t.clone()));
        }
        let ctx = Arc::new(ctx);
        self.cached = Some(Cached {
            bundle: Arc::clone(bundle),
            user: user.map(str::to_string),
            declared: self.declared.clone(),
            ctx: Arc::clone(&ctx),
            telemetry: Arc::clone(&telemetry),
        });
        (ctx, telemetry)
    }
}

/// `ctx` with the statement's time (UTC: the bundle names no workspace zone
/// yet; the engine reads no clock).
pub fn at_now(ctx: &EvalContext) -> EvalContext {
    ctx.clone()
        .with_time(TimeContext::utc(chrono::Utc::now().timestamp()))
}

// ── Postgres StartupMessage ──────────────────────────────────────────────────

/// What the proxy takes out of a StartupMessage when policy rules are on.
#[derive(Debug, Default)]
pub struct StartupContext {
    /// The StartupMessage to forward: the original bytes without any
    /// `vericto.*` parameter or `options` switch.
    pub raw: Vec<u8>,
    /// The `vericto.*` settings, in the order the server would apply them
    /// (`options` first, then the parameters).
    pub settings: Vec<(String, String)>,
    pub application_name: Option<String>,
}

/// Splits the `vericto.*` settings and `application_name` out of a
/// StartupMessage (`raw` = length + version + pairs). `None` when the message
/// cannot be read as pairs (it is then forwarded as it came: the server will
/// refuse it).
pub fn strip_startup(raw: &[u8]) -> Option<StartupContext> {
    let body = raw.get(8..)?;
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut parts = body.split(|&b| b == 0);
    loop {
        let key = parts.next()?;
        if key.is_empty() {
            break;
        }
        let val = parts.next()?;
        pairs.push((key.to_vec(), val.to_vec()));
    }
    let mut out = StartupContext::default();
    let mut direct = Vec::new();
    let mut kept: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(pairs.len());
    let mut app_from_options = None;
    let mut app_direct = None;
    for (key, val) in pairs {
        let name = String::from_utf8_lossy(&key)
            .to_ascii_lowercase()
            .replace('-', "_");
        if name == "options" {
            let text = String::from_utf8_lossy(&val).into_owned();
            let (rest, settings) = split_options(&text);
            for (n, v) in settings {
                if n.starts_with("vericto.") {
                    out.settings.push((n, v));
                } else if n == "application_name" {
                    app_from_options = Some(v);
                }
            }
            if !rest.is_empty() {
                kept.push((key, rest.into_bytes()));
            }
        } else if name.starts_with("vericto.") {
            direct.push((name, String::from_utf8_lossy(&val).into_owned()));
        } else {
            if name == "application_name" {
                app_direct = Some(String::from_utf8_lossy(&val).into_owned());
            }
            kept.push((key, val));
        }
    }
    out.settings.extend(direct);
    out.application_name = app_direct
        .or(app_from_options)
        .map(|a| truncate_chars(&a, MAX_APPLICATION_NAME_CHARS));
    let mut msg = raw[4..8].to_vec();
    for (k, v) in kept {
        msg.extend_from_slice(&k);
        msg.push(0);
        msg.extend_from_slice(&v);
        msg.push(0);
    }
    msg.push(0);
    let mut bytes = ((msg.len() + 4) as i32).to_be_bytes().to_vec();
    bytes.extend_from_slice(&msg);
    out.raw = bytes;
    Some(out)
}

/// An `options` string without its `vericto.*` switches, and every
/// `name=value` it sets (names as the server reads them). Words are split on
/// unescaped whitespace (`\` escapes the next character), as `pg_split_opts`
/// does; kept words are copied with their original escapes.
fn split_options(options: &str) -> (String, Vec<(String, String)>) {
    // (original text, unescaped text) per word.
    let mut words: Vec<(String, String)> = Vec::new();
    let mut orig = String::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = options.chars();
    while let Some(c) = chars.next() {
        if c.is_ascii_whitespace() {
            if in_word {
                words.push((std::mem::take(&mut orig), std::mem::take(&mut word)));
                in_word = false;
            }
            continue;
        }
        in_word = true;
        orig.push(c);
        if c == '\\' {
            if let Some(next) = chars.next() {
                orig.push(next);
                word.push(next);
            }
        } else {
            word.push(c);
        }
    }
    if in_word {
        words.push((orig, word));
    }
    let mut kept: Vec<String> = Vec::new();
    let mut settings = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let (o, w) = &words[i];
        let (setting, used) = if w == "-c" {
            (words.get(i + 1).map(|(_, n)| n.clone()), 2)
        } else if let Some(rest) = w.strip_prefix("--") {
            (Some(rest.to_string()), 1)
        } else if let Some(rest) = w.strip_prefix("-c") {
            (Some(rest.to_string()), 1)
        } else {
            (None, 1)
        };
        let parsed = setting
            .as_deref()
            .and_then(|s| s.split_once('='))
            .map(|(n, v)| (n.to_ascii_lowercase().replace('-', "_"), v.to_string()));
        match parsed {
            Some((n, v)) if n.starts_with("vericto.") => settings.push((n, v)),
            other => {
                if let Some(s) = other {
                    settings.push(s);
                }
                kept.push(o.clone());
                if used == 2
                    && let Some((o2, _)) = words.get(i + 1)
                {
                    kept.push(o2.clone());
                }
            }
        }
        i += used;
    }
    (kept.join(" "), settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The announcement is the engine's language and features, comma-separated,
    /// so adopting an engine with another feature cannot leave it unannounced
    /// (the control plane would withhold the policies that need it) or announce
    /// one the engine refuses (they would fail closed in their scope).
    #[test]
    fn the_announcement_is_the_engines_language_and_features() {
        let mut tokens = vec![vericto_engine::policy::POLICY_LANGUAGE];
        tokens.extend_from_slice(vericto_engine::policy::POLICY_FEATURES);
        assert_eq!(POLICY_LANGUAGE_ANNOUNCEMENT, tokens.join(", "));
        assert!(POLICY_LANGUAGE_ANNOUNCEMENT.starts_with("cel/1,"));
    }

    fn map(json: serde_json::Value) -> PrincipalMap {
        PrincipalMap::from_sync(Some(json))
    }

    fn signals<'a>(user: Option<&'a str>, app: Option<&'a str>) -> SessionSignals<'a> {
        SessionSignals {
            db_user: user,
            application_name: app,
            listener: "0.0.0.0:5433",
        }
    }

    #[test]
    fn the_flag_parses_three_values_and_refuses_anything_else() {
        assert_eq!(PolicyRulesMode::parse(None), Ok(PolicyRulesMode::Off));
        assert_eq!(PolicyRulesMode::parse(Some(" ")), Ok(PolicyRulesMode::Off));
        assert_eq!(
            PolicyRulesMode::parse(Some("OFF")),
            Ok(PolicyRulesMode::Off)
        );
        assert_eq!(
            PolicyRulesMode::parse(Some(" Observe\n")),
            Ok(PolicyRulesMode::Observe)
        );
        assert_eq!(
            PolicyRulesMode::parse(Some("enforce")),
            Ok(PolicyRulesMode::Enforce)
        );
        for bad in ["on", "true", "block", "observer"] {
            let err = PolicyRulesMode::parse(Some(bad)).unwrap_err();
            assert!(err.contains("VERICTO_POLICY_RULES"), "{err}");
            assert!(err.contains(&format!("{bad:?}")), "{err}");
        }
    }

    #[test]
    fn glob_matches_stars_and_question_marks_case_sensitively() {
        assert!(glob("dev_*", "dev_ana"));
        assert!(glob("dev_*", "dev_"));
        assert!(!glob("dev_*", "Dev_ana"));
        assert!(glob("Metabase*", "Metabase v0.50"));
        assert!(glob("*base*", "Metabase"));
        assert!(glob("a?c", "abc"));
        assert!(!glob("a?c", "ac"));
        assert!(glob("*", ""));
        assert!(!glob("", "x"));
        assert!(glob("exact", "exact"));
    }

    fn sample() -> PrincipalMap {
        map(serde_json::json!({
            "version": "p1",
            "entries": [
                { "id": "svc-billing", "type": "service", "owner": "pay@acme.com",
                  "identify": { "db_user": "billing_svc" }, "attrs": { "tier": "critical" } },
                { "id": "human:{db_user}", "type": "human",
                  "identify": { "db_user_pattern": "dev_*" } },
                { "id": "metabase", "type": "tool",
                  "identify": { "db_user": "metabase_ro" },
                  "narrow": { "application_name": "Metabase*" } },
                { "id": "bi-by-app", "type": "tool",
                  "identify": { "application_name": "Looker*" } }
            ],
            "defaults": { "unmatched": { "type": "unknown", "trust": "weak" } }
        }))
    }

    #[test]
    fn an_exact_db_user_identifies_with_medium_trust_and_the_entry_fields() {
        let p = sample().resolve(&signals(Some("billing_svc"), None));
        assert_eq!(p.id, "svc-billing");
        assert_eq!(p.principal_type, PrincipalType::Service);
        assert_eq!(p.trust, Trust::Medium);
        assert_eq!(p.via.as_deref(), Some("db_user"));
        assert_eq!(p.owner.as_deref(), Some("pay@acme.com"));
        assert_eq!(p.attrs.get("tier").map(String::as_str), Some("critical"));
    }

    #[test]
    fn a_template_id_takes_the_session_user() {
        let p = sample().resolve(&signals(Some("dev_ana"), None));
        assert_eq!(p.id, "human:dev_ana");
        assert_eq!(p.via.as_deref(), Some("db_user_pattern"));
        assert_eq!(p.trust, Trust::Medium);
    }

    #[test]
    fn narrowing_must_also_match_and_never_raises_trust() {
        let m = sample();
        let p = m.resolve(&signals(Some("metabase_ro"), Some("Metabase v50")));
        assert_eq!((p.id.as_str(), p.trust), ("metabase", Trust::Medium));
        // Same user from another tool: the narrowing fails, nothing else matches.
        let p = m.resolve(&signals(Some("metabase_ro"), Some("psql")));
        assert_eq!(p.principal_type, PrincipalType::Unknown);
        assert_eq!(
            (p.id.as_str(), p.trust, p.via),
            ("metabase_ro", Trust::Weak, None)
        );
        let p = m.resolve(&signals(Some("metabase_ro"), None));
        assert_eq!(p.principal_type, PrincipalType::Unknown);
    }

    #[test]
    fn the_strongest_signal_wins() {
        // Looker identifies weakly by application_name; billing_svc identifies
        // with medium trust by its user: the medium one wins, no ambiguity.
        let p = sample().resolve(&signals(Some("billing_svc"), Some("Looker 24")));
        assert_eq!((p.id.as_str(), p.trust), ("svc-billing", Trust::Medium));
        // Only the weak one matches: weak.
        let p = sample().resolve(&signals(Some("someone"), Some("Looker 24")));
        assert_eq!((p.id.as_str(), p.trust), ("bi-by-app", Trust::Weak));
        assert_eq!(p.via.as_deref(), Some("application_name"));
    }

    #[test]
    fn two_principals_at_the_same_top_trust_are_ambiguous_unknown_and_weak() {
        let m = map(serde_json::json!({ "entries": [
            { "id": "a", "type": "agent", "identify": { "db_user": "shared" } },
            { "id": "b", "type": "service", "identify": { "db_user_pattern": "sha*" } },
            { "id": "c", "type": "tool", "identify": { "listener": "0.0.0.0:5433" } }
        ]}));
        let p = m.resolve(&signals(Some("shared"), None));
        assert_eq!(p.principal_type, PrincipalType::Unknown);
        assert_eq!(
            (p.id.as_str(), p.trust, p.via),
            ("shared", Trust::Weak, None)
        );
        // A weaker match does not break a tie, and does not count as one.
        let p = m.resolve(&signals(Some("other"), None));
        assert_eq!((p.id.as_str(), p.trust), ("c", Trust::Weak));
        assert_eq!(p.via.as_deref(), Some("listener"));
    }

    #[test]
    fn the_unmatched_default_is_weak_whatever_it_says() {
        let m = map(serde_json::json!({ "entries": [],
            "defaults": { "unmatched": { "type": "human", "trust": "strong" } } }));
        let p = m.resolve(&signals(Some("x"), None));
        assert_eq!(p.principal_type, PrincipalType::Human);
        assert_eq!(p.trust, Trust::Weak);
    }

    #[test]
    fn a_malformed_section_or_entry_is_ignored_not_fatal() {
        assert_eq!(PrincipalMap::from_sync(None), PrincipalMap::default());
        assert_eq!(
            PrincipalMap::from_sync(Some(serde_json::Value::Null)),
            PrincipalMap::default()
        );
        for bad in [
            serde_json::json!("nope"),
            serde_json::json!([1, 2]),
            serde_json::json!({ "entries": "x" }),
        ] {
            assert_eq!(map(bad), PrincipalMap::default());
        }
        let m = map(serde_json::json!({ "entries": [
            { "id": 7, "type": "agent", "identify": { "db_user": "u" } },
            { "id": "no-signal", "type": "agent", "identify": { "api_key": "k1", "oidc": {} } },
            { "id": "ok", "type": "robot", "identify": { "db_user": "u" }, "future_key": true }
        ]}));
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].id, "ok");
        assert_eq!(m.entries[0].principal_type, PrincipalType::Unknown);
    }

    #[test]
    fn set_statements_are_parsed_strictly() {
        let mut d = SessionDeclared::default();
        assert_eq!(
            intercept_context_statement("SELECT 1", false, &mut d),
            ContextStatement::NotContext
        );
        assert_eq!(
            intercept_context_statement("SELECT * FROM vericto.audit", false, &mut d),
            ContextStatement::NotContext
        );
        assert_eq!(
            intercept_context_statement("UPDATE vericto.t SET a = 1 WHERE id = 1", false, &mut d),
            ContextStatement::NotContext
        );
        assert_eq!(
            intercept_context_statement("SET vericto.ticket = 'OPS-1';", false, &mut d),
            ContextStatement::Consumed
        );
        assert_eq!(d.ticket.as_deref(), Some("OPS-1"));
        assert_eq!(
            intercept_context_statement("set session VERICTO.TENANT to acme_eu", false, &mut d),
            ContextStatement::Consumed
        );
        assert_eq!(d.tenant.as_deref(), Some("acme_eu"));
    }

    #[test]
    fn set_once_reset_set_config_and_unknown_keys_are_blocked() {
        let mut d = SessionDeclared::default();
        assert_eq!(
            intercept_context_statement("SET vericto.ticket='A-1'", false, &mut d),
            ContextStatement::Consumed
        );
        for sql in [
            "SET vericto.ticket = 'A-2'",
            "RESET vericto.ticket",
            "SET vericto.ticket TO DEFAULT",
            "SELECT set_config('vericto.ticket', 'A-3', false)",
            "SET vericto.ticket = 'x'; SELECT 1",
            "SET LOCAL vericto.tenant = 't'",
            "SET vericto.role = 'admin'",
        ] {
            assert!(
                matches!(
                    intercept_context_statement(sql, false, &mut d),
                    ContextStatement::Blocked(_)
                ),
                "{sql}"
            );
        }
        assert_eq!(d.ticket.as_deref(), Some("A-1"), "unchanged");
        // An unset key: RESET has nothing to undo.
        assert_eq!(
            intercept_context_statement("RESET vericto.tenant", false, &mut d),
            ContextStatement::Consumed
        );
        // Prepared: refused even when it would be valid.
        assert!(matches!(
            intercept_context_statement("SET vericto.tenant = 't'", true, &mut d),
            ContextStatement::Blocked(_)
        ));
        assert_eq!(d.tenant, None);
    }

    #[test]
    fn context_values_are_bounded() {
        let mut d = SessionDeclared::default();
        let long = format!("SET vericto.ticket = '{}'", "x".repeat(129));
        assert!(matches!(
            intercept_context_statement(&long, false, &mut d),
            ContextStatement::Blocked(_)
        ));
        assert!(matches!(
            intercept_context_statement("SET vericto.ticket = ''", false, &mut d),
            ContextStatement::Blocked(_)
        ));
        assert!(d.set(ContextKey::Ticket, "a\u{7}b").is_err());
        assert_eq!(
            intercept_context_statement("SET vericto.ticket = 'it''s'", false, &mut d),
            ContextStatement::Consumed
        );
        assert_eq!(d.ticket.as_deref(), Some("it's"));
    }

    fn startup(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut body = 196608i32.to_be_bytes().to_vec();
        for (k, v) in pairs {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        let mut raw = ((body.len() + 4) as i32).to_be_bytes().to_vec();
        raw.extend_from_slice(&body);
        raw
    }

    #[test]
    fn startup_vericto_settings_are_taken_out_and_the_rest_kept() {
        let raw = startup(&[
            ("user", "dev_ana"),
            ("database", "app"),
            (
                "options",
                "-c vericto.ticket=OPS-1 -c statement_timeout=5s --vericto.tenant=t1 -csearch_path=a\\ b",
            ),
            ("application_name", "psql"),
            ("vericto.ticket", "OPS-2"),
        ]);
        let s = strip_startup(&raw).unwrap();
        assert_eq!(
            s.settings,
            vec![
                ("vericto.ticket".to_string(), "OPS-1".to_string()),
                ("vericto.tenant".to_string(), "t1".to_string()),
                ("vericto.ticket".to_string(), "OPS-2".to_string()),
            ]
        );
        assert_eq!(s.application_name.as_deref(), Some("psql"));
        assert_eq!(
            s.raw,
            startup(&[
                ("user", "dev_ana"),
                ("database", "app"),
                ("options", "-c statement_timeout=5s -csearch_path=a\\ b"),
                ("application_name", "psql"),
            ])
        );
        // Nothing to take out: byte for byte the same message.
        let plain = startup(&[("user", "u"), ("options", "-c x=1")]);
        assert_eq!(strip_startup(&plain).unwrap().raw, plain);
        // Only vericto switches: the options parameter goes away.
        let only = startup(&[("user", "u"), ("options", "-c vericto.tenant=t")]);
        assert_eq!(strip_startup(&only).unwrap().raw, startup(&[("user", "u")]));
    }

    #[test]
    fn startup_application_name_from_options_and_startup_set_once_rules() {
        let raw = startup(&[("user", "u"), ("options", "-c application_name=Metabase")]);
        assert_eq!(
            strip_startup(&raw).unwrap().application_name.as_deref(),
            Some("Metabase")
        );
        let mut d = SessionDeclared::default();
        assert!(d.set_from_startup("vericto.ticket", "A").is_ok());
        assert!(d.set_from_startup("vericto.ticket", "B").is_ok());
        assert_eq!(d.ticket.as_deref(), Some("B"));
        assert!(d.set_from_startup("vericto.other", "x").is_err());
        // After startup the key is set: a SET is the second one.
        assert!(matches!(
            intercept_context_statement("SET vericto.ticket = 'C'", false, &mut d),
            ContextStatement::Blocked(_)
        ));
    }
}
