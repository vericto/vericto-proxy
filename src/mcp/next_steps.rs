// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! What an agent should do next after a tool answers: the Rust port of
//! vericto-fmw `backend/src/services/mcp-tools/next-steps.ts` (PR #536), with
//! the `execute_sql` actions of design "MCP execution modes" §6.4. The same
//! verdict always gets the same hint, and a hint never comes from row
//! contents (§15, T1).
//!
//! The shared part (`verdict_step`, `kill_switch_step`, `group_steps`,
//! `next_steps_text`) is held equal to the TypeScript one by the fixtures in
//! `tests/mcp-contract/check-sql-next-steps.json`, which both test suites assert.

use serde::Serialize;

/// The tools a hint may point to.
#[cfg(test)]
pub const HINT_TOOLS: &[&str] = &[
    "check_sql",
    "list_rules",
    "show_rule",
    "list_reports",
    "show_report",
    "whoami",
    "explain_block",
    "execute_sql",
    "describe_schema",
];

/// Ordered by precedence: the first one present is a check's `next_action`.
/// The first eight are #536's; the rest were added after them (§6.4).
pub const NEXT_ACTIONS: &[&str] = &[
    "stop",
    "request_access",
    "do_not_run",
    "apply_fix_and_recheck",
    "fix_and_recheck",
    "run_approved_query",
    "mention_to_user",
    "run_as_written",
    "done",
    "refine_query",
    "request_write_access",
    "await_approval",
    "request_new_approval",
    "fix_sql_error",
    "retry_later",
];

/// Which tools this caller can call.
pub trait ToolAccess: Sync {
    fn has(&self, tool: &str) -> bool;
    /// The scope that would open `tool`, or `None`.
    fn scope_for(&self, _tool: &str) -> Option<&'static str> {
        None
    }
}

/// `/mcp` (a runtime key): every runtime tool; explain_block is the account
/// server's. The hosted contract's `RUNTIME_TOOL_ACCESS`.
pub struct RuntimeAccess;
impl ToolAccess for RuntimeAccess {
    fn has(&self, tool: &str) -> bool {
        matches!(
            tool,
            "check_sql" | "list_rules" | "show_rule" | "list_reports" | "show_report" | "whoami"
        )
    }
}

/// `vericto-proxy mcp` (Proxy mode): execute_sql, describe_schema, a local
/// check_sql and whoami; linked to the control plane, also the rule tools
/// (list_rules, show_rule) the shared fixtures are worded for.
pub struct ProxyAccess {
    pub linked: bool,
}
impl ToolAccess for ProxyAccess {
    fn has(&self, tool: &str) -> bool {
        matches!(
            tool,
            "execute_sql" | "describe_schema" | "check_sql" | "whoami"
        ) || (self.linked && matches!(tool, "list_rules" | "show_rule"))
    }
}

/// "call show_rule VERICTO-001" when the caller can, "ask the user to grant
/// this connection the … scope (for …)" when a scope would open it, else None.
pub fn call_hint(access: &dyn ToolAccess, tool: &str, call: Option<&str>) -> Option<String> {
    if access.has(tool) {
        return Some(format!("call {}", call.unwrap_or(tool)));
    }
    access.scope_for(tool).map(|scope| {
        format!("ask the user to grant this connection the {scope} scope (for {tool})")
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextStep {
    pub action: &'static str,
    /// The statements (their first line) it applies to.
    pub lines: Vec<u32>,
    pub rule_code: Option<String>,
    /// The tool to call next, when there is one and the caller has it.
    pub tool: Option<&'static str>,
    pub message: String,
}

/// What a finding says about one statement.
#[derive(Debug, Clone, Default)]
pub struct VerdictFacts {
    pub status: String,
    pub rule_code: Option<String>,
    pub severity: Option<String>,
    pub suggested_fix: Option<String>,
    pub approved_query: Option<String>,
    pub access_denied: Vec<DeniedName>,
    pub parse_error_kind: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DeniedName {
    pub schema: Option<String>,
    pub table: String,
    pub column: Option<String>,
    pub needed: Option<String>,
}

pub struct VerdictContext<'a> {
    pub access: &'a dyn ToolAccess,
    pub dialect: &'a str,
    pub ruleset_version: Option<&'a str>,
    /// Proxy mode: `execute_sql` exists for the database, so the check_sql
    /// hints point to it (§6.7).
    pub execute_available: bool,
}

const PARSE_RULE_CODE: &str = "VERICTO-PARSE-ERROR";
const MAX_REFS: usize = 3;

fn denied_refs(refs: &[DeniedName]) -> String {
    let shown: Vec<String> = refs
        .iter()
        .take(MAX_REFS)
        .map(|r| {
            let col = r.column.as_deref().filter(|c| *c != "*");
            let name = [r.schema.as_deref(), Some(r.table.as_str()), col]
                .into_iter()
                .flatten()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(".");
            match &r.needed {
                Some(n) => format!("{name} ({n})"),
                None => name,
            }
        })
        .collect();
    let more = if refs.len() > MAX_REFS {
        format!(" and {} more", refs.len() - MAX_REFS)
    } else {
        String::new()
    };
    shown.join(", ") + &more
}

fn allowed_as_written(ruleset_version: Option<&str>) -> String {
    match ruleset_version {
        Some(v) => format!(
            "safe to run as written under ruleset {v}; no need to call check_sql again while ruleset_version stays {v}."
        ),
        None => "allowed as written; nothing to fix.".to_string(),
    }
}

/// One step without its lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub action: &'static str,
    pub rule_code: Option<String>,
    pub tool: Option<&'static str>,
    pub message: String,
}

impl Step {
    pub fn new(
        action: &'static str,
        rule_code: Option<String>,
        tool: Option<&'static str>,
        message: String,
    ) -> Self {
        Self {
            action,
            rule_code,
            tool,
            message,
        }
    }

    pub fn with_lines(self, lines: Vec<u32>) -> NextStep {
        NextStep {
            action: self.action,
            lines,
            rule_code: self.rule_code,
            tool: self.tool,
            message: self.message,
        }
    }
}

/// The next step for one statement's check_sql verdict (#536 `verdictStep`).
pub fn verdict_step(f: &VerdictFacts, ctx: &VerdictContext<'_>) -> Step {
    let rule = f.rule_code.clone();
    let step = |action: &'static str, message: String, tool: Option<&'static str>| {
        Step::new(action, rule.clone(), tool, message)
    };
    let blocked = f.status == "BLOCKED";
    let recheck = call_hint(ctx.access, "check_sql", Some("check_sql again"))
        .unwrap_or_else(|| "check it again".to_string());

    if f.status == "PARSE_ERROR" || rule.as_deref() == Some(PARSE_RULE_CODE) {
        let outcome = if blocked {
            "it is blocked and was not evaluated"
        } else {
            "it was not evaluated"
        };
        if f.parse_error_kind.as_deref() == Some("too_complex") {
            return step(
                "fix_and_recheck",
                format!(
                    "too complex to evaluate, so {outcome}; split it into simpler statements, then {recheck}."
                ),
                Some("check_sql"),
            );
        }
        let dialect_hint = if ctx.access.has("whoami") {
            "the database's dialect (whoami lists it)"
        } else {
            "the database's dialect (ask the user which)"
        };
        return step(
            "fix_and_recheck",
            format!(
                "could not be parsed as {}, so {outcome}; fix the syntax or pass {dialect_hint}, then {recheck}. Do not run it unchecked.",
                ctx.dialect
            ),
            Some("check_sql"),
        );
    }
    if blocked && !f.access_denied.is_empty() {
        return step(
            "request_access",
            format!(
                "do not run it: the agent access policy does not allow {}. Rephrasing will not help; ask the user to extend the policy.",
                denied_refs(&f.access_denied)
            ),
            None,
        );
    }
    if blocked && f.suggested_fix.is_some() {
        return step(
            "apply_fix_and_recheck",
            format!(
                "do not run it as written; apply the suggested fix, then {recheck} with the corrected SQL."
            ),
            Some("check_sql"),
        );
    }
    if blocked {
        let show = rule
            .as_deref()
            .and_then(|r| call_hint(ctx.access, "show_rule", Some(&format!("show_rule {r}"))));
        let dont = match &rule {
            Some(r) => format!("do not run it, and do not rephrase it to get past {r}"),
            None => "do not run it".to_string(),
        };
        return match show {
            Some(show) => step(
                "do_not_run",
                format!("{dont}; {show} to see what the rule allows, or ask the user."),
                ctx.access.has("show_rule").then_some("show_rule"),
            ),
            None => step(
                "do_not_run",
                format!("{dont}; ask the user how to proceed."),
                None,
            ),
        };
    }
    if f.approved_query.is_some() {
        if ctx.execute_available {
            return step(
                "run_approved_query",
                "call execute_sql with your original sql; the approved rewrite is applied for you."
                    .to_string(),
                Some("execute_sql"),
            );
        }
        return step(
            "run_approved_query",
            "run the approved_query instead of the original; never run the original.".to_string(),
            None,
        );
    }
    if f.status == "FLAGGED" || f.status == "MONITORED" {
        let what = match &rule {
            Some(r) => match &f.severity {
                Some(s) => format!("{r} ({s})"),
                None => r.clone(),
            },
            None => "this finding".to_string(),
        };
        return step(
            "mention_to_user",
            format!("allowed; mention {what} to the user when you run it."),
            None,
        );
    }
    if ctx.execute_available {
        return step(
            "run_as_written",
            "call execute_sql with the same sql.".to_string(),
            Some("execute_sql"),
        );
    }
    step(
        "run_as_written",
        allowed_as_written(ctx.ruleset_version),
        None,
    )
}

/// The kill switch stops every statement the same way (#536 `killSwitchStep`).
pub fn kill_switch_step(block_id: &str, lines: Vec<u32>) -> NextStep {
    kill_switch_step_for(block_id, lines, "check_sql")
}

/// [`kill_switch_step`] naming the tool that was called (check_sql, or
/// execute_sql in the executing modes).
pub fn kill_switch_step_for(block_id: &str, lines: Vec<u32>, tool: &str) -> NextStep {
    NextStep {
        action: "stop",
        lines,
        rule_code: None,
        tool: None,
        message: format!(
            "stop: do not run any SQL and do not call {tool} again; tell the user. A person must lift the kill-switch block {block_id}."
        ),
    }
}

/// Same message, one step (#536 `groupSteps`).
pub fn group_steps(per_statement: Vec<(u32, Step)>) -> Vec<NextStep> {
    let mut groups: Vec<NextStep> = Vec::new();
    for (line, step) in per_statement {
        match groups
            .iter_mut()
            .find(|g| g.action == step.action && g.message == step.message)
        {
            Some(g) => g.lines.push(line),
            None => groups.push(step.with_lines(vec![line])),
        }
    }
    let rank = |a: &str| {
        NEXT_ACTIONS
            .iter()
            .position(|x| *x == a)
            .unwrap_or(usize::MAX)
    };
    groups.sort_by(|a, b| {
        rank(a.action)
            .cmp(&rank(b.action))
            .then(a.lines[0].cmp(&b.lines[0]))
    });
    groups
}

const MAX_LINES_SHOWN: usize = 10;

fn lines_label(lines: &[u32]) -> String {
    let shown = lines
        .iter()
        .take(MAX_LINES_SHOWN)
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let more = if lines.len() > MAX_LINES_SHOWN {
        format!(" and {} more", lines.len() - MAX_LINES_SHOWN)
    } else {
        String::new()
    };
    format!(
        "{} {shown}{more}",
        if lines.len() == 1 { "line" } else { "lines" }
    )
}

/// The "Next:" block of a check's text (#536 `nextStepsText`).
pub fn next_steps_text(steps: &[NextStep], all_lines: bool) -> Vec<String> {
    if steps.is_empty() {
        return Vec::new();
    }
    if steps.len() == 1 && all_lines {
        return vec![format!("Next: {}", steps[0].message)];
    }
    let mut out = vec!["Next:".to_string()];
    for s in steps {
        out.push(format!(
            "- {}{}: {}",
            lines_label(&s.lines),
            s.rule_code
                .as_ref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default(),
            s.message
        ));
    }
    out
}

// ── execute_sql (design §6.4, §6.5; vericto-fmw execute-sql.ts) ──────────────

/// Why the input was refused before evaluation (§6.2, §14.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidReason {
    MultipleStatements,
    NulByte,
    TooLarge {
        max_bytes: usize,
    },
    ParamsMismatch {
        placeholders: usize,
        params: usize,
    },
    Empty,
    /// A schema-level problem of one argument (max_rows out of range …).
    Argument(String),
    /// A statement no tier runs (`SET`, `COPY`, `DO` …).
    NeverRun(String),
}

/// Which of the three layers of §9.1 keeps a tier closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Database,
    Scope,
    Process,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Database => "database",
            Layer::Scope => "scope",
            Layer::Process => "process",
        }
    }
}

/// Why the database could not be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    Connect,
    Tls,
    Auth,
    PoolBusy,
}

/// What happened to one execute_sql call: what the next steps are computed from.
#[derive(Debug, Clone)]
pub enum Outcome {
    Executed {
        verdict: VerdictFacts,
        /// The tagged columns a mask rewrote, as `schema.table.column` or `table.column`.
        masked_columns: Vec<String>,
        /// A business policy bound the rows (rewrite_limit).
        limit_bound: bool,
        truncation: Option<(&'static str, u64)>,
        row_count: usize,
    },
    Blocked(VerdictFacts),
    KillSwitch(String),
    TierNotEnabled {
        tier: &'static str,
        command: String,
        enabled_tiers: Vec<&'static str>,
        database: String,
        layer: Layer,
    },
    TierMismatch {
        tier: &'static str,
        command: String,
    },
    InvalidInput(InvalidReason),
    DatabaseError(String),
    Timeout(u32),
    Unavailable {
        reason: Unavailable,
        sqlstate: Option<String>,
        retry_after_s: u32,
    },
    NotReady(u32),
}

/// What execute_sql answers about one call, besides the rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteVerdict {
    pub status: &'static str,
    pub error_code: Option<&'static str>,
    pub execution_status: &'static str,
    pub next_steps: Vec<NextStep>,
}

impl ExecuteVerdict {
    pub fn next_action(&self) -> &'static str {
        self.next_steps[0].action
    }
}

/// `show_rule`'s next step (#536 `ruleNextStep`).
pub fn rule_next_step(is_active: bool, resolved_action: &str, access: &dyn ToolAccess) -> String {
    if !is_active {
        return "This rule is off in this workspace, so it neither blocks nor flags anything now."
            .to_string();
    }
    let check_again = call_hint(access, "check_sql", Some("check_sql again"))
        .unwrap_or_else(|| "check it again".to_string());
    if resolved_action == "block" {
        return format!(
            "To comply, rewrite the SQL so it no longer matches this rule's condition, then {check_again}. Only a workspace admin can change the rule: if the user needs the SQL as written, ask them."
        );
    }
    format!(
        "Matching SQL is allowed but reported ({resolved_action}); mention the finding to the user when you run it."
    )
}

pub struct ExecuteContext<'a> {
    pub access: &'a dyn ToolAccess,
    pub dialect: &'a str,
    pub ruleset_version: Option<&'a str>,
}

fn one(
    action: &'static str,
    message: String,
    tool: Option<&'static str>,
    rule_code: Option<String>,
) -> NextStep {
    NextStep {
        action,
        lines: vec![1],
        rule_code,
        tool,
        message,
    }
}

/// "an UPDATE", "a DELETE".
pub fn article(command: &str) -> String {
    let c = command.to_ascii_uppercase();
    let an = c.starts_with(['A', 'E', 'I', 'O', 'U']);
    format!("{} {c}", if an { "an" } else { "a" })
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// 262144 → "256 KiB"; a value that is not a whole KiB stays in bytes.
fn bytes_label(n: u64) -> String {
    if n >= 1024 && n % 1024 == 0 {
        format!("{} KiB", n / 1024)
    } else {
        format!("{n}-byte")
    }
}

/// "call execute_sql again" when the caller has it, else the neutral wording.
fn again(access: &dyn ToolAccess) -> String {
    call_hint(access, "execute_sql", Some("execute_sql again"))
        .unwrap_or_else(|| "send it again".to_string())
}

/// The SQLSTATE condition names the hints quote; others go by code only.
pub fn sqlstate_name(code: &str) -> Option<&'static str> {
    Some(match code {
        "42P01" => "undefined_table",
        "42703" => "undefined_column",
        "42883" => "undefined_function",
        "42P02" => "undefined_parameter",
        "3F000" => "invalid_schema_name",
        "42601" => "syntax_error",
        "42501" => "insufficient_privilege",
        "42804" => "datatype_mismatch",
        "42846" => "cannot_coerce",
        "22P02" => "invalid_text_representation",
        "22012" => "division_by_zero",
        "22003" => "numeric_value_out_of_range",
        "22007" => "invalid_datetime_format",
        "25006" => "read_only_sql_transaction",
        "57014" => "query_canceled",
        _ => return None,
    })
}

fn sqlstate_label(code: &str) -> String {
    match sqlstate_name(code) {
        Some(n) => format!("{code} {n}"),
        None => code.to_string(),
    }
}

/// The steps of a statement the evaluator did not let run.
fn refused_steps(f: &VerdictFacts, ctx: &ExecuteContext<'_>) -> Vec<NextStep> {
    let rule = f.rule_code.clone();
    if f.status == "PARSE_ERROR" || rule.as_deref() == Some(PARSE_RULE_CODE) {
        if f.parse_error_kind.as_deref() == Some("too_complex") {
            return vec![one(
                "fix_and_recheck",
                format!(
                    "not run: too complex to evaluate; split it into simpler statements, then {}.",
                    again(ctx.access)
                ),
                Some("execute_sql"),
                rule,
            )];
        }
        return vec![one(
            "fix_and_recheck",
            format!(
                "not run: it could not be parsed as {}; fix the syntax, then {}. Do not run it another way.",
                ctx.dialect,
                again(ctx.access)
            ),
            Some("execute_sql"),
            rule,
        )];
    }
    if !f.access_denied.is_empty() {
        return vec![one(
            "request_access",
            format!(
                "not run: the agent access policy does not allow {}. Rephrasing will not help; ask the user to extend the policy.",
                denied_refs(&f.access_denied)
            ),
            None,
            rule,
        )];
    }
    if f.suggested_fix.as_deref().is_some_and(|s| !s.is_empty()) {
        return vec![one(
            "apply_fix_and_recheck",
            format!(
                "not run; apply the suggested fix and {} with the corrected SQL.",
                again(ctx.access)
            ),
            Some("execute_sql"),
            rule,
        )];
    }
    let show = rule
        .as_deref()
        .and_then(|r| call_hint(ctx.access, "show_rule", Some(&format!("show_rule {r}"))));
    let dont = match &rule {
        Some(r) => format!("not run: do not rephrase it to get past {r}"),
        None => "not run: do not rephrase it to get past the rules".to_string(),
    };
    vec![match show {
        Some(show) => one(
            "do_not_run",
            format!("{dont}; {show} to see what the rule allows, or ask the user."),
            ctx.access.has("show_rule").then_some("show_rule"),
            rule,
        ),
        None => one(
            "do_not_run",
            format!("{dont}; ask the user how to proceed."),
            None,
            rule,
        ),
    }]
}

fn executed_steps(
    verdict: &VerdictFacts,
    masked: &[String],
    limit_bound: bool,
    truncation: Option<(&'static str, u64)>,
    row_count: usize,
    ctx: &ExecuteContext<'_>,
) -> Vec<NextStep> {
    let mut steps = Vec::new();
    let rule = verdict.rule_code.clone();
    if !masked.is_empty() || limit_bound {
        let mut what = Vec::new();
        if !masked.is_empty() {
            let more = if masked.len() > 3 {
                format!(" and {} more", masked.len() - 3)
            } else {
                String::new()
            };
            what.push(format!(
                "{}{more} masked",
                masked
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if limit_bound {
            what.push("rows bounded by policy".to_string());
        }
        let tail = if masked.is_empty() {
            "the policy bounds the rows, do not try to read past it another way."
        } else {
            "the values you see are masked by policy, do not try to read them another way."
        };
        steps.push(one(
            "mention_to_user",
            format!("ran the approved rewrite ({}); {tail}", what.join("; ")),
            None,
            rule.clone(),
        ));
    } else if verdict.status == "FLAGGED" || verdict.status == "MONITORED" {
        let what = match (&rule, &verdict.severity) {
            (Some(r), Some(s)) => format!("{r} ({s})"),
            (Some(r), None) => r.clone(),
            _ => "this finding".to_string(),
        };
        steps.push(one(
            "mention_to_user",
            format!("ran; mention {what} to the user."),
            None,
            rule.clone(),
        ));
    }
    if let Some((reason, limit)) = truncation {
        let cut = if reason == "max_rows" {
            format!("the {limit}-row limit")
        } else {
            format!("the {} result limit", bytes_label(limit))
        };
        steps.push(one(
            "refine_query",
            format!(
                "showing {row_count} rows, cut at {cut}; add a WHERE, select fewer columns, or page with ORDER BY and a WHERE on the last key you saw. Do not raise max_rows to read everything."
            ),
            None,
            rule.clone(),
        ));
    }
    if steps.is_empty() {
        steps.push(one(
            "done",
            match ctx.ruleset_version {
                Some(v) => format!("ran under ruleset {v}; nothing else to do."),
                None => "ran as written; nothing else to do.".to_string(),
            },
            None,
            rule,
        ));
    }
    steps
}

fn invalid_message(r: &InvalidReason) -> String {
    match r {
        InvalidReason::MultipleStatements => "not run: send one statement per call".to_string(),
        InvalidReason::NulByte => "not run: the SQL contains a NUL byte; remove it".to_string(),
        InvalidReason::TooLarge { max_bytes } => {
            format!("not run: the SQL is larger than {max_bytes} bytes; send a smaller statement")
        }
        InvalidReason::ParamsMismatch {
            placeholders,
            params,
        } => format!(
            "not run: the statement has {} and {} sent; send one param per placeholder",
            plural(*placeholders, "placeholder", "placeholders"),
            plural(*params, "param was", "params were")
        ),
        InvalidReason::Empty => "not run: the SQL is empty; send one statement".to_string(),
        InvalidReason::Argument(what) => format!("not run: {what}; fix the arguments"),
        InvalidReason::NeverRun(what) => unreachable!("handled apart: {what}"),
    }
}

fn database_error_step(sqlstate: &str, ctx: &ExecuteContext<'_>) -> NextStep {
    let label = sqlstate_label(sqlstate);
    if matches!(sqlstate, "42P01" | "42703" | "42883" | "3F000") {
        let describe = call_hint(ctx.access, "describe_schema", None);
        let tool =
            (describe.is_some() && ctx.access.has("describe_schema")).then_some("describe_schema");
        return one(
            "fix_sql_error",
            format!(
                "the database refused it ({label}); {}.",
                describe
                    .map(|d| format!("{d} to see the tables and columns"))
                    .unwrap_or_else(|| "check the table and column names".to_string())
            ),
            tool,
            None,
        );
    }
    if sqlstate == "42501" || sqlstate == "25006" {
        return one(
            "fix_sql_error",
            format!(
                "the database refused it ({label}): the database role does not allow it; do not look for another way, ask the user."
            ),
            None,
            None,
        );
    }
    if sqlstate.starts_with("22") {
        return one(
            "fix_sql_error",
            format!(
                "the database refused it ({label}); check the values and casts, then {}.",
                again(ctx.access)
            ),
            Some("execute_sql"),
            None,
        );
    }
    one(
        "fix_sql_error",
        format!(
            "the database refused it ({label}); fix the statement, then {}.",
            again(ctx.access)
        ),
        Some("execute_sql"),
        None,
    )
}

fn format_seconds(ms: u32) -> String {
    if ms % 1000 == 0 {
        format!("{} s", ms / 1000)
    } else {
        format!("{:.1} s", f64::from(ms) / 1000.0)
    }
}

/// Everything execute_sql answers about one call, besides the rows (the Rust
/// side of vericto-fmw `executeSqlVerdict`, held equal by
/// `tests/mcp-contract/execute-sql-next-steps.json`).
pub fn execute_verdict(o: &Outcome, ctx: &ExecuteContext<'_>) -> ExecuteVerdict {
    let out = |status, error_code, execution_status, next_steps| ExecuteVerdict {
        status,
        error_code,
        execution_status,
        next_steps,
    };
    match o {
        Outcome::Executed {
            verdict,
            masked_columns,
            limit_bound,
            truncation,
            row_count,
        } => out(
            "EXECUTED",
            None,
            "executed",
            executed_steps(
                verdict,
                masked_columns,
                *limit_bound,
                *truncation,
                *row_count,
                ctx,
            ),
        ),
        Outcome::Blocked(f) => out("BLOCKED", Some("BLOCKED"), "blocked", refused_steps(f, ctx)),
        Outcome::KillSwitch(id) => out(
            "BLOCKED",
            Some("KILL_SWITCH"),
            "blocked",
            vec![kill_switch_step_for(id, vec![1], "execute_sql")],
        ),
        Outcome::TierNotEnabled {
            tier,
            command,
            enabled_tiers,
            database,
            layer,
        } => {
            let message = if *tier == "read" {
                let hint = match layer {
                    Layer::Database => "Proxy mode is off for this database",
                    Layer::Scope => "the key needs the sql:read scope",
                    Layer::Process => "this proxy process does not allow it",
                };
                format!(
                    "not run: reading is not enabled for you on {database} ({hint}); ask the user. Rephrasing will not help."
                )
            } else {
                let list = if enabled_tiers.is_empty() {
                    "no tier".to_string()
                } else {
                    format!("only {}", enabled_tiers.join(", "))
                };
                format!(
                    "not run: this is {} and {list} {} enabled for you on {database}. Each tier (write, delete, DDL) needs a person to enable it, and each statement needs approval; ask the user. Rephrasing will not help.",
                    article(command),
                    if enabled_tiers.len() == 1 {
                        "is"
                    } else {
                        "are"
                    }
                )
            };
            out(
                "BLOCKED",
                Some("TIER_NOT_ENABLED"),
                "tier_refused",
                vec![one("request_write_access", message, None, None)],
            )
        }
        Outcome::TierMismatch { tier, command } => out(
            "ERROR",
            Some("INVALID_INPUT"),
            "invalid",
            vec![one(
                "fix_and_recheck",
                format!(
                    "this statement is {} (tier {tier}); {} with tier: {tier}.",
                    article(command),
                    again(ctx.access)
                ),
                Some("execute_sql"),
                None,
            )],
        ),
        Outcome::InvalidInput(InvalidReason::NeverRun(what)) => out(
            "ERROR",
            Some("INVALID_INPUT"),
            "invalid",
            vec![one(
                "do_not_run",
                format!(
                    "not run: {what} is never run through execute_sql, at any tier. Do not look for another way to run it; ask the user."
                ),
                None,
                None,
            )],
        ),
        Outcome::InvalidInput(r) => out(
            "ERROR",
            Some("INVALID_INPUT"),
            "invalid",
            vec![one(
                "fix_and_recheck",
                format!("{}, then {}.", invalid_message(r), again(ctx.access)),
                Some("execute_sql"),
                None,
            )],
        ),
        Outcome::DatabaseError(code) => out(
            "ERROR",
            Some("DATABASE_ERROR"),
            "db_error",
            vec![database_error_step(code, ctx)],
        ),
        Outcome::Timeout(ms) => out(
            "ERROR",
            Some("TIMEOUT"),
            "timeout",
            vec![one(
                "refine_query",
                format!(
                    "cancelled after {}; narrow it (WHERE on an indexed column, LIMIT). Do not retry it unchanged.",
                    format_seconds(*ms)
                ),
                None,
                None,
            )],
        ),
        Outcome::Unavailable {
            reason,
            sqlstate,
            retry_after_s,
        } => {
            let step = if *reason == Unavailable::Auth
                || sqlstate.as_deref().is_some_and(|s| s.starts_with("28"))
            {
                one(
                    "stop",
                    "stop: Vericto could not log in to the database; do not retry, ask the user to check the proxy's database credentials.".to_string(),
                    None,
                    None,
                )
            } else if *reason == Unavailable::Tls {
                one(
                    "stop",
                    "stop: the TLS check of the database connection failed; do not retry, ask the user to check the proxy's database TLS settings.".to_string(),
                    None,
                    None,
                )
            } else {
                one(
                    "retry_later",
                    format!(
                        "the database is unavailable right now ({}); retry in {retry_after_s} s.",
                        if *reason == Unavailable::PoolBusy {
                            "every connection is busy"
                        } else {
                            "cannot connect"
                        }
                    ),
                    Some("execute_sql"),
                    None,
                )
            };
            out(
                "ERROR",
                Some("DATABASE_UNAVAILABLE"),
                "db_error",
                vec![step],
            )
        }
        Outcome::NotReady(s) => out(
            "ERROR",
            Some("NOT_READY"),
            "blocked",
            vec![one(
                "retry_later",
                format!(
                    "not run: Vericto has not loaded this workspace's rules yet; retry in {s} s."
                ),
                Some("execute_sql"),
                None,
            )],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    struct Access(Vec<String>);
    impl ToolAccess for Access {
        fn has(&self, tool: &str) -> bool {
            self.0.iter().any(|t| t == tool)
        }
    }

    fn s(v: &Value, k: &str) -> Option<String> {
        v.get(k).and_then(Value::as_str).map(str::to_string)
    }

    /// The shared contract: every case of tests/mcp-contract/check-sql-next-steps.json.
    #[test]
    fn next_steps_match_the_contract_fixtures() {
        let raw = include_str!("../../tests/mcp-contract/check-sql-next-steps.json");
        let doc: Value = serde_json::from_str(raw).unwrap();
        let mut n = 0;
        for case in doc["verdict_step"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let f = &case["facts"];
            let facts = VerdictFacts {
                status: s(f, "status").unwrap(),
                rule_code: s(f, "rule_code"),
                severity: s(f, "severity"),
                suggested_fix: s(f, "suggested_fix"),
                approved_query: s(f, "approved_query"),
                access_denied: f
                    .get("access_denied")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|r| DeniedName {
                                schema: s(r, "schema"),
                                table: s(r, "table").unwrap(),
                                column: s(r, "column"),
                                needed: s(r, "needed"),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                parse_error_kind: s(f, "parse_error_kind"),
            };
            let tools: Vec<String> = case["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap().to_string())
                .collect();
            let access = Access(tools);
            let ctx = VerdictContext {
                access: &access,
                dialect: case["dialect"].as_str().unwrap(),
                ruleset_version: case["ruleset_version"].as_str(),
                execute_available: case["execute_available"].as_bool().unwrap_or(false),
            };
            let got = verdict_step(&facts, &ctx);
            let want = &case["expected"];
            assert_eq!(got.action, want["action"].as_str().unwrap(), "{name}");
            assert_eq!(got.message, want["message"].as_str().unwrap(), "{name}");
            assert_eq!(
                got.tool,
                want["tool"].as_str().map(|t| HINT_TOOLS
                    .iter()
                    .find(|x| **x == t)
                    .copied()
                    .unwrap()),
                "{name}"
            );
            n += 1;
        }
        for case in doc["kill_switch_step"].as_array().unwrap() {
            let got = kill_switch_step(case["block_id"].as_str().unwrap(), vec![1]);
            assert_eq!(got.message, case["expected"]["message"].as_str().unwrap());
            n += 1;
        }
        for case in doc["next_steps_text"].as_array().unwrap() {
            let steps: Vec<NextStep> = case["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|st| NextStep {
                    action: NEXT_ACTIONS
                        .iter()
                        .find(|a| **a == st["action"].as_str().unwrap())
                        .copied()
                        .unwrap(),
                    lines: st["lines"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|l| l.as_u64().unwrap() as u32)
                        .collect(),
                    rule_code: s(st, "rule_code"),
                    tool: None,
                    message: st["message"].as_str().unwrap().to_string(),
                })
                .collect();
            let got = next_steps_text(&steps, case["all_lines"].as_bool().unwrap());
            let want: Vec<String> = case["expected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_str().unwrap().to_string())
                .collect();
            assert_eq!(got, want, "{}", case["name"]);
            n += 1;
        }
        assert!(n >= 15, "the fixtures hold {n} cases");
    }

    #[test]
    fn grouping_keeps_precedence_order() {
        let a = Step::new("mention_to_user", None, None, "m".into());
        let b = Step::new("stop", None, None, "s".into());
        let g = group_steps(vec![(3, a.clone()), (1, b), (5, a)]);
        assert_eq!(g[0].action, "stop");
        assert_eq!(g[1].lines, vec![3, 5]);
    }
}
