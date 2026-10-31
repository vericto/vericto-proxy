// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The state every tool call reads: the configuration, the pool, the synced
//! snapshots shared with the rule syncer (ruleset, policy, allowlists, kill
//! switch, business policies), the telemetry queue, and who is calling.

use std::sync::Arc;
use std::time::Instant;

use serde_json::Value;
use vericto_engine::policy::{DbContext, EvalContext, HostMode, SessionContext, Ticket};
use vericto_engine::{Dialect, EnforcementPolicy, SensitivePolicy};

use crate::mcp::config::{McpConfig, Transport};
use crate::mcp::identity::{self, Identity};
use crate::mcp::pool::Pool;
use crate::tcp::evaluator::{
    PolicyEval, TcpDecision, evaluate_message_guarded, evaluate_message_with_guard,
};
use crate::tcp::kill_switch::{KillBlock, SharedKillSwitch};
use crate::tcp::policy_rules::{
    PolicyRulesMode, PolicyTelemetry, SessionSignals, SharedPolicyRules,
};
use crate::tcp::postgres::EventIdentity;
use crate::tcp::protocol::QueryKind;
use crate::tcp::rules_sync::{
    BundleOrigin, BundleWatch, SharedAccessPolicies, SharedPolicy, SharedRuleset,
    SharedTelemetryMode,
};
use crate::telemetry::{EventQueue, TelemetryEvent};

/// Where events go: the (quota-gated) queue the reporter drains.
#[derive(Clone)]
pub struct EventSink {
    pub queue: Arc<dyn EventQueue>,
    pub database_id: String,
}

/// The synced state, shared with the rule syncer.
#[derive(Clone)]
pub struct Shared {
    pub ruleset: SharedRuleset,
    pub policy: SharedPolicy,
    pub agent_access: SharedAccessPolicies,
    pub kill_switch: SharedKillSwitch,
    pub telemetry_mode: SharedTelemetryMode,
    pub policy_rules: SharedPolicyRules,
    pub watch: Arc<BundleWatch>,
}

impl Shared {
    /// The built-in state: the standard ruleset and default policy, nothing
    /// synced yet.
    pub fn built_in() -> Self {
        use arc_swap::ArcSwap;
        Self {
            ruleset: Arc::new(ArcSwap::from_pointee(
                crate::tcp::evaluator::default_ruleset(),
            )),
            policy: Arc::new(ArcSwap::from_pointee(EnforcementPolicy::default())),
            agent_access: Arc::new(ArcSwap::from_pointee(Default::default())),
            kill_switch: SharedKillSwitch::default(),
            telemetry_mode: Arc::new(ArcSwap::from_pointee(Default::default())),
            policy_rules: Arc::new(ArcSwap::from_pointee(Default::default())),
            watch: Arc::new(BundleWatch::default()),
        }
    }
}

pub struct Runtime {
    pub cfg: McpConfig,
    pub pool: Pool,
    pub shared: Shared,
    pub policy_mode: PolicyRulesMode,
    /// The control-plane link is configured.
    pub linked: bool,
    /// No statement runs before a bundle is in force (§7.5).
    pub require_control_plane: bool,
    /// The keyring trusts at least one bundle-signing key.
    pub trusted_keys: bool,
    pub telemetry: Option<EventSink>,
    pub database_id: Option<String>,
    /// Startup findings repeated in `whoami.warnings` (codes).
    pub warnings: Vec<Value>,
    /// SHA-256 of `VERICTO_API_KEY` (stdio identity), and its fingerprint.
    pub process_key: Option<(String, String)>,
    /// `VERICTO_MCP_AUTH_TOKENS_FILE`.
    pub local_tokens: Vec<Identity>,
    /// stdio: this process's session id (one client, one conversation).
    pub session_id: String,
}

/// The MCP client's declared `clientInfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Who is calling.
#[derive(Debug, Clone)]
pub struct Caller {
    pub transport: Transport,
    pub identity: Option<Identity>,
    pub client: ClientInfo,
}

impl Caller {
    pub fn key_id(&self) -> Option<&str> {
        self.identity.as_ref().and_then(|i| i.key_id.as_deref())
    }
}

/// What one evaluation saw and decided.
pub struct Evaluated {
    pub decision: TcpDecision,
    pub eval_us: u128,
    pub policy: Arc<EnforcementPolicy>,
    pub identity: EventIdentity,
}

impl Runtime {
    /// The stdio caller: the control-plane key, named by the bundle's `mcp`
    /// section (`self.key_id`) when the control plane sends it.
    pub fn stdio_caller(&self, client: ClientInfo) -> Caller {
        let section = self.shared.watch.mcp();
        let identity = self.process_key.as_ref().map(|(sha, _)| {
            let me = section.as_deref().and_then(|s| s.get("self"));
            Identity {
                // The stdio identity is the reporting key, which the API records
                // itself: the event names no other key.
                key_id: me
                    .and_then(|m| m.get("key_id"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                name: Some("control-plane key (VERICTO_API_KEY)".to_string()),
                principal_id: None,
                sha256: sha.clone(),
                expires_at: None,
                kill_switch: identity::kill_block(me.and_then(|m| m.get("kill_switch"))),
            }
        });
        Caller {
            transport: Transport::Stdio,
            identity,
            client,
        }
    }

    /// The identities an HTTP bearer token may belong to now: the signed
    /// bundle's `mcp.identities`, and `VERICTO_MCP_AUTH_TOKENS_FILE`.
    pub fn http_identities(&self) -> Vec<Identity> {
        let mut ids = identity::from_bundle(self.shared.watch.mcp().as_deref());
        ids.extend(self.local_tokens.iter().cloned());
        ids
    }

    /// The per-call limits in force: this process's, lowered to the control
    /// plane's (`mcp.limits`) where those are lower; never raised by it.
    pub fn limits(&self) -> crate::mcp::config::Limits {
        let mut l = self.cfg.limits;
        let Some(section) = self.shared.watch.mcp() else {
            return l;
        };
        let Some(cp) = section.get("limits") else {
            return l;
        };
        let get = |k: &str| cp.get(k).and_then(Value::as_u64).filter(|v| *v > 0);
        let low32 =
            |cur: u32, k: &str| get(k).map_or(cur, |v| cur.min(v.min(u64::from(u32::MAX)) as u32));
        let lowsz = |cur: usize, k: &str| get(k).map_or(cur, |v| cur.min(v as usize));
        l.max_rows_cap = low32(l.max_rows_cap, "max_rows_cap");
        l.max_rows = low32(l.max_rows, "max_rows").min(l.max_rows_cap);
        l.max_result_bytes = lowsz(l.max_result_bytes, "max_result_bytes");
        l.max_cell_bytes = lowsz(l.max_cell_bytes, "max_cell_bytes");
        l.statement_timeout_cap_ms = low32(l.statement_timeout_cap_ms, "statement_timeout_cap_ms");
        l.statement_timeout_ms =
            low32(l.statement_timeout_ms, "statement_timeout_ms").min(l.statement_timeout_cap_ms);
        l.lock_timeout_ms = low32(l.lock_timeout_ms, "lock_timeout_ms");
        l
    }

    /// Whether the read tier is enabled (the bundle's `mcp.tiers.read`; a
    /// control plane that sends no `mcp` section leaves it enabled), and the
    /// layer that closes it when it is not.
    pub fn read_tier(&self) -> Result<(), crate::mcp::next_steps::Layer> {
        use crate::mcp::next_steps::Layer;
        let Some(section) = self.shared.watch.mcp() else {
            return Ok(());
        };
        let read = section
            .get("tiers")
            .and_then(|t| t.get("read"))
            .and_then(Value::as_str);
        if matches!(read, None | Some("enabled")) {
            return Ok(());
        }
        let own_scope = section
            .get("self")
            .and_then(|m| m.get("sql_read"))
            .and_then(Value::as_bool);
        Err(if own_scope == Some(false) {
            Layer::Scope
        } else {
            Layer::Database
        })
    }

    /// The tools hints may name on this server.
    pub fn access(&self) -> crate::mcp::next_steps::ProxyAccess {
        crate::mcp::next_steps::ProxyAccess {
            linked: self.linked,
        }
    }

    /// No bundle yet and one is required (`NOT_READY`).
    pub fn not_ready(&self) -> bool {
        self.require_control_plane && self.shared.watch.origin() == BundleOrigin::None
    }

    /// The version of the rules in force: the bundle's, else the built-in
    /// ruleset's.
    pub fn ruleset_version(&self) -> String {
        self.shared
            .watch
            .version()
            .map(|v| (*v).clone())
            .unwrap_or_else(|| vericto_engine::STANDARD_RULESET_VERSION.to_string())
    }

    /// The database's name as the agent sees it.
    pub fn database_name(&self) -> &str {
        &self.cfg.database.dbname
    }

    /// The kill-switch block that refuses `caller` now, if any: its key's
    /// (HTTP: the agent key's; stdio: the proxy key's), the proxy key's (it
    /// stops every caller of this server), or the database user's and the
    /// workspace's, as on the TCP path. Read fresh for every call.
    pub fn kill_switch_block(&self, caller: &Caller) -> Option<Arc<KillBlock>> {
        if caller.transport == Transport::Http {
            let current = self.http_identities();
            if let Some(b) = caller
                .identity
                .as_ref()
                .and_then(|me| current.into_iter().find(|i| i.sha256 == me.sha256))
                .and_then(|i| i.kill_switch)
            {
                return Some(Arc::new(b));
            }
        }
        let section = self.shared.watch.mcp();
        if let Some(b) = identity::kill_block(
            section
                .as_deref()
                .and_then(|s| s.get("self"))
                .and_then(|m| m.get("kill_switch")),
        ) {
            return Some(Arc::new(b));
        }
        self.shared
            .kill_switch
            .load()
            .as_ref()
            .and_then(|ks| ks.for_user(Some(self.cfg.database.user.as_str())).cloned())
    }

    /// The listener label principals can name (`mcp:stdio`, `mcp:http`).
    fn listener(&self) -> &'static str {
        match self.cfg.transport {
            Transport::Stdio => "mcp:stdio",
            Transport::Http => "mcp:http",
        }
    }

    /// The workspace policy with the database user's allowlist applied, as a
    /// TCP session of that user gets it.
    ///
    /// Unqualified names must mean the same table to the evaluator and to the
    /// database (design §7.2): with `VERICTO_MCP_SEARCH_PATH` set, its first
    /// schema is the allowlist's default schema; without it, the search path
    /// is pinned to the allowlist's default schema ([`Self::search_path`]).
    pub fn policy_for_db_user(&self) -> Arc<EnforcementPolicy> {
        let base = self.shared.policy.load_full();
        let map = self.shared.agent_access.load_full();
        match crate::tcp::session::select_policy(&map, Some(self.cfg.database.user.as_str())) {
            None => base,
            Some(mut access) => {
                if let Some(first) = self.cfg.search_path.as_ref().and_then(|p| p.first()) {
                    access.default_schema = Some(first.clone());
                }
                Arc::new(EnforcementPolicy {
                    access_policy: Some(access),
                    ..(*base).clone()
                })
            }
        }
    }

    /// The search path a call pins: `VERICTO_MCP_SEARCH_PATH`; else, under an
    /// allowlist, its default schema (the engine's `public` when it names
    /// none), so a role whose own search path points elsewhere cannot make
    /// `users` mean another table than the one the allowlist checked; else the
    /// role's own.
    pub fn search_path(&self, policy: &EnforcementPolicy) -> Option<Vec<String>> {
        if let Some(p) = &self.cfg.search_path {
            return Some(p.clone());
        }
        policy.access_policy.as_ref().map(|a| {
            vec![
                a.default_schema
                    .clone()
                    .unwrap_or_else(|| "public".to_string()),
            ]
        })
    }

    /// Evaluates `sql` under one snapshot of everything synced (§7.1 step 2),
    /// with the MCP identity as the principal (§11.4).
    pub fn evaluate(
        &self,
        sql: &str,
        kind: QueryKind,
        caller: &Caller,
        ticket: Option<&str>,
        policy: Arc<EnforcementPolicy>,
    ) -> Evaluated {
        let rules = self.shared.ruleset.load_full();
        let start = Instant::now();
        let (decision, telemetry) = if self.policy_mode.is_on() {
            let bundle = self.shared.policy_rules.load_full();
            let principal = bundle.principals.resolve(&SessionSignals {
                db_user: Some(self.cfg.database.user.as_str()),
                application_name: None,
                listener: self.listener(),
                mcp_credential: caller.key_id(),
            });
            let telemetry = PolicyTelemetry {
                principal_id: Some(principal.id.clone()),
                principal_type: Some(principal.principal_type.as_str().to_string()),
                principal_trust: Some(principal.trust.as_str().to_string()),
                principal_via: principal.via.clone(),
                application_name: None,
                policy_bundle_version: bundle.version.clone(),
                ticket_id: ticket.map(str::to_string),
                session_tenant: None,
            };
            let mut session = SessionContext::new();
            session.listener = Some(self.listener().to_string());
            let mut ctx = EvalContext::new()
                .with_mode(HostMode::Mcp)
                .with_principal(principal)
                .with_session(session);
            if let Some(id) = &self.database_id {
                ctx = ctx.with_db(DbContext::new().with_id(id.clone()));
            }
            if let Some(t) = ticket {
                ctx = ctx.with_ticket(Ticket::declared(t.to_string()));
            }
            let ctx = crate::tcp::policy_rules::at_now(&ctx);
            let rules = bundle.rules.as_ref().unwrap_or(&rules);
            let d = evaluate_message_with_guard(
                sql,
                Dialect::Postgres,
                kind,
                rules,
                &policy,
                Some(&PolicyEval {
                    mode: self.policy_mode,
                    policies: &bundle.policies,
                    ctx: &ctx,
                }),
                self.cfg.max_binary_operators,
            );
            (d, Some(Arc::new(telemetry)))
        } else {
            (
                evaluate_message_guarded(
                    sql,
                    Dialect::Postgres,
                    kind,
                    &rules,
                    &policy,
                    self.cfg.max_binary_operators,
                ),
                None,
            )
        };
        let eval_us = start.elapsed().as_micros();
        let identity = EventIdentity {
            db_user: Some(self.cfg.database.user.clone()),
            access_mode: policy.access_policy.as_ref().map(|p| p.mode),
            policy: telemetry,
        };
        Evaluated {
            decision,
            eval_us,
            policy,
            identity,
        }
    }

    /// Builds the event of one call (the evaluator's mapping, then the MCP
    /// fields) and queues it. Never blocks; a no-op without the link.
    pub fn emit(
        &self,
        sql: &str,
        decision: &TcpDecision,
        eval_us: u128,
        identity: &EventIdentity,
        fill: impl FnOnce(&mut TelemetryEvent),
    ) -> Option<String> {
        let sink = self.telemetry.as_ref()?;
        let mode = **self.shared.telemetry_mode.load();
        let mut ev = crate::tcp::postgres::build_event(
            &sink.database_id,
            sql,
            Dialect::Postgres,
            decision,
            eval_us,
            mode,
            identity,
            chrono::Utc::now(),
        );
        ev.source = Some(crate::telemetry::MCP_PROXY_SOURCE.to_string());
        fill(&mut ev);
        let id = ev.event_id.clone();
        sink.queue.push(ev);
        Some(id)
    }

    /// The MCP fields every event of `caller` carries.
    pub fn caller_fields(&self, caller: &Caller, ev: &mut TelemetryEvent) {
        ev.mcp_client_name = caller.client.name.clone();
        ev.mcp_client_version = caller.client.version.clone();
        ev.session_kind = Some(match caller.transport {
            Transport::Stdio => "stdio".to_string(),
            Transport::Http => "per_call".to_string(),
        });
        if caller.transport == Transport::Stdio {
            ev.session_id_hash =
                Some(identity::sha256_hex(self.session_id.as_bytes())[..16].to_string());
        }
        // Streamable HTTP: the agent key is the identity (the API keeps it
        // when it is a key of the reporting key's workspace). stdio: the
        // reporting key is, and the event names none.
        if caller.transport == Transport::Http
            && let Some(id) = &caller.identity
        {
            ev.api_key_id = id.key_id.clone();
        }
    }

    /// `taint` of every answer (§6.3, §10.7): trust labels are not in this
    /// release, so no session is ever tainted; the object is present so a
    /// client reads one shape from the first release on.
    pub fn taint(&self) -> Value {
        // The contract (execute-sql-output.json, whoami-execution.json): null
        // until trust labels and taint exist (M1.4).
        Value::Null
    }

    /// The mask style of an output column the engine reports as masked.
    pub fn mask_of(
        &self,
        policy: &EnforcementPolicy,
        touched: &[vericto_engine::TouchedColumn],
        column: &str,
    ) -> Option<String> {
        let t = touched
            .iter()
            .find(|t| t.policy == SensitivePolicy::Mask && t.column.eq_ignore_ascii_case(column))?;
        let style = policy
            .sensitive_columns
            .iter()
            .find(|s| {
                s.column.eq_ignore_ascii_case(&t.column)
                    && s.table.eq_ignore_ascii_case(&t.table)
                    && s.policy == SensitivePolicy::Mask
            })
            .map(|s| mask_style_name(&s.mask_style))
            .unwrap_or("mask");
        Some(style.to_string())
    }
}

/// The name of a mask style, as the dashboard shows it.
pub fn mask_style_name(style: &vericto_engine::MaskStyle) -> &'static str {
    match style {
        vericto_engine::MaskStyle::Full => "full",
        vericto_engine::MaskStyle::Last4 => "last4",
        vericto_engine::MaskStyle::Email => "email",
        vericto_engine::MaskStyle::Hash => "hash",
    }
}
