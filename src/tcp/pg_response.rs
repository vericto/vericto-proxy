// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Ordered PostgreSQL responses and prepared-statement state.
//!
//! PostgreSQL permits clients to pipeline frontend messages.  Consequently a
//! local reply cannot be written by the frontend task: an earlier server reply
//! may still be in flight, and a write can split one backend message.  Each
//! frontend message that expects a response registers a bounded plan before it
//! is forwarded.  The server relay is the sole in-session writer and applies
//! local replacements at the corresponding backend response position.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use vericto_engine::{EnforcementPolicy, Rule};

use crate::tcp::codec::PgMessage;
use crate::tcp::policy_rules::PolicyRules;

const MAX_RESPONSE_PLANS: usize = 4096;
const MAX_PREPARED_STATEMENTS: usize = 1024;
const MAX_PORTALS: usize = 4096;
const MAX_PREPARED_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PREPARED_NAME_BYTES: usize = 1024;

/// The policy inputs under which a prepared statement was last evaluated.
#[derive(Clone)]
pub struct EvalSnapshot {
    pub rules: Arc<Vec<Rule>>,
    pub policy: Arc<EnforcementPolicy>,
    pub bundle: Option<Arc<PolicyRules>>,
    pub context: Option<Arc<vericto_engine::policy::EvalContext>>,
}

impl EvalSnapshot {
    pub fn same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.rules, &other.rules)
            && Arc::ptr_eq(&self.policy, &other.policy)
            && match (&self.bundle, &other.bundle) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
            && match (&self.context, &other.context) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

#[derive(Clone)]
pub struct PreparedStatement {
    pub original_sql: Arc<str>,
    pub upstream_sql: Arc<str>,
    pub snapshot: EvalSnapshot,
}

#[derive(Clone)]
struct ParseCandidate {
    id: u64,
    name: Vec<u8>,
    statement: PreparedStatement,
}

#[derive(Clone)]
struct BindCandidate {
    id: u64,
    portal: Vec<u8>,
    statement: Option<PreparedStatement>,
}

/// State changes are committed only after PostgreSQL acknowledges the matching
/// Parse/Bind/Close.  An ErrorResponse drops the candidate and leaves an older
/// object of the same name intact, matching PostgreSQL's behavior.
#[derive(Default)]
pub struct PreparedState {
    statements: HashMap<Vec<u8>, PreparedStatement>,
    portals: HashMap<Vec<u8>, PreparedStatement>,
    parses: HashMap<u64, ParseCandidate>,
    binds: HashMap<u64, BindCandidate>,
    next_id: u64,
}

impl PreparedState {
    fn bounded_name(name: &[u8]) -> std::io::Result<Vec<u8>> {
        if name.len() > MAX_PREPARED_NAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PostgreSQL prepared statement or portal name exceeds the proxy bound",
            ));
        }
        Ok(name.to_vec())
    }

    fn retained_sql_bytes_with(&self, additional: Option<&PreparedStatement>) -> usize {
        let mut seen = HashSet::new();
        let mut bytes = 0usize;
        let mut count = |statement: &PreparedStatement| {
            for sql in [&statement.original_sql, &statement.upstream_sql] {
                let ptr = Arc::as_ptr(sql) as *const () as usize;
                if seen.insert(ptr) {
                    bytes = bytes.saturating_add(sql.len());
                }
            }
        };
        for statement in self.statements.values() {
            count(statement);
        }
        for statement in self.portals.values() {
            count(statement);
        }
        for candidate in self.parses.values() {
            count(&candidate.statement);
        }
        for candidate in self.binds.values() {
            if let Some(statement) = &candidate.statement {
                count(statement);
            }
        }
        if let Some(statement) = additional {
            count(statement);
        }
        bytes
    }

    pub fn statement_for_portal(&self, portal: &[u8]) -> Option<PreparedStatement> {
        self.binds
            .values()
            .filter(|candidate| candidate.portal == portal)
            .max_by_key(|candidate| candidate.id)
            .and_then(|candidate| candidate.statement.clone())
            .or_else(|| self.portals.get(portal).cloned())
    }

    pub fn statement(&self, name: &[u8]) -> Option<PreparedStatement> {
        self.parses
            .values()
            .filter(|candidate| candidate.name == name)
            .max_by_key(|candidate| candidate.id)
            .map(|candidate| candidate.statement.clone())
            .or_else(|| self.statements.get(name).cloned())
    }

    pub fn update_snapshot(&mut self, name: &[u8], snapshot: EvalSnapshot) {
        if let Some(candidate) = self
            .parses
            .values_mut()
            .filter(|candidate| candidate.name == name)
            .max_by_key(|candidate| candidate.id)
        {
            candidate.statement.snapshot = snapshot;
        } else if let Some(statement) = self.statements.get_mut(name) {
            statement.snapshot = snapshot;
        }
    }

    pub fn update_portal_snapshot(&mut self, portal: &[u8], snapshot: EvalSnapshot) {
        if let Some(candidate) = self
            .binds
            .values_mut()
            .filter(|candidate| candidate.portal == portal)
            .max_by_key(|candidate| candidate.id)
            && let Some(statement) = candidate.statement.as_mut()
        {
            statement.snapshot = snapshot;
        } else if let Some(statement) = self.portals.get_mut(portal) {
            statement.snapshot = snapshot;
        }
    }

    pub fn stage_parse(
        &mut self,
        name: &[u8],
        statement: PreparedStatement,
    ) -> std::io::Result<u64> {
        let name = Self::bounded_name(name)?;
        if !self.statements.contains_key(&name)
            && self.statements.len() + self.parses.len() >= MAX_PREPARED_STATEMENTS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "PostgreSQL prepared statement state limit reached",
            ));
        }
        if self.retained_sql_bytes_with(Some(&statement)) > MAX_PREPARED_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "PostgreSQL retained prepared SQL limit reached",
            ));
        }
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        self.parses.insert(
            id,
            ParseCandidate {
                id,
                name,
                statement,
            },
        );
        Ok(id)
    }

    pub fn stage_bind(&mut self, portal: &[u8], statement: &[u8]) -> std::io::Result<u64> {
        let portal = Self::bounded_name(portal)?;
        let statement_name = Self::bounded_name(statement)?;
        if !self.portals.contains_key(&portal)
            && self.portals.len() + self.binds.len() >= MAX_PORTALS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "PostgreSQL portal state limit reached",
            ));
        }
        // A portal owns the prepared plan as it existed at Bind. It remains
        // executable after the source statement is closed or replaced.
        let statement = self.statement(&statement_name);
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        self.binds.insert(
            id,
            BindCandidate {
                id,
                portal,
                statement,
            },
        );
        Ok(id)
    }

    fn commit_parse(&mut self, id: u64) {
        let Some(candidate) = self.parses.remove(&id) else {
            return;
        };
        debug_assert_eq!(candidate.id, id);
        self.statements
            .insert(candidate.name.clone(), candidate.statement);
        // Portals own the executable plan produced by Bind. PostgreSQL keeps
        // them valid when their source statement is closed or when the unnamed
        // statement is replaced, so statement changes never remove portals.
    }

    fn commit_bind(&mut self, id: u64) -> std::io::Result<()> {
        let Some(candidate) = self.binds.remove(&id) else {
            return Ok(());
        };
        debug_assert_eq!(candidate.id, id);
        let statement = candidate.statement.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PostgreSQL accepted a Bind for a statement the proxy could not track",
            )
        })?;
        self.portals.insert(candidate.portal, statement);
        Ok(())
    }

    fn close_statement(&mut self, name: &[u8]) {
        self.statements.remove(name);
        // PostgreSQL portals remain valid after their source statement closes.
    }

    fn close_portal(&mut self, name: &[u8]) {
        self.portals.remove(name);
    }

    fn abort(&mut self, action: &PreparedAction) {
        match action {
            PreparedAction::CommitParse(id) => {
                self.parses.remove(id);
            }
            PreparedAction::CommitBind(id) => {
                self.binds.remove(id);
            }
            _ => {}
        }
    }

    fn apply(&mut self, action: PreparedAction) -> std::io::Result<()> {
        match action {
            PreparedAction::CommitParse(id) => self.commit_parse(id),
            PreparedAction::CommitBind(id) => self.commit_bind(id)?,
            PreparedAction::CloseStatement(name) => self.close_statement(&name),
            PreparedAction::ClosePortal(name) => self.close_portal(&name),
            PreparedAction::SimpleQuery => {
                self.close_statement(b"");
            }
        }
        Ok(())
    }

    fn transaction_end(&mut self) {
        // Bind candidates may already belong to a frontend group pipelined
        // after the Sync whose ReadyForQuery ended this transaction. Earlier
        // candidates have completed or were aborted with the server error.
        self.portals.clear();
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        (self.statements.len(), self.portals.len())
    }
}

#[derive(Clone)]
pub enum PreparedAction {
    CommitParse(u64),
    CommitBind(u64),
    CloseStatement(Vec<u8>),
    ClosePortal(Vec<u8>),
    SimpleQuery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    Simple,
    Parse,
    Bind,
    Describe,
    Execute,
    Close,
    Sync,
    FunctionCall,
}

struct ResponsePlan {
    kind: PlanKind,
    replacement: Option<Vec<u8>>,
    simple_preserve_error: bool,
    simple_saw_error: bool,
    action: Option<PreparedAction>,
    completion: Option<tokio::sync::oneshot::Sender<bool>>,
    _permit: OwnedSemaphorePermit,
}

struct Inner {
    plans: VecDeque<ResponsePlan>,
    server_skip_until_sync: bool,
    startup_complete: bool,
}

/// Shared by the PostgreSQL frontend task and backend relay.
#[derive(Clone)]
pub struct PgResponseCoordinator {
    inner: Arc<Mutex<Inner>>,
    permits: Arc<Semaphore>,
    prepared: Arc<Mutex<PreparedState>>,
}

impl Default for PgResponseCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl PgResponseCoordinator {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                plans: VecDeque::new(),
                server_skip_until_sync: false,
                startup_complete: false,
            })),
            permits: Arc::new(Semaphore::new(MAX_RESPONSE_PLANS)),
            prepared: Arc::new(Mutex::new(PreparedState::default())),
        }
    }

    pub fn prepared(&self) -> &Arc<Mutex<PreparedState>> {
        &self.prepared
    }

    pub fn startup_complete(&self) -> std::io::Result<bool> {
        self.inner
            .lock()
            .map(|inner| inner.startup_complete)
            .map_err(|_| std::io::Error::other("PostgreSQL response coordinator lock poisoned"))
    }

    pub fn complete_startup(&self) -> std::io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| std::io::Error::other("PostgreSQL response coordinator lock poisoned"))?
            .startup_complete = true;
        Ok(())
    }

    #[cfg(test)]
    pub fn has_plans(&self) -> std::io::Result<bool> {
        self.inner
            .lock()
            .map(|inner| !inner.plans.is_empty())
            .map_err(|_| std::io::Error::other("PostgreSQL response coordinator lock poisoned"))
    }

    pub async fn register(
        &self,
        kind: PlanKind,
        replacement: Option<Vec<u8>>,
        preserve_error: bool,
        action: Option<PreparedAction>,
    ) -> std::io::Result<()> {
        self.register_with_completion(kind, replacement, preserve_error, action, None)
            .await
    }

    pub async fn register_simple_with_completion(
        &self,
        replacement: Vec<u8>,
        preserve_error: bool,
        action: Option<PreparedAction>,
    ) -> std::io::Result<tokio::sync::oneshot::Receiver<bool>> {
        let (send, receive) = tokio::sync::oneshot::channel();
        self.register_with_completion(
            PlanKind::Simple,
            Some(replacement),
            preserve_error,
            action,
            Some(send),
        )
        .await?;
        Ok(receive)
    }

    async fn register_with_completion(
        &self,
        kind: PlanKind,
        replacement: Option<Vec<u8>>,
        preserve_error: bool,
        action: Option<PreparedAction>,
        completion: Option<tokio::sync::oneshot::Sender<bool>>,
    ) -> std::io::Result<()> {
        // Backpressure is deliberate: silently evicting a plan could associate a
        // local rejection with another statement's response.
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "response coordinator closed",
                )
            })?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("PostgreSQL response coordinator lock poisoned"))?;
        if inner.server_skip_until_sync {
            if kind == PlanKind::Sync {
                // The frontend Sync is the protocol boundary. Messages the
                // client pipelines after it will be processed by PostgreSQL
                // after recovery even if the backend ReadyForQuery has not
                // arrived yet, so their plans must be retained.
                inner.server_skip_until_sync = false;
            } else {
                drop(permit);
                if let Some(action) = &action {
                    self.prepared
                        .lock()
                        .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?
                        .abort(action);
                }
                if let Some(completion) = completion {
                    let _ = completion.send(false);
                }
                return Ok(());
            }
        }
        inner.plans.push_back(ResponsePlan {
            kind,
            replacement,
            simple_preserve_error: preserve_error,
            simple_saw_error: false,
            action,
            completion,
            _permit: permit,
        });
        Ok(())
    }

    /// Registers the response shape of an ordinary frontend message. Messages
    /// with no response (Flush and CopyData) deliberately consume no queue slot.
    pub async fn register_message(
        &self,
        msg: &PgMessage,
        action: Option<PreparedAction>,
    ) -> std::io::Result<()> {
        let kind = match msg.tag {
            b'Q' => PlanKind::Simple,
            b'P' => PlanKind::Parse,
            b'B' => PlanKind::Bind,
            b'D' => PlanKind::Describe,
            b'E' => PlanKind::Execute,
            b'C' => PlanKind::Close,
            b'S' => PlanKind::Sync,
            b'F' => PlanKind::FunctionCall,
            // Flush, CopyData and CopyDone are continuations of an existing
            // response. CopyFail causes E for that response, not a new cycle.
            b'H' | b'd' | b'c' | b'f' | b'p' | b'X' => return Ok(()),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "unsupported pipelined PostgreSQL frontend message tag {:?}",
                        msg.tag as char
                    ),
                ));
            }
        };
        self.register(kind, None, false, action).await
    }

    fn is_done(kind: PlanKind, tag: u8) -> bool {
        match kind {
            PlanKind::Simple | PlanKind::Sync | PlanKind::FunctionCall => tag == b'Z',
            PlanKind::Parse => tag == b'1' || tag == b'E',
            PlanKind::Bind => tag == b'2' || tag == b'E',
            PlanKind::Describe => matches!(tag, b'T' | b'n' | b'E'),
            // DataRow, CopyData and copy response tags are intermediate.
            PlanKind::Execute => matches!(tag, b'C' | b'I' | b's' | b'E'),
            PlanKind::Close => tag == b'3' || tag == b'E',
        }
    }

    fn pop_completion(inner: &mut Inner, tag: u8) -> (ResponsePlan, Vec<ResponsePlan>) {
        let completed = inner.plans.pop_front().expect("front exists");
        let extended_error =
            tag == b'E' && !matches!(completed.kind, PlanKind::Simple | PlanKind::FunctionCall);
        let mut skipped = Vec::new();
        if extended_error {
            while inner
                .plans
                .front()
                .is_some_and(|plan| plan.kind != PlanKind::Sync)
            {
                skipped.push(inner.plans.pop_front().expect("front exists"));
            }
            // If the frontend Sync is already queued, every plan after it
            // belongs to the recovered cycle and must be accepted even before
            // the backend ReadyForQuery arrives. Otherwise future registrations
            // are skipped until that Sync is registered.
            inner.server_skip_until_sync = !inner
                .plans
                .front()
                .is_some_and(|plan| plan.kind == PlanKind::Sync);
        }
        if completed.kind == PlanKind::Sync && tag == b'Z' {
            inner.server_skip_until_sync = false;
        }
        (completed, skipped)
    }

    fn apply_completion(
        &self,
        mut completed: ResponsePlan,
        skipped: Vec<ResponsePlan>,
        tag: u8,
        ready_status: Option<u8>,
    ) -> std::io::Result<()> {
        if let Some(completion) = completed.completion.take() {
            let _ = completion.send(!completed.simple_saw_error);
        }
        let mut prepared = self
            .prepared
            .lock()
            .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?;
        if tag == b'E' {
            if let Some(action) = &completed.action {
                prepared.abort(action);
            }
        } else if let Some(action) = completed.action {
            prepared.apply(action)?;
        }
        for mut plan in skipped {
            if let Some(completion) = plan.completion.take() {
                let _ = completion.send(false);
            }
            if let Some(action) = &plan.action {
                prepared.abort(action);
            }
        }
        if tag == b'Z' && ready_status == Some(crate::tcp::tx_state::PG_IDLE) {
            prepared.transaction_end();
        }
        Ok(())
    }

    /// What to do with one complete backend message. Async messages are always
    /// visible and never advance a plan. Non-ReadyForQuery terminal messages
    /// complete their plan under this same lock, avoiding a second lock on the
    /// normal extended-protocol path.
    pub fn disposition(&self, tag: u8) -> std::io::Result<BackendDisposition> {
        if is_async(tag) {
            return Ok(BackendDisposition::Forward);
        }
        let (output, completion) = {
            let mut inner = self.inner.lock().map_err(|_| {
                std::io::Error::other("PostgreSQL response coordinator lock poisoned")
            })?;
            let Some(plan) = inner.plans.front_mut() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "PostgreSQL backend message {:?} has no response plan",
                        tag as char
                    ),
                ));
            };
            if tag == b'W' {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "PostgreSQL COPY BOTH/replication is not supported by the ordered response coordinator",
                ));
            }
            let output = if plan.kind == PlanKind::Simple && plan.replacement.is_some() {
                if tag == b'E' {
                    plan.simple_saw_error = true;
                    if plan.simple_preserve_error {
                        BackendDisposition::Forward
                    } else {
                        BackendDisposition::Suppress
                    }
                } else if tag == b'Z' {
                    BackendDisposition::BeforeForward(
                        if plan.simple_preserve_error && plan.simple_saw_error {
                            Vec::new()
                        } else {
                            plan.replacement.clone().unwrap_or_default()
                        },
                    )
                } else {
                    BackendDisposition::Suppress
                }
            } else if tag == b'E' && plan.replacement.is_some() {
                BackendDisposition::Replace(plan.replacement.clone().unwrap_or_default())
            } else {
                BackendDisposition::Forward
            };
            let completion = if tag != b'Z'
                && inner
                    .plans
                    .front()
                    .is_some_and(|front| Self::is_done(front.kind, tag))
            {
                Some(Self::pop_completion(&mut inner, tag))
            } else {
                None
            };
            (output, completion)
        };
        if let Some((completed, skipped)) = completion {
            self.apply_completion(completed, skipped, tag, None)?;
        }
        Ok(output)
    }

    /// ReadyForQuery carries the status byte needed for transaction cleanup,
    /// so its plan completes only after the relay has read that body.
    pub fn finish(&self, tag: u8, ready_status: Option<u8>) -> std::io::Result<()> {
        if tag != b'Z' {
            return Ok(());
        }
        let (completed, skipped) = {
            let mut inner = self.inner.lock().map_err(|_| {
                std::io::Error::other("PostgreSQL response coordinator lock poisoned")
            })?;
            let Some(front) = inner.plans.front() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "backend response completed without a response plan",
                ));
            };
            if !Self::is_done(front.kind, tag) {
                return Ok(());
            }
            Self::pop_completion(&mut inner, tag)
        };
        self.apply_completion(completed, skipped, tag, ready_status)
    }
}

fn is_async(tag: u8) -> bool {
    matches!(tag, b'A' | b'N' | b'S' | b'K')
}

pub enum BackendDisposition {
    Forward,
    Suppress,
    Replace(Vec<u8>),
    BeforeForward(Vec<u8>),
}

/// Reads a cstring as opaque bytes, returning the bytes and next offset.
fn bytes_cstring(body: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let tail = body.get(offset..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    Some((&tail[..end], offset + end + 1))
}

pub fn parse_name(msg: &PgMessage) -> Option<&[u8]> {
    (msg.tag == b'P').then_some(())?;
    bytes_cstring(&msg.body, 0).map(|v| v.0)
}

pub fn bind_names(msg: &PgMessage) -> Option<(&[u8], &[u8])> {
    (msg.tag == b'B').then_some(())?;
    let (portal, after) = bytes_cstring(&msg.body, 0)?;
    let (statement, _) = bytes_cstring(&msg.body, after)?;
    Some((portal, statement))
}

pub fn execute_portal(msg: &PgMessage) -> Option<&[u8]> {
    (msg.tag == b'E').then_some(())?;
    bytes_cstring(&msg.body, 0).map(|v| v.0)
}

pub fn close_target(msg: &PgMessage) -> Option<PreparedAction> {
    (msg.tag == b'C').then_some(())?;
    let (&kind, rest) = msg.body.split_first()?;
    let (name, _) = bytes_cstring(rest, 0)?;
    match kind {
        b'S' => Some(PreparedAction::CloseStatement(name.to_vec())),
        b'P' => Some(PreparedAction::ClosePortal(name.to_vec())),
        _ => None,
    }
}

/// A Parse guaranteed to fail without changing a client statement or portal.
pub fn invalid_parse() -> PgMessage {
    let mut body = b"__vericto_ordered_rejection\0SELECT FROM\0".to_vec();
    body.extend_from_slice(&0i16.to_be_bytes());
    PgMessage { tag: b'P', body }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_names_are_decoded() {
        let p = PgMessage {
            tag: b'P',
            body: b"s\0SELECT 1\0\0\0".to_vec(),
        };
        assert_eq!(parse_name(&p), Some(&b"s"[..]));
        let b = PgMessage {
            tag: b'B',
            body: b"portal\0s\0tail".to_vec(),
        };
        assert_eq!(bind_names(&b), Some((&b"portal"[..], &b"s"[..])));
        let e = PgMessage {
            tag: b'E',
            body: b"portal\0\0\0\0\0".to_vec(),
        };
        assert_eq!(execute_portal(&e), Some(&b"portal"[..]));
    }

    fn snapshot() -> EvalSnapshot {
        EvalSnapshot {
            rules: Arc::new(Vec::new()),
            policy: Arc::new(EnforcementPolicy::default()),
            bundle: None,
            context: None,
        }
    }

    fn statement(sql: &str) -> PreparedStatement {
        PreparedStatement {
            original_sql: Arc::from(sql),
            upstream_sql: Arc::from(sql),
            snapshot: snapshot(),
        }
    }

    #[test]
    fn named_and_unnamed_state_commits_and_closes_on_backend_ack() {
        let mut state = PreparedState::default();
        let named = state.stage_parse(b"named", statement("SELECT 1")).unwrap();
        let unnamed = state.stage_parse(b"", statement("SELECT 2")).unwrap();
        assert!(
            state.statement(b"named").is_some(),
            "candidates resolve for pipelined Bind"
        );
        state.commit_parse(named);
        state.commit_parse(unnamed);
        let bind = state.stage_bind(b"portal", b"named").unwrap();
        state.commit_bind(bind).unwrap();
        assert_eq!(
            state
                .statement_for_portal(b"portal")
                .unwrap()
                .original_sql
                .as_ref(),
            "SELECT 1"
        );
        state.close_statement(b"named");
        assert!(
            state.statement_for_portal(b"portal").is_some(),
            "a portal survives closing its source statement"
        );
        assert!(state.statement(b"").is_some());

        let old_unnamed = state.stage_bind(b"old-unnamed", b"").unwrap();
        state.commit_bind(old_unnamed).unwrap();
        let replacement = state.stage_parse(b"", statement("SELECT 3")).unwrap();
        state.commit_parse(replacement);
        assert_eq!(
            state
                .statement_for_portal(b"old-unnamed")
                .unwrap()
                .original_sql
                .as_ref(),
            "SELECT 2",
            "a portal keeps the plan bound before the unnamed statement changed"
        );
    }

    #[test]
    fn transaction_end_clears_portals_but_preserves_named_statements() {
        let mut state = PreparedState::default();
        let parse = state.stage_parse(b"named", statement("SELECT 1")).unwrap();
        state.commit_parse(parse);
        let bind = state.stage_bind(b"portal", b"named").unwrap();
        state.commit_bind(bind).unwrap();
        state.transaction_end();
        assert!(state.statement(b"named").is_some());
        assert!(state.statement_for_portal(b"portal").is_none());
    }

    #[tokio::test]
    async fn copy_transitions_stay_with_execute_and_copy_both_fails_closed() {
        let responses = PgResponseCoordinator::new();
        responses
            .register(PlanKind::Execute, None, false, None)
            .await
            .unwrap();
        for tag in [b'H', b'd', b'c'] {
            assert!(matches!(
                responses.disposition(tag).unwrap(),
                BackendDisposition::Forward
            ));
            responses.finish(tag, None).unwrap();
            assert!(responses.has_plans().unwrap());
        }
        assert!(matches!(
            responses.disposition(b'C').unwrap(),
            BackendDisposition::Forward
        ));
        responses.finish(b'C', None).unwrap();
        assert!(!responses.has_plans().unwrap());

        responses
            .register(PlanKind::Simple, None, false, None)
            .await
            .unwrap();
        let Err(error) = responses.disposition(b'W') else {
            panic!("COPY BOTH must fail closed");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("COPY BOTH"));
    }

    #[tokio::test]
    async fn recovery_keeps_plans_registered_after_an_already_queued_sync() {
        let responses = PgResponseCoordinator::new();
        responses.complete_startup().unwrap();
        responses
            .register(PlanKind::Parse, None, false, None)
            .await
            .unwrap();
        responses
            .register(PlanKind::Sync, None, false, None)
            .await
            .unwrap();
        assert!(matches!(
            responses.disposition(b'E').unwrap(),
            BackendDisposition::Forward
        ));
        responses.finish(b'E', None).unwrap();
        responses
            .register(PlanKind::Simple, None, false, None)
            .await
            .unwrap();
        responses
            .finish(b'Z', Some(crate::tcp::tx_state::PG_IDLE))
            .unwrap();
        assert!(matches!(
            responses.disposition(b'C').unwrap(),
            BackendDisposition::Forward
        ));
        responses.finish(b'C', None).unwrap();
        responses
            .finish(b'Z', Some(crate::tcp::tx_state::PG_IDLE))
            .unwrap();
        assert!(!responses.has_plans().unwrap());
    }

    #[tokio::test]
    async fn transaction_boundary_keeps_a_bind_candidate_from_the_next_group() {
        let responses = PgResponseCoordinator::new();
        responses.complete_startup().unwrap();
        let parse = responses
            .prepared()
            .lock()
            .unwrap()
            .stage_parse(b"statement", statement("SELECT 1"))
            .unwrap();
        responses.prepared().lock().unwrap().commit_parse(parse);
        responses
            .register(PlanKind::Sync, None, false, None)
            .await
            .unwrap();
        let bind = responses
            .prepared()
            .lock()
            .unwrap()
            .stage_bind(b"portal", b"statement")
            .unwrap();
        responses
            .register(
                PlanKind::Bind,
                None,
                false,
                Some(PreparedAction::CommitBind(bind)),
            )
            .await
            .unwrap();
        responses
            .finish(b'Z', Some(crate::tcp::tx_state::PG_IDLE))
            .unwrap();
        assert!(matches!(
            responses.disposition(b'2').unwrap(),
            BackendDisposition::Forward
        ));
        responses.finish(b'2', None).unwrap();
        assert!(
            responses
                .prepared()
                .lock()
                .unwrap()
                .statement_for_portal(b"portal")
                .is_some()
        );
    }

    #[tokio::test]
    async fn function_call_stays_planned_through_ready_for_query() {
        let responses = PgResponseCoordinator::new();
        responses.complete_startup().unwrap();
        responses
            .register(PlanKind::FunctionCall, None, false, None)
            .await
            .unwrap();
        assert!(matches!(
            responses.disposition(b'V').unwrap(),
            BackendDisposition::Forward
        ));
        responses.finish(b'V', None).unwrap();
        assert!(responses.has_plans().unwrap());
        responses
            .finish(b'Z', Some(crate::tcp::tx_state::PG_IDLE))
            .unwrap();
        assert!(!responses.has_plans().unwrap());
    }

    #[test]
    fn portal_held_sql_stays_inside_the_memory_bound() {
        let mut state = PreparedState::default();
        let sql = "x".repeat(MAX_PREPARED_BYTES / 2);
        let parse = state.stage_parse(b"large", statement(&sql)).unwrap();
        state.commit_parse(parse);
        let bind = state.stage_bind(b"portal", b"large").unwrap();
        state.commit_bind(bind).unwrap();
        state.close_statement(b"large");
        assert!(state.statement(b"large").is_none());
        assert!(state.statement_for_portal(b"portal").is_some());
        assert!(
            state.stage_parse(b"another", statement("x")).is_err(),
            "portal-owned SQL still counts after its source statement closes"
        );
    }

    #[test]
    fn prepared_state_is_bounded() {
        let mut state = PreparedState::default();
        assert!(PreparedState::bounded_name(&vec![b'x'; MAX_PREPARED_NAME_BYTES + 1]).is_err());
        state.portals = (0..MAX_PORTALS)
            .map(|i| (i.to_be_bytes().to_vec(), statement("SELECT 1")))
            .collect();
        assert!(state.stage_bind(b"another", b"").is_err());
        assert_eq!(state.counts(), (0, MAX_PORTALS));
    }
}
