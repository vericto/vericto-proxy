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
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;
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

/// An [`EvalSnapshot`] by reference: what the session compares against
/// without taking any reference count.
#[derive(Clone, Copy)]
pub struct SnapshotRef<'a> {
    pub rules: &'a Arc<Vec<Rule>>,
    pub policy: &'a Arc<EnforcementPolicy>,
    pub bundle: Option<&'a Arc<PolicyRules>>,
    pub context: Option<&'a Arc<vericto_engine::policy::EvalContext>>,
}

impl SnapshotRef<'_> {
    pub fn to_owned(self) -> EvalSnapshot {
        EvalSnapshot {
            rules: Arc::clone(self.rules),
            policy: Arc::clone(self.policy),
            bundle: self.bundle.cloned(),
            context: self.context.cloned(),
        }
    }
}

impl EvalSnapshot {
    pub fn by_ref(&self) -> SnapshotRef<'_> {
        SnapshotRef {
            rules: &self.rules,
            policy: &self.policy,
            bundle: self.bundle.as_ref(),
            context: self.context.as_ref(),
        }
    }

    /// Whether this is the snapshot `other` refers to (the same `Arc`s).
    pub fn is(&self, other: SnapshotRef<'_>) -> bool {
        Arc::ptr_eq(&self.rules, other.rules)
            && Arc::ptr_eq(&self.policy, other.policy)
            && match (&self.bundle, other.bundle) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
            && match (&self.context, other.context) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }

    pub fn same_as(&self, other: &Self) -> bool {
        self.is(other.by_ref())
    }
}

/// A prepared statement as the proxy tracks it. Shared, with one reference
/// count, by its pending Parse, the statement table and every portal bound
/// from it (4.17.3: a Bind no longer copies the SQL and snapshot handles).
#[derive(Clone)]
pub struct PreparedStatement(Arc<Prepared>);

pub struct Prepared {
    pub original_sql: Arc<str>,
    pub upstream_sql: Arc<str>,
    pub snapshot: EvalSnapshot,
}

impl std::ops::Deref for PreparedStatement {
    type Target = Prepared;

    fn deref(&self) -> &Prepared {
        &self.0
    }
}

impl PreparedStatement {
    pub fn new(original_sql: Arc<str>, upstream_sql: Arc<str>, snapshot: EvalSnapshot) -> Self {
        Self(Arc::new(Prepared {
            original_sql,
            upstream_sql,
            snapshot,
        }))
    }

    /// The statement as evaluated under `snapshot`. Whoever else holds it
    /// (a portal bound earlier) keeps the snapshot it had, as a copy would.
    fn set_snapshot(&mut self, snapshot: EvalSnapshot) {
        match Arc::get_mut(&mut self.0) {
            Some(prepared) => prepared.snapshot = snapshot,
            None => {
                *self = Self::new(
                    Arc::clone(&self.original_sql),
                    Arc::clone(&self.upstream_sql),
                    snapshot,
                )
            }
        }
    }

    /// The SQL it retains, not counting what another entry shares.
    fn own_sql_bytes(&self) -> usize {
        if Arc::ptr_eq(&self.original_sql, &self.upstream_sql) {
            self.original_sql.len()
        } else {
            self.original_sql
                .len()
                .saturating_add(self.upstream_sql.len())
        }
    }
}

/// Bytes of a statement or portal name kept inline.
const INLINE_NAME: usize = 30;

/// A statement or portal name: inline up to [`INLINE_NAME`] bytes, which
/// covers the names drivers generate (`S_1`, `P0_1`, `__asyncpg_stmt_1__`),
/// so tracking one allocates nothing; a longer one is boxed.
#[derive(Clone)]
pub enum Name {
    Inline { len: u8, bytes: [u8; INLINE_NAME] },
    Boxed(Box<[u8]>),
}

impl Name {
    pub fn new(name: &[u8]) -> Self {
        if name.len() <= INLINE_NAME {
            let mut bytes = [0u8; INLINE_NAME];
            bytes[..name.len()].copy_from_slice(name);
            Name::Inline {
                len: name.len() as u8,
                bytes,
            }
        } else {
            Name::Boxed(name.into())
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Name::Inline { len, bytes } => &bytes[..usize::from(*len)],
            Name::Boxed(bytes) => bytes,
        }
    }
}

impl std::ops::Deref for Name {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::borrow::Borrow<[u8]> for Name {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Name {}

impl std::hash::Hash for Name {
    // As `[u8]` hashes, so a `HashMap<Name, _>` is looked up by `&[u8]`.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state)
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self.as_bytes()))
    }
}

#[derive(Clone)]
struct ParseCandidate {
    id: u64,
    name: Name,
    statement: PreparedStatement,
}

#[derive(Clone)]
struct BindCandidate {
    id: u64,
    portal: Name,
    statement: Option<PreparedStatement>,
}

/// Statements or portals by name. The unnamed one, which most drivers use for
/// every statement (and pgbench, libpq and JDBC for every portal), is kept
/// apart, so it costs no hashing.
#[derive(Default)]
struct Named {
    unnamed: Option<PreparedStatement>,
    named: HashMap<Name, PreparedStatement>,
}

impl Named {
    fn get(&self, name: &[u8]) -> Option<&PreparedStatement> {
        if name.is_empty() {
            self.unnamed.as_ref()
        } else {
            self.named.get(name)
        }
    }

    fn get_mut(&mut self, name: &[u8]) -> Option<&mut PreparedStatement> {
        if name.is_empty() {
            self.unnamed.as_mut()
        } else {
            self.named.get_mut(name)
        }
    }

    fn contains_key(&self, name: &[u8]) -> bool {
        self.get(name).is_some()
    }

    fn insert(&mut self, name: Name, statement: PreparedStatement) -> Option<PreparedStatement> {
        if name.is_empty() {
            self.unnamed.replace(statement)
        } else {
            self.named.insert(name, statement)
        }
    }

    fn remove(&mut self, name: &[u8]) -> Option<PreparedStatement> {
        if name.is_empty() {
            self.unnamed.take()
        } else {
            self.named.remove(name)
        }
    }

    fn len(&self) -> usize {
        usize::from(self.unnamed.is_some()) + self.named.len()
    }

    fn values(&self) -> impl Iterator<Item = &PreparedStatement> {
        self.unnamed.iter().chain(self.named.values())
    }

    fn clear(&mut self) {
        self.unnamed = None;
        self.named.clear();
    }
}

/// State changes are committed only after PostgreSQL acknowledges the matching
/// Parse/Bind/Close.  An ErrorResponse drops the candidate and leaves an older
/// object of the same name intact, matching PostgreSQL's behavior.
///
/// It also counts, against one reference snapshot (`epoch`), how many of the
/// statements, portals and candidates it holds were evaluated under another
/// one. While the session's current snapshot is that reference and the count
/// is 0, no Bind or Execute can need a re-evaluation, and
/// [`Self::all_evaluated_under`] says so without looking anything up.
#[derive(Default)]
pub struct PreparedState {
    statements: Named,
    portals: Named,
    /// Pending Parse and Bind candidates, in registration (= id) order: the
    /// backend acknowledges them in that order.
    parses: VecDeque<ParseCandidate>,
    binds: VecDeque<BindCandidate>,
    next_id: u64,
    epoch: Option<EvalSnapshot>,
    stale: usize,
    /// The SQL every entry retains, each counted on its own (shared SQL
    /// counted again): an upper bound of the retained bytes, kept as entries
    /// come and go (4.17.3; a Parse used to sum it over every entry).
    retained_upper: usize,
}

impl PreparedState {
    fn check_name(name: &[u8]) -> std::io::Result<()> {
        if name.len() > MAX_PREPARED_NAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PostgreSQL prepared statement or portal name exceeds the proxy bound",
            ));
        }
        Ok(())
    }

    fn bounded_name(name: &[u8]) -> std::io::Result<Name> {
        Self::check_name(name)?;
        Ok(Name::new(name))
    }

    fn is_stale(epoch: &Option<EvalSnapshot>, snapshot: &EvalSnapshot) -> bool {
        !epoch.as_ref().is_some_and(|epoch| epoch.same_as(snapshot))
    }

    /// An entry now held.
    fn held(&mut self, statement: &PreparedStatement) {
        if Self::is_stale(&self.epoch, &statement.snapshot) {
            self.stale += 1;
        }
        self.retained_upper = self
            .retained_upper
            .saturating_add(statement.own_sql_bytes());
    }

    /// An entry no longer held.
    fn released(&mut self, statement: &PreparedStatement) {
        if Self::is_stale(&self.epoch, &statement.snapshot) {
            self.stale -= 1;
        }
        self.retained_upper = self
            .retained_upper
            .saturating_sub(statement.own_sql_bytes());
    }

    fn entries(&self) -> impl Iterator<Item = &PreparedStatement> {
        self.statements
            .values()
            .chain(self.portals.values())
            .chain(self.parses.iter().map(|candidate| &candidate.statement))
            .chain(
                self.binds
                    .iter()
                    .filter_map(|candidate| candidate.statement.as_ref()),
            )
    }

    /// Whether every statement, portal and candidate held was evaluated under
    /// `current` (then no Bind or Execute needs a re-evaluation for a changed
    /// snapshot). O(1) while `current` stays the same; one pass over the held
    /// entries when it changed, to count them against it.
    pub fn all_evaluated_under(&mut self, current: SnapshotRef<'_>) -> bool {
        if !self.epoch.as_ref().is_some_and(|epoch| epoch.is(current)) {
            self.stale = self
                .entries()
                .filter(|statement| !statement.snapshot.is(current))
                .count();
            self.epoch = Some(current.to_owned());
        }
        self.stale == 0
    }

    fn retained_sql_bytes_with(&self, additional: Option<&PreparedStatement>) -> usize {
        let mut seen = HashSet::new();
        let mut bytes = 0usize;
        for statement in self.entries().chain(additional) {
            for sql in [&statement.original_sql, &statement.upstream_sql] {
                let ptr = Arc::as_ptr(sql) as *const () as usize;
                if seen.insert(ptr) {
                    bytes = bytes.saturating_add(sql.len());
                }
            }
        }
        bytes
    }

    /// The retained SQL counted without sharing: never less than
    /// [`Self::retained_sql_bytes_with`]. Kept incrementally in
    /// `retained_upper`; this recount checks it.
    #[cfg(test)]
    fn retained_sql_upper_bound(&self) -> usize {
        self.entries().fold(0usize, |bytes, statement| {
            bytes.saturating_add(statement.own_sql_bytes())
        })
    }

    #[cfg(test)]
    pub fn statement_for_portal(&self, portal: &[u8]) -> Option<PreparedStatement> {
        self.statement_for_portal_ref(portal).cloned()
    }

    /// The statement a portal executes: the latest pending Bind of that name,
    /// else the committed portal.
    pub fn statement_for_portal_ref(&self, portal: &[u8]) -> Option<&PreparedStatement> {
        self.binds
            .iter()
            .rev()
            .find(|candidate| candidate.portal.as_bytes() == portal)
            .and_then(|candidate| candidate.statement.as_ref())
            .or_else(|| self.portals.get(portal))
    }

    pub fn statement(&self, name: &[u8]) -> Option<PreparedStatement> {
        self.statement_ref(name).cloned()
    }

    /// A statement by name: the latest pending Parse of that name, else the
    /// committed statement.
    pub fn statement_ref(&self, name: &[u8]) -> Option<&PreparedStatement> {
        self.parses
            .iter()
            .rev()
            .find(|candidate| candidate.name.as_bytes() == name)
            .map(|candidate| &candidate.statement)
            .or_else(|| self.statements.get(name))
    }

    pub fn update_snapshot(&mut self, name: &[u8], snapshot: EvalSnapshot) {
        let epoch = &self.epoch;
        let target = match self
            .parses
            .iter_mut()
            .rev()
            .find(|candidate| candidate.name.as_bytes() == name)
        {
            Some(candidate) => Some(&mut candidate.statement),
            None => self.statements.get_mut(name),
        };
        if let Some(statement) = target
            && !statement.snapshot.same_as(&snapshot)
        {
            let delta = (Self::is_stale(epoch, &snapshot) as isize)
                - (Self::is_stale(epoch, &statement.snapshot) as isize);
            statement.set_snapshot(snapshot);
            self.stale = self.stale.wrapping_add_signed(delta);
        }
    }

    pub fn update_portal_snapshot(&mut self, portal: &[u8], snapshot: EvalSnapshot) {
        let epoch = &self.epoch;
        let target = match self
            .binds
            .iter_mut()
            .rev()
            .find(|candidate| candidate.portal.as_bytes() == portal)
        {
            Some(candidate) => candidate.statement.as_mut(),
            None => self.portals.get_mut(portal),
        };
        if let Some(statement) = target
            && !statement.snapshot.same_as(&snapshot)
        {
            let delta = (Self::is_stale(epoch, &snapshot) as isize)
                - (Self::is_stale(epoch, &statement.snapshot) as isize);
            statement.set_snapshot(snapshot);
            self.stale = self.stale.wrapping_add_signed(delta);
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
        // The exact count (shared SQL counted once) only when the upper bound
        // kept incrementally is over the limit.
        if self
            .retained_upper
            .saturating_add(statement.own_sql_bytes())
            > MAX_PREPARED_BYTES
            && self.retained_sql_bytes_with(Some(&statement)) > MAX_PREPARED_BYTES
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "PostgreSQL retained prepared SQL limit reached",
            ));
        }
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        self.held(&statement);
        self.parses.push_back(ParseCandidate {
            id,
            name,
            statement,
        });
        Ok(id)
    }

    pub fn stage_bind(&mut self, portal: &[u8], statement: &[u8]) -> std::io::Result<u64> {
        let portal = Self::bounded_name(portal)?;
        Self::check_name(statement)?;
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
        let statement = self.statement(statement);
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        if let Some(statement) = &statement {
            self.held(statement);
        }
        self.binds.push_back(BindCandidate {
            id,
            portal,
            statement,
        });
        Ok(id)
    }

    fn take_parse(&mut self, id: u64) -> Option<ParseCandidate> {
        // Acknowledged in order: the candidate is normally the first one.
        let candidate = if self.parses.front().is_some_and(|c| c.id == id) {
            self.parses.pop_front()?
        } else {
            let index = self.parses.iter().position(|c| c.id == id)?;
            self.parses.remove(index)?
        };
        self.released(&candidate.statement);
        Some(candidate)
    }

    fn take_bind(&mut self, id: u64) -> Option<BindCandidate> {
        let candidate = if self.binds.front().is_some_and(|c| c.id == id) {
            self.binds.pop_front()?
        } else {
            let index = self.binds.iter().position(|c| c.id == id)?;
            self.binds.remove(index)?
        };
        if let Some(statement) = &candidate.statement {
            self.released(statement);
        }
        Some(candidate)
    }

    fn commit_parse(&mut self, id: u64) {
        let Some(candidate) = self.take_parse(id) else {
            return;
        };
        debug_assert_eq!(candidate.id, id);
        self.held(&candidate.statement);
        if let Some(old) = self.statements.insert(candidate.name, candidate.statement) {
            self.released(&old);
        }
        // Portals own the executable plan produced by Bind. PostgreSQL keeps
        // them valid when their source statement is closed or when the unnamed
        // statement is replaced, so statement changes never remove portals.
    }

    fn commit_bind(&mut self, id: u64) -> std::io::Result<()> {
        let Some(candidate) = self.take_bind(id) else {
            return Ok(());
        };
        debug_assert_eq!(candidate.id, id);
        let statement = candidate.statement.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PostgreSQL accepted a Bind for a statement the proxy could not track",
            )
        })?;
        self.held(&statement);
        if let Some(old) = self.portals.insert(candidate.portal, statement) {
            self.released(&old);
        }
        Ok(())
    }

    fn close_statement(&mut self, name: &[u8]) {
        if let Some(old) = self.statements.remove(name) {
            self.released(&old);
        }
        // PostgreSQL portals remain valid after their source statement closes.
    }

    fn close_portal(&mut self, name: &[u8]) {
        if let Some(old) = self.portals.remove(name) {
            self.released(&old);
        }
    }

    fn abort(&mut self, action: &PreparedAction) {
        match action {
            PreparedAction::CommitParse(id) => {
                self.take_parse(*id);
            }
            PreparedAction::CommitBind(id) => {
                self.take_bind(*id);
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
        let epoch = &self.epoch;
        let (stale_portals, portal_sql) =
            self.portals
                .values()
                .fold((0usize, 0usize), |(stale, bytes), statement| {
                    (
                        stale + usize::from(Self::is_stale(epoch, &statement.snapshot)),
                        bytes.saturating_add(statement.own_sql_bytes()),
                    )
                });
        self.stale -= stale_portals;
        self.retained_upper = self.retained_upper.saturating_sub(portal_sql);
        self.portals.clear();
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        (self.statements.len(), self.portals.len())
    }

    /// The stale count kept incrementally, against a recount.
    #[cfg(test)]
    fn check_stale_count(&self) {
        let recount = self
            .entries()
            .filter(|statement| Self::is_stale(&self.epoch, &statement.snapshot))
            .count();
        assert_eq!(self.stale, recount, "incremental stale count");
        assert_eq!(
            self.retained_upper,
            self.retained_sql_upper_bound(),
            "incremental retained SQL bound"
        );
    }
}

#[derive(Clone)]
pub enum PreparedAction {
    CommitParse(u64),
    CommitBind(u64),
    CloseStatement(Name),
    ClosePortal(Name),
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
    action: Option<PreparedAction>,
    /// A reply the proxy writes itself at this response's position: rare, so
    /// boxed, keeping the plans of ordinary messages small.
    local: Option<Box<LocalReply>>,
}

struct LocalReply {
    bytes: Vec<u8>,
    /// Simple cycles: a server error is kept (and the local bytes then
    /// dropped) instead of suppressed.
    preserve_error: bool,
    saw_error: bool,
    /// Told whether the local reply was sent (no server error came first).
    completion: Option<tokio::sync::oneshot::Sender<bool>>,
}

/// A plan the queue had no room for; see
/// [`PgResponseCoordinator::register_message`].
pub struct PendingPlan(ResponsePlan);

struct Inner {
    plans: VecDeque<ResponsePlan>,
    server_skip_until_sync: bool,
    startup_complete: bool,
    /// The frontend waits for a free slot (the queue held
    /// [`MAX_RESPONSE_PLANS`] plans); the relay wakes it once one is freed.
    frontend_waiting: bool,
}

/// Shared by the PostgreSQL frontend task and backend relay.
#[derive(Clone)]
pub struct PgResponseCoordinator {
    inner: Arc<Mutex<Inner>>,
    /// Signalled by the relay when a slot frees up while the frontend waits.
    space: Arc<Notify>,
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
                frontend_waiting: false,
            })),
            space: Arc::new(Notify::new()),
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

    /// Registers a plan, waiting while the queue is full. The frontend uses
    /// [`Self::register_now`], which lets it send what it holds before it
    /// waits.
    #[cfg(test)]
    pub async fn register(
        &self,
        kind: PlanKind,
        replacement: Option<Vec<u8>>,
        preserve_error: bool,
        action: Option<PreparedAction>,
    ) -> std::io::Result<()> {
        if let Some(full) = self.register_now(kind, replacement, preserve_error, action)? {
            self.register_when_room(full).await?;
        }
        Ok(())
    }

    /// Registers a plan without waiting: `Some` is the plan to pass to
    /// [`Self::register_when_room`] when the queue is full.
    pub fn register_now(
        &self,
        kind: PlanKind,
        replacement: Option<Vec<u8>>,
        preserve_error: bool,
        action: Option<PreparedAction>,
    ) -> std::io::Result<Option<PendingPlan>> {
        let local = replacement.map(|bytes| {
            Box::new(LocalReply {
                bytes,
                preserve_error,
                saw_error: false,
                completion: None,
            })
        });
        Ok(self
            .push(ResponsePlan {
                kind,
                action,
                local,
            })?
            .map(PendingPlan))
    }

    /// A simple cycle's local reply, told whether it was sent; registered as
    /// [`Self::register_now`] does.
    pub fn register_simple_with_completion_now(
        &self,
        replacement: Vec<u8>,
        preserve_error: bool,
        action: Option<PreparedAction>,
    ) -> std::io::Result<(Option<PendingPlan>, tokio::sync::oneshot::Receiver<bool>)> {
        let (send, receive) = tokio::sync::oneshot::channel();
        let full = self
            .push(ResponsePlan {
                kind: PlanKind::Simple,
                action,
                local: Some(Box::new(LocalReply {
                    bytes: replacement,
                    preserve_error,
                    saw_error: false,
                    completion: Some(send),
                })),
            })?
            .map(PendingPlan);
        Ok((full, receive))
    }

    /// Queues `plan`, waiting while the queue is full.
    ///
    /// Backpressure is deliberate: silently evicting a plan could associate a
    /// local rejection with another statement's response. A full queue makes
    /// the frontend wait until the relay completes a plan; the slot count is
    /// the queue length itself, checked under the lock the push takes anyway.
    pub async fn register_when_room(&self, plan: PendingPlan) -> std::io::Result<()> {
        let mut plan = plan.0;
        loop {
            match self.push(plan)? {
                None => return Ok(()),
                // `notify_one` stores a permit when it runs before this wait
                // starts, so a slot freed in between is not missed.
                Some(full) => {
                    plan = full;
                    self.space.notified().await;
                }
            }
        }
    }

    /// Queues `plan` now, or gives it back when the queue is full.
    fn push(&self, plan: ResponsePlan) -> std::io::Result<Option<ResponsePlan>> {
        let mut inner = self.lock_inner()?;
        if inner.plans.len() >= MAX_RESPONSE_PLANS {
            inner.frontend_waiting = true;
            return Ok(Some(plan));
        }
        if inner.server_skip_until_sync {
            if plan.kind == PlanKind::Sync {
                // The frontend Sync is the protocol boundary. Messages the
                // client pipelines after it will be processed by PostgreSQL
                // after recovery even if the backend ReadyForQuery has not
                // arrived yet, so their plans must be retained.
                inner.server_skip_until_sync = false;
            } else {
                if let Some(action) = &plan.action {
                    self.prepared
                        .lock()
                        .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?
                        .abort(action);
                }
                if let Some(completion) = plan.local.and_then(|mut local| local.completion.take()) {
                    let _ = completion.send(false);
                }
                return Ok(None);
            }
        }
        inner.plans.push_back(plan);
        Ok(None)
    }

    fn lock_inner(&self) -> std::io::Result<MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| std::io::Error::other("PostgreSQL response coordinator lock poisoned"))
    }

    /// Registers the response shape of an ordinary frontend message, without
    /// waiting: `Some` is the plan to pass to [`Self::register_when_room`]
    /// when the queue is full (the usual case needs no `.await`). Messages
    /// with no response (Flush and CopyData) deliberately consume no queue slot.
    pub fn register_message(
        &self,
        msg: &PgMessage,
        action: Option<PreparedAction>,
    ) -> std::io::Result<Option<PendingPlan>> {
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
            b'H' | b'd' | b'c' | b'f' | b'p' | b'X' => return Ok(None),
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
        Ok(self
            .push(ResponsePlan {
                kind,
                action,
                local: None,
            })?
            .map(PendingPlan))
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

    /// Opens one coordinator pass for the backend messages the relay holds
    /// whole: one lock of the response queue for all of them (and of the
    /// prepared state only if a completed plan changes it), instead of one or
    /// two per message. Process the messages in wire order with
    /// [`BackendBatch::message`]; the locks are released when the batch drops,
    /// before the relay writes to the client.
    pub fn backend_batch(&self) -> std::io::Result<BackendBatch<'_>> {
        Ok(BackendBatch {
            inner: self.lock_inner()?,
            prepared: None,
            coordinator: self,
            freed: false,
        })
    }

    /// What to do with one backend message (see [`BackendBatch::message`]),
    /// as a pass of its own. For a ReadyForQuery, call [`Self::finish`] once
    /// its status byte has been read.
    pub fn disposition(&self, tag: u8) -> std::io::Result<BackendDisposition> {
        self.backend_batch()?.disposition(tag)
    }

    /// ReadyForQuery carries the status byte needed for transaction cleanup,
    /// so its plan completes only after the relay has read that body.
    #[cfg(test)]
    pub fn finish(&self, tag: u8, ready_status: Option<u8>) -> std::io::Result<()> {
        self.backend_batch()?.finish(tag, ready_status)
    }
}

/// One pass of the relay over the response queue; see
/// [`PgResponseCoordinator::backend_batch`]. Holds `std` mutex guards, so it
/// cannot be kept across an `.await` (the relay task would not be `Send`).
pub struct BackendBatch<'a> {
    inner: MutexGuard<'a, Inner>,
    prepared: Option<MutexGuard<'a, PreparedState>>,
    coordinator: &'a PgResponseCoordinator,
    /// A plan completed: a frontend waiting for a slot can be woken.
    freed: bool,
}

impl BackendBatch<'_> {
    /// What to do with one complete backend message whose body the relay has
    /// read (`ready_status` is the status byte of a ReadyForQuery), and its
    /// plan's completion when the message ends it. Equivalent to
    /// [`Self::disposition`] followed by [`Self::finish`].
    #[inline]
    pub fn message(
        &mut self,
        tag: u8,
        ready_status: Option<u8>,
    ) -> std::io::Result<BackendDisposition> {
        // The usual case, done inline: the response of a plan with no local
        // reply, which does not end in an extended-protocol error (that one
        // skips plans up to the Sync). Same result as the general path below.
        if !is_async(tag)
            && tag != b'W'
            && let Some(front) = self.inner.plans.front()
            && front.local.is_none()
            && (tag != b'E' || matches!(front.kind, PlanKind::Simple | PlanKind::FunctionCall))
        {
            if PgResponseCoordinator::is_done(front.kind, tag) {
                let completed = self.inner.plans.pop_front().expect("front exists");
                if completed.kind == PlanKind::Sync && tag == b'Z' {
                    self.inner.server_skip_until_sync = false;
                }
                let ready = if tag == b'Z' { ready_status } else { None };
                self.complete(completed, Vec::new(), tag, ready)?;
            }
            return Ok(BackendDisposition::Forward);
        }
        let output = self.disposition(tag)?;
        self.finish(tag, ready_status)?;
        Ok(output)
    }

    /// What to do with one backend message. Async messages are always
    /// visible and never advance a plan. Non-ReadyForQuery terminal messages
    /// complete their plan here; a ReadyForQuery completes in [`Self::finish`].
    pub fn disposition(&mut self, tag: u8) -> std::io::Result<BackendDisposition> {
        if is_async(tag) {
            return Ok(BackendDisposition::Forward);
        }
        let inner = &mut *self.inner;
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
        let output = match plan.local.as_deref_mut() {
            // No local reply is planned for this response: the message is the
            // server's own and goes out as read.
            None => BackendDisposition::Forward,
            Some(local) if plan.kind == PlanKind::Simple => {
                if tag == b'E' {
                    local.saw_error = true;
                    if local.preserve_error {
                        BackendDisposition::Forward
                    } else {
                        BackendDisposition::Suppress
                    }
                } else if tag == b'Z' {
                    BackendDisposition::BeforeForward(if local.preserve_error && local.saw_error {
                        Vec::new()
                    } else {
                        local.bytes.clone()
                    })
                } else {
                    BackendDisposition::Suppress
                }
            }
            Some(local) if tag == b'E' => BackendDisposition::Replace(local.bytes.clone()),
            Some(_) => BackendDisposition::Forward,
        };
        if tag != b'Z' && PgResponseCoordinator::is_done(plan.kind, tag) {
            let (completed, skipped) = PgResponseCoordinator::pop_completion(inner, tag);
            self.complete(completed, skipped, tag, None)?;
        }
        Ok(output)
    }

    /// Completes the plan a ReadyForQuery ends, with its status byte.
    pub fn finish(&mut self, tag: u8, ready_status: Option<u8>) -> std::io::Result<()> {
        if tag != b'Z' {
            return Ok(());
        }
        let Some(front) = self.inner.plans.front() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "backend response completed without a response plan",
            ));
        };
        if !PgResponseCoordinator::is_done(front.kind, tag) {
            return Ok(());
        }
        let (completed, skipped) = PgResponseCoordinator::pop_completion(&mut self.inner, tag);
        self.complete(completed, skipped, tag, ready_status)
    }

    fn complete(
        &mut self,
        mut completed: ResponsePlan,
        skipped: Vec<ResponsePlan>,
        tag: u8,
        ready_status: Option<u8>,
    ) -> std::io::Result<()> {
        self.freed = true;
        if let Some(local) = completed.local.as_deref_mut()
            && let Some(completion) = local.completion.take()
        {
            let _ = completion.send(!local.saw_error);
        }
        let transaction_end = tag == b'Z' && ready_status == Some(crate::tcp::tx_state::PG_IDLE);
        let touches_state = completed.action.is_some()
            || transaction_end
            || skipped.iter().any(|plan| {
                plan.action.is_some()
                    || plan
                        .local
                        .as_ref()
                        .is_some_and(|local| local.completion.is_some())
            });
        if !touches_state {
            return Ok(());
        }
        // Same lock order as the frontend (response queue, then prepared
        // state), taken at most once per batch.
        if self.prepared.is_none() {
            self.prepared = Some(
                self.coordinator
                    .prepared
                    .lock()
                    .map_err(|_| std::io::Error::other("prepared state lock poisoned"))?,
            );
        }
        let prepared = self.prepared.as_mut().expect("locked above");
        if tag == b'E' {
            if let Some(action) = &completed.action {
                prepared.abort(action);
            }
        } else if let Some(action) = completed.action {
            prepared.apply(action)?;
        }
        for mut plan in skipped {
            if let Some(completion) = plan
                .local
                .as_deref_mut()
                .and_then(|local| local.completion.take())
            {
                let _ = completion.send(false);
            }
            if let Some(action) = &plan.action {
                prepared.abort(action);
            }
        }
        if transaction_end {
            prepared.transaction_end();
        }
        Ok(())
    }
}

impl Drop for BackendBatch<'_> {
    fn drop(&mut self) {
        if self.freed && self.inner.frontend_waiting {
            self.inner.frontend_waiting = false;
            self.coordinator.space.notify_one();
        }
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
        b'S' => Some(PreparedAction::CloseStatement(Name::new(name))),
        b'P' => Some(PreparedAction::ClosePortal(Name::new(name))),
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
        PreparedStatement::new(Arc::from(sql), Arc::from(sql), snapshot())
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

    /// The incremental count behind [`PreparedState::all_evaluated_under`]
    /// matches a recount after any sequence of stages, commits, aborts,
    /// closes, refreshes and transaction ends under two alternating snapshots;
    /// and the answer matches checking every entry.
    #[test]
    fn the_stale_count_follows_every_state_change() {
        let snapshots = [snapshot(), snapshot()];
        let mut state = PreparedState::default();
        let mut pending_parses: Vec<u64> = Vec::new();
        let mut pending_binds: Vec<u64> = Vec::new();
        let names: [&[u8]; 3] = [b"", b"a", b"b"];
        let mut seed: u64 = 0x5eed;
        let mut next = |n: u64| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) % n
        };
        for _ in 0..20_000 {
            let current = &snapshots[next(2) as usize];
            let name = names[next(3) as usize];
            match next(10) {
                0 | 1 => {
                    let statement = PreparedStatement::new(
                        Arc::from("SELECT 1"),
                        Arc::from("SELECT 1"),
                        current.clone(),
                    );
                    if let Ok(id) = state.stage_parse(name, statement) {
                        pending_parses.push(id);
                    }
                }
                2 | 3 => {
                    if let Ok(id) = state.stage_bind(name, names[next(3) as usize]) {
                        pending_binds.push(id);
                    }
                }
                4 if !pending_parses.is_empty() => {
                    let id = pending_parses.remove(0);
                    if next(4) == 0 {
                        state.abort(&PreparedAction::CommitParse(id));
                    } else {
                        state.commit_parse(id);
                    }
                }
                5 if !pending_binds.is_empty() => {
                    let id = pending_binds.remove(0);
                    if next(4) == 0 {
                        state.abort(&PreparedAction::CommitBind(id));
                    } else {
                        let _ = state.commit_bind(id);
                    }
                }
                6 => state.close_statement(name),
                7 => state.close_portal(name),
                8 => {
                    if next(2) == 0 {
                        state.update_snapshot(name, current.clone());
                    } else {
                        state.update_portal_snapshot(name, current.clone());
                    }
                }
                _ => {
                    if next(3) == 0 {
                        state.transaction_end();
                    } else {
                        let all = state
                            .entries()
                            .all(|statement| statement.snapshot.same_as(current));
                        assert_eq!(state.all_evaluated_under(current.by_ref()), all);
                    }
                }
            }
            state.check_stale_count();
        }
    }

    #[test]
    fn prepared_state_is_bounded() {
        let mut state = PreparedState::default();
        assert!(PreparedState::bounded_name(&vec![b'x'; MAX_PREPARED_NAME_BYTES + 1]).is_err());
        for i in 0..MAX_PORTALS {
            state
                .portals
                .insert(Name::new(&i.to_be_bytes()), statement("SELECT 1"));
        }
        assert!(state.stage_bind(b"another", b"").is_err());
        assert_eq!(state.counts(), (0, MAX_PORTALS));
    }
}
