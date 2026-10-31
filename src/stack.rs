// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Parsing on a thread with a large stack.
//!
//! The parser builds a statement's tree by recursion, so a deeply nested
//! statement needs a deep stack, deeper than the 2 MiB a worker thread has. A
//! thread's stack is reserved address space, committed only as it is touched,
//! so a large one costs memory only for the statements that actually go deep.
//!
//! - In `mcp` mode every parse of agent text (the statement count, the class,
//!   the evaluation) runs here ([`on_big_stack`]), on a thread whose stack holds
//!   the deepest statement `VERICTO_MAX_QUERY_BYTES` lets in.
//! - The TCP proxy evaluates a statement larger than
//!   `VERICTO_INLINE_EVAL_MAX_BYTES` here ([`on_stack_for_statement`]), on a
//!   thread whose stack is sized from the statement's length; a smaller one
//!   runs on a worker, whose stack is [`WORKER_STACK_BYTES`].

/// The stack of the async runtime's threads (workers and blocking pool), set
/// explicitly rather than left at the 2 MiB default: a statement of at most
/// `VERICTO_INLINE_EVAL_MAX_BYTES` is evaluated on a worker.
pub const WORKER_STACK_BYTES: usize = 8 << 20;

/// The stack of an analysis thread: enough for the deepest nesting 1 MiB of
/// SQL can hold (measured on a release build).
pub const ANALYSIS_STACK_BYTES: usize = 256 << 20;

/// Most analysis threads alive at once: a client that floods calls waits for
/// a slot instead of reserving stacks without bound.
pub const MAX_ANALYSIS_THREADS: usize = 8;

/// Stack reserved per byte of SQL for the TCP proxy's evaluation threads.
/// Measured on a release build, the deepest statement of a length needs at
/// most about 250 bytes of stack per byte of SQL (debug builds several times
/// that); this leaves twice that headroom.
const STACK_PER_SQL_BYTE: usize = if cfg!(debug_assertions) { 4096 } else { 512 };

/// The smallest stack of a TCP evaluation thread: what any statement needs
/// before its depth counts, with headroom.
const MIN_STATEMENT_STACK_BYTES: usize = 16 << 20;

/// Which bounded set of threads a parse runs on.
#[derive(Debug, Clone, Copy)]
pub enum Slots {
    /// `mcp` mode: [`MAX_ANALYSIS_THREADS`].
    Mcp,
    /// The TCP proxy: two per CPU the process may use, at least
    /// [`MAX_ANALYSIS_THREADS`]. Evaluation is CPU-bound, so more would only
    /// reserve more stacks.
    Tcp,
}

impl Slots {
    fn semaphore(self) -> &'static tokio::sync::Semaphore {
        use std::sync::OnceLock;
        use tokio::sync::Semaphore;
        static MCP: OnceLock<Semaphore> = OnceLock::new();
        static TCP: OnceLock<Semaphore> = OnceLock::new();
        match self {
            Slots::Mcp => MCP.get_or_init(|| Semaphore::new(MAX_ANALYSIS_THREADS)),
            Slots::Tcp => TCP.get_or_init(|| Semaphore::new(tcp_slots())),
        }
    }
}

fn tcp_slots() -> usize {
    let cpus = std::thread::available_parallelism().map_or(1, usize::from);
    cpus.saturating_mul(2).max(MAX_ANALYSIS_THREADS)
}

/// The stack of the thread that evaluates a statement of `sql_len` bytes.
pub fn statement_stack_bytes(sql_len: usize) -> usize {
    sql_len
        .saturating_mul(STACK_PER_SQL_BYTE)
        .max(MIN_STATEMENT_STACK_BYTES)
}

/// Runs `f` on a fresh thread with [`ANALYSIS_STACK_BYTES`] of stack and
/// waits for it without blocking the async worker.
pub async fn on_big_stack<F, R>(f: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    on_stack(Slots::Mcp, ANALYSIS_STACK_BYTES, f).await
}

/// Runs the evaluation `f` of a statement of `sql_len` bytes on a fresh thread
/// with [`statement_stack_bytes`] of stack, one of the TCP proxy's slots.
/// `None`: the thread could not be started, or `f` did not return.
pub async fn on_stack_for_statement<F, R>(sql_len: usize, f: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    on_stack(Slots::Tcp, statement_stack_bytes(sql_len), f).await
}

/// Runs `f` on a fresh thread with `stack_bytes` of stack, once one of
/// `slots` is free, and waits for it without blocking the async worker.
pub async fn on_stack<F, R>(slots: Slots, stack_bytes: usize, f: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let _slot = slots.semaphore().acquire().await.ok()?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("vericto-parse".into())
        .stack_size(stack_bytes)
        .spawn(move || {
            let _ = tx.send(f());
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, stack_bytes, "Could not start a parse thread");
        return None;
    }
    rx.await.ok()
}

/// [`on_big_stack`] from synchronous code (waits on the calling thread).
#[cfg(test)]
pub fn on_big_stack_sync<F, R>(f: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::thread::Builder::new()
        .name("vericto-parse".into())
        .stack_size(ANALYSIS_STACK_BYTES)
        .spawn(f)
        .ok()?
        .join()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deeply nested statement is counted and classified here without
    /// harm.
    #[tokio::test]
    async fn deeply_nested_statements_are_parsed_on_a_large_stack() {
        let sql = format!("SELECT {}1", "1+".repeat(20_000));
        let (count, class) = on_big_stack(move || {
            (
                crate::mcp::classify::statement_count(&sql),
                crate::mcp::classify::classify(&sql).is_ok(),
            )
        })
        .await
        .unwrap();
        assert_eq!(count, 1);
        let _ = class;
    }

    #[test]
    fn a_statement_stack_grows_with_the_statement() {
        assert_eq!(statement_stack_bytes(0), MIN_STATEMENT_STACK_BYTES);
        assert_eq!(statement_stack_bytes(1025), MIN_STATEMENT_STACK_BYTES);
        assert_eq!(
            statement_stack_bytes(1 << 20),
            (1 << 20) * STACK_PER_SQL_BYTE
        );
        assert_eq!(statement_stack_bytes(usize::MAX), usize::MAX);
    }

    #[tokio::test]
    async fn an_unstartable_thread_is_none_not_a_panic() {
        // More address space than any machine has.
        assert_eq!(on_stack(Slots::Tcp, usize::MAX / 2, || 1).await, None);
        assert_eq!(on_stack_for_statement(10, || 1).await, Some(1));
    }
}
