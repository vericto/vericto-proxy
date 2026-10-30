// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Parsing on a thread with a large stack.
//!
//! The parser builds a statement's tree by recursion, so a deeply nested
//! statement needs a deep stack, deeper than the 2 MiB a worker thread has. In
//! `mcp` mode every parse of agent text (the statement count, the class, the
//! evaluation) runs here, on a thread whose stack (reserved, committed only as
//! it is touched) holds the deepest statement `VERICTO_MAX_QUERY_BYTES` lets in.

/// The stack of an analysis thread: enough for the deepest nesting 1 MiB of
/// SQL can hold (measured on a release build).
pub const ANALYSIS_STACK_BYTES: usize = 256 << 20;

/// Most analysis threads alive at once: a client that floods calls waits for
/// a slot instead of reserving stacks without bound.
pub const MAX_ANALYSIS_THREADS: usize = 8;

fn slots() -> &'static tokio::sync::Semaphore {
    static SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(MAX_ANALYSIS_THREADS))
}

/// Runs `f` on a fresh thread with [`ANALYSIS_STACK_BYTES`] of stack and
/// waits for it without blocking the async worker.
pub async fn on_big_stack<F, R>(f: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let _slot = slots().acquire().await.ok()?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("vericto-mcp-parse".into())
        .stack_size(ANALYSIS_STACK_BYTES)
        .spawn(move || {
            let _ = tx.send(f());
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "Could not start a parse thread");
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
        .name("vericto-mcp-parse".into())
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
}
