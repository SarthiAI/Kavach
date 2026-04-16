//! Hot-reload watcher for policy TOML files.
//!
//! Enabled by the `watcher` feature. Watches a policy file on disk and
//! calls [`PolicyEngine::reload`] whenever the file changes, so operators
//! can edit `policies.toml` and have the running gate pick up new rules
//! without a restart.
//!
//! # Failure semantics
//!
//! - A parse error on the new file is **logged and swallowed** — the old,
//!   working policy set continues to run. A typo must not take down the
//!   gate.
//! - Filesystem errors from `notify` are logged; the watcher loop continues.
//! - When the returned [`tokio::task::JoinHandle`] is dropped or aborted,
//!   the watcher shuts down cleanly.
//!
//! # Event debouncing
//!
//! Editors often produce multiple events per save (`write`, `rename`,
//! `chmod`). The watcher collapses bursts within `debounce` into a single
//! reload. Default: 250ms.
//!
//! # Example
//!
//! ```ignore
//! use kavach_core::{PolicyEngine, PolicySet, spawn_policy_watcher};
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let engine = Arc::new(PolicyEngine::new(
//!     PolicySet::from_file("policies.toml").unwrap(),
//! ));
//! let _handle = spawn_policy_watcher(
//!     engine.clone(),
//!     "policies.toml",
//!     Duration::from_millis(250),
//! ).unwrap();
//! // engine is now hot-reloaded on file changes.
//! ```

use crate::policy::{PolicyEngine, PolicySet};
use notify::{Event, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Errors returned when starting a watcher.
#[derive(Debug, Error)]
pub enum WatcherError {
    /// Failed to initialize the OS-level file watcher.
    #[error("failed to start file watcher: {0}")]
    WatcherInit(String),

    /// Failed to begin watching the path.
    #[error("failed to watch path {path:?}: {reason}")]
    WatchPath { path: PathBuf, reason: String },
}

/// Spawn a background task that watches `path` and reloads `engine` on
/// every file modification. Returns the task handle — drop or abort to
/// stop watching.
///
/// `debounce` collapses bursts of FS events (editors often produce several
/// per save) into one reload.
pub fn spawn_policy_watcher(
    engine: Arc<PolicyEngine>,
    path: impl AsRef<Path>,
    debounce: Duration,
) -> Result<JoinHandle<()>, WatcherError> {
    let path = path.as_ref().to_path_buf();
    let (tx, mut rx) = mpsc::unbounded_channel::<notify::Result<Event>>();

    // Build the notify watcher. The callback fires from a notify thread;
    // we just forward events into our mpsc for the async task to consume.
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| WatcherError::WatcherInit(e.to_string()))?;

    watcher
        .watch(&path, RecursiveMode::NonRecursive)
        .map_err(|e| WatcherError::WatchPath {
            path: path.clone(),
            reason: e.to_string(),
        })?;

    let handle = tokio::spawn(async move {
        // Keep the watcher alive for the lifetime of the task — dropping
        // the Watcher stops the underlying OS watch.
        let _watcher_guard = watcher;

        loop {
            // Wait for the first event. If the channel is closed, exit.
            // Event contents don't matter — any filesystem event triggers
            // a reload attempt.
            match rx.recv().await {
                Some(Ok(_ev)) => {}
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "policy watcher error");
                    continue;
                }
                None => {
                    tracing::debug!("policy watcher channel closed — exiting");
                    return;
                }
            }

            // Drain any bursts within the debounce window so we reload once
            // per save even if the editor produced 5 events.
            let deadline = tokio::time::sleep(debounce);
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => break,
                    maybe_ev = rx.recv() => match maybe_ev {
                        Some(_) => continue, // keep draining
                        None => {
                            tracing::debug!("policy watcher channel closed mid-debounce — exiting");
                            return;
                        }
                    }
                }
            }

            // Attempt the reload. Parse errors are logged; engine keeps the
            // previous good policy set.
            match PolicySet::from_file(path.to_str().unwrap_or("")) {
                Ok(set) => {
                    engine.reload(set);
                    tracing::info!(path = ?path, "policy hot-reloaded");
                }
                Err(e) => {
                    tracing::warn!(
                        path = ?path,
                        error = %e,
                        "policy file change detected but parse failed — keeping previous policies"
                    );
                }
            }
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::time::{sleep, Duration as TokioDuration};

    fn engine_from(toml: &str) -> Arc<PolicyEngine> {
        Arc::new(PolicyEngine::new(PolicySet::from_toml(toml).unwrap()))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watcher_reloads_on_file_change() {
        let initial = r#"
[[policy]]
name = "initial"
effect = "permit"
conditions = [{ action = "act" }]
"#;
        let updated = r#"
[[policy]]
name = "updated_one"
effect = "permit"
conditions = [{ action = "act" }]

[[policy]]
name = "updated_two"
effect = "refuse"
conditions = [{ action = "other" }]
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(initial.as_bytes()).unwrap();
        file.flush().unwrap();

        let engine = engine_from(initial);
        assert_eq!(engine.policy_count(), 1);

        let _handle =
            spawn_policy_watcher(engine.clone(), file.path(), Duration::from_millis(50)).unwrap();

        // Give the watcher a moment to set up.
        sleep(TokioDuration::from_millis(100)).await;

        std::fs::write(file.path(), updated).unwrap();

        // Poll until the engine observes the new policy count, or fail after
        // 2 seconds (filesystem watchers on macOS can be laggy).
        let mut got = 0;
        for _ in 0..40 {
            sleep(TokioDuration::from_millis(50)).await;
            got = engine.policy_count();
            if got == 2 {
                return;
            }
        }
        panic!("watcher did not reload; engine still has {got} policies");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watcher_keeps_old_policies_on_parse_error() {
        let initial = r#"
[[policy]]
name = "initial"
effect = "permit"
conditions = [{ action = "act" }]
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(initial.as_bytes()).unwrap();
        file.flush().unwrap();

        let engine = engine_from(initial);
        assert_eq!(engine.policy_count(), 1);

        let _handle =
            spawn_policy_watcher(engine.clone(), file.path(), Duration::from_millis(50)).unwrap();

        sleep(TokioDuration::from_millis(100)).await;

        // Overwrite with garbage. The watcher should log and NOT wipe the
        // engine's loaded policies.
        std::fs::write(file.path(), b"this is not valid toml ::::").unwrap();
        sleep(TokioDuration::from_millis(500)).await;

        assert_eq!(
            engine.policy_count(),
            1,
            "parse error must not clear existing policies"
        );
    }

    #[tokio::test]
    async fn watcher_fails_to_start_on_missing_path() {
        let engine = engine_from("");
        let err = spawn_policy_watcher(
            engine,
            "/definitely/not/a/real/path/to/anything",
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(err, WatcherError::WatchPath { .. }));
    }
}
