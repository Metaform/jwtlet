//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

use JwtVerificationError::VerificationFailed;
use async_trait::async_trait;
use dsdk_facet_core::jwt::JwtVerificationError;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, watch};

pub(crate) struct SaTokenState {
    pub(crate) token: String,
}

impl SaTokenState {
    pub(crate) fn new(token: String) -> Self {
        Self { token }
    }

    pub(crate) fn token(&self) -> String {
        self.token.clone()
    }
}

/// Abstraction over the mechanism that signals when the SA token should be re-read.
#[async_trait]
pub(crate) trait RenewalTrigger: Send + Sync {
    async fn wait_for_trigger(&mut self) -> Result<(), JwtVerificationError>;
}

/// Watches the token file for modifications and fires when it changes.
///
/// The kubelet does an atomic rename-write when rotating projected SA tokens, which raises
/// a `Create` or `Modify` event depending on the OS watcher backend.
pub(crate) struct FileBasedRenewalTrigger {
    /// Kept alive so the OS watcher keeps running; never accessed directly.
    _watcher: RecommendedWatcher,
    event_rx: mpsc::Receiver<notify::Result<Event>>,
}

impl FileBasedRenewalTrigger {
    pub(crate) fn new(token_file_path: PathBuf) -> Result<Self, JwtVerificationError> {
        let (event_tx, event_rx) = mpsc::channel(100);

        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = event_tx.try_send(res);
        })
        .map_err(|e| VerificationFailed(format!("Failed to create file watcher: {e}")))?;

        watcher
            .watch(&token_file_path, RecursiveMode::NonRecursive)
            .map_err(|e| {
                VerificationFailed(format!("Failed to watch token file {}: {e}", token_file_path.display()))
            })?;

        Ok(Self {
            _watcher: watcher,
            event_rx,
        })
    }
}

#[async_trait]
impl RenewalTrigger for FileBasedRenewalTrigger {
    async fn wait_for_trigger(&mut self) -> Result<(), JwtVerificationError> {
        loop {
            match self.event_rx.recv().await {
                Some(Ok(event)) => {
                    if matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                    ) {
                        return Ok(());
                    }
                }
                Some(Err(e)) => {
                    return Err(VerificationFailed(format!("File watch error: {e}")));
                }
                None => {
                    return Err(VerificationFailed("File watcher channel closed".to_string()));
                }
            }
        }
    }
}

/// Background task that re-reads the SA token file whenever the trigger fires.
pub(crate) struct SaTokenRenewer {
    pub(crate) token_file: PathBuf,
    pub(crate) state: Arc<RwLock<SaTokenState>>,
}

impl SaTokenRenewer {
    /// Spawns the renewal loop and returns a handle that shuts it down on drop.
    pub(crate) fn start(self: Arc<Self>, mut trigger: Box<dyn RenewalTrigger>) -> TaskHandle {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = trigger.wait_for_trigger() => {
                        match result {
                            Ok(()) => {
                                match tokio::fs::read_to_string(&self.token_file).await {
                                    Ok(raw) => {
                                        let mut state = self.state.write().await;
                                        state.token = raw.trim().to_string();
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to re-read SA token file: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("SA token renewal trigger failed: {e}. Stopping.");
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        TaskHandle {
            shutdown_tx,
            _task: task,
        }
    }
}

pub(crate) struct TaskHandle {
    shutdown_tx: watch::Sender<bool>,
    _task: tokio::task::JoinHandle<()>,
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}
