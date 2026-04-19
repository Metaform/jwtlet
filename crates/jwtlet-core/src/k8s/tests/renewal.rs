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

#![allow(clippy::unwrap_used)]

use crate::k8s::renewal::{FileBasedRenewalTrigger, RenewalTrigger, SaTokenRenewer, SaTokenState};
use async_trait::async_trait;
use dsdk_facet_core::jwt::JwtVerificationError;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::mpsc;

fn write_token_file(content: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("jwtlet-renewal-test-{}.token", uuid::Uuid::new_v4()));
    std::fs::write(&p, content).unwrap();
    p
}

/// A trigger backed by a mpsc channel — fires once per message, stops when the sender drops.
struct ChannelTrigger(mpsc::Receiver<()>);

#[async_trait]
impl RenewalTrigger for ChannelTrigger {
    async fn wait_for_trigger(&mut self) -> Result<(), JwtVerificationError> {
        self.0
            .recv()
            .await
            .ok_or_else(|| JwtVerificationError::VerificationFailed("trigger channel closed".into()))
    }
}

#[test]
fn sa_token_state_stores_and_returns_token() {
    let state = SaTokenState::new("initial-token".to_string());
    assert_eq!(state.token(), "initial-token");
}

#[test]
fn sa_token_state_reflects_direct_update() {
    let mut state = SaTokenState::new("v1".to_string());
    state.token = "v2".to_string();
    assert_eq!(state.token(), "v2");
}

#[tokio::test]
async fn renewer_updates_state_when_trigger_fires() {
    let token_file = write_token_file("initial-token");
    let state = Arc::new(RwLock::new(SaTokenState::new("initial-token".to_string())));

    let (trigger_tx, trigger_rx) = mpsc::channel(1);
    let renewer = Arc::new(SaTokenRenewer {
        token_file: token_file.clone(),
        state: Arc::clone(&state),
    });
    let _handle = renewer.start(Box::new(ChannelTrigger(trigger_rx)));

    // Update the file then signal the trigger
    std::fs::write(&token_file, "rotated-token").unwrap();
    trigger_tx.send(()).await.unwrap();

    // Poll until the background task updates the state (max 1 s)
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    loop {
        if state.read().await.token() == "rotated-token" {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "state was not updated within 1s");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn renewer_stops_cleanly_when_trigger_channel_closes() {
    let token_file = write_token_file("token");
    let state = Arc::new(RwLock::new(SaTokenState::new("token".to_string())));

    let (trigger_tx, trigger_rx) = mpsc::channel(1);
    let renewer = Arc::new(SaTokenRenewer {
        token_file: token_file.clone(),
        state: Arc::clone(&state),
    });
    let handle = renewer.start(Box::new(ChannelTrigger(trigger_rx)));

    // Dropping the sender closes the channel; the renewal loop exits cleanly.
    drop(trigger_tx);
    drop(handle);

    assert_eq!(state.read().await.token(), "token");
}

#[tokio::test]
async fn task_handle_sends_shutdown_signal_on_drop() {
    let token_file = write_token_file("token");
    let state = Arc::new(RwLock::new(SaTokenState::new("token".to_string())));

    let (trigger_tx, trigger_rx) = mpsc::channel(1);
    let renewer = Arc::new(SaTokenRenewer {
        token_file: token_file.clone(),
        state: Arc::clone(&state),
    });
    let handle = renewer.start(Box::new(ChannelTrigger(trigger_rx)));

    drop(handle);

    // After shutdown, any pending trigger send either succeeds or fails — state must not change.
    let _ = trigger_tx.send(()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(state.read().await.token(), "token");
}

#[tokio::test]
async fn file_trigger_fires_when_file_is_written() {
    let token_file = write_token_file("original");
    let mut trigger = FileBasedRenewalTrigger::new(token_file.clone()).unwrap();

    let path = token_file.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        std::fs::write(&path, "updated").unwrap();
    });

    tokio::time::timeout(Duration::from_secs(5), trigger.wait_for_trigger())
        .await
        .expect("timed out waiting for file trigger")
        .expect("trigger returned an error");
}

#[test]
fn file_trigger_returns_error_for_nonexistent_path() {
    let missing = PathBuf::from("/tmp/does-not-exist-jwtlet-renewal-test.token");
    assert!(FileBasedRenewalTrigger::new(missing).is_err());
}
