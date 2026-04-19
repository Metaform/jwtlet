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

use crate::resource::mem::MemoryResourceStore;
use crate::resource::{ResourceMapping, ResourceService};
use std::collections::HashSet;
use std::sync::Arc;

#[tokio::test]
async fn verify_returns_false_when_no_mapping_exists() {
    let service = create_service();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string()])
        .await
        .unwrap();
    assert!(!result);
}

#[tokio::test]
async fn verify_returns_true_when_all_scopes_present() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string(), "write".to_string()])
        .await
        .unwrap();
    assert!(result);
}

#[tokio::test]
async fn verify_returns_true_when_requested_scopes_are_subset() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write", "admin"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string()])
        .await
        .unwrap();
    assert!(result);
}

#[tokio::test]
async fn verify_returns_false_when_scope_is_missing() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string(), "write".to_string()])
        .await
        .unwrap();
    assert!(!result);
}

#[tokio::test]
async fn verify_is_scoped_to_participant_context() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx2", vec!["read".to_string()])
        .await
        .unwrap();
    assert!(!result);
}

fn create_service() -> ResourceService {
    ResourceService::builder()
        .store(Arc::new(MemoryResourceStore::new()))
        .build()
}

fn create_mapping(client_id: &str, context: &str, scopes: &[&str]) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier(client_id.to_string())
        .participant_context(context.to_string())
        .scopes(scopes.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
        .build()
}
