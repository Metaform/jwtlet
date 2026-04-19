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
use crate::resource::{ResourceError, ResourceMapping, ResourceStore};
use std::collections::HashSet;

fn mapping(client_id: &str, context: &str, scopes: &[&str]) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier(client_id.to_string())
        .participant_context(context.to_string())
        .scopes(scopes.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
        .build()
}

#[tokio::test]
async fn save_and_resolve() {
    let store = MemoryResourceStore::new();
    let m = mapping("client1", "ctx1", &["read", "write"]);

    store.save_mapping(m).await.unwrap();

    let result = store.resolve_mapping("client1", "ctx1").await.unwrap();
    assert!(result.is_some());
    let found = result.unwrap();
    assert_eq!(found.client_identifier, "client1");
    assert_eq!(found.participant_context, "ctx1");
    assert!(found.scopes.contains("read"));
    assert!(found.scopes.contains("write"));
}

#[tokio::test]
async fn resolve_returns_none_when_not_found() {
    let store = MemoryResourceStore::new();

    let result = store.resolve_mapping("unknown", "ctx1").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn update_replaces_existing() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();

    let updated = mapping("client1", "ctx1", &["read", "write", "admin"]);
    store.update_mapping(updated).await.unwrap();

    let found = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(found.scopes.len(), 3);
    assert!(found.scopes.contains("admin"));
}

#[tokio::test]
async fn update_returns_not_found_for_missing_mapping() {
    let store = MemoryResourceStore::new();

    let err = store
        .update_mapping(mapping("ghost", "ctx1", &["read"]))
        .await
        .unwrap_err();
    assert!(matches!(err, ResourceError::NotFound(_)));
}

#[tokio::test]
async fn remove_mapping_deletes_entry() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();

    store.remove_mapping("client1", "ctx1").await.unwrap();

    let result = store.resolve_mapping("client1", "ctx1").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn remove_mappings_for_deletes_all_client_entries() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();
    store
        .save_mapping(mapping("client1", "ctx2", &["write"]))
        .await
        .unwrap();
    store.save_mapping(mapping("client2", "ctx1", &["read"])).await.unwrap();

    store.remove_mappings_for("client1").await.unwrap();

    assert!(store.resolve_mapping("client1", "ctx1").await.unwrap().is_none());
    assert!(store.resolve_mapping("client1", "ctx2").await.unwrap().is_none());
    assert!(store.resolve_mapping("client2", "ctx1").await.unwrap().is_some());
}
