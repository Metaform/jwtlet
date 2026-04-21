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

use crate::saccount::{MemoryServiceAccountStore, ServiceAccount, ServiceAccountAuthorizer};
use std::collections::HashSet;

#[tokio::test]
async fn authorize_returns_true_when_client_has_all_required_roles() {
    let store = create_store(&[("client1", &["admin", "reader"])]);

    let required = HashSet::from(["admin", "reader"]);
    let result = store.authorize("client1", &required).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn authorize_returns_true_when_client_has_superset_of_required_roles() {
    let store = create_store(&[("client1", &["admin", "reader", "writer"])]);

    let required = HashSet::from(["reader"]);
    let result = store.authorize("client1", &required).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn authorize_returns_false_when_client_is_missing_a_role() {
    let store = create_store(&[("client1", &["reader"])]);

    let required = HashSet::from(["reader", "admin"]);
    let result = store.authorize("client1", &required).await.unwrap();
    assert!(!result);
}

#[tokio::test]
async fn authorize_returns_false_when_client_does_not_exist() {
    let store = create_store(&[("client1", &["admin"])]);

    let required = HashSet::from(["admin"]);
    let result = store.authorize("unknown", &required).await.unwrap();
    assert!(!result);
}

#[tokio::test]
async fn authorize_returns_true_when_no_roles_required() {
    let store = create_store(&[("client1", &["admin"])]);

    let required = HashSet::new();
    let result = store.authorize("client1", &required).await.unwrap();
    assert!(result);
}

#[tokio::test]
async fn authorize_is_scoped_to_client_id() {
    let store = create_store(&[("client1", &["admin"]), ("client2", &["reader"])]);

    let required = HashSet::from(["admin"]);
    assert!(store.authorize("client1", &required).await.unwrap());
    assert!(!store.authorize("client2", &required).await.unwrap());
}

fn create_store(accounts: &[(&str, &[&str])]) -> MemoryServiceAccountStore {
    MemoryServiceAccountStore::from_accounts(accounts.iter().map(|(id, roles)| {
        ServiceAccount::builder()
            .client_id(*id)
            .roles(roles.iter().map(|r| r.to_string()).collect::<HashSet<_>>())
            .build()
    }))
}
