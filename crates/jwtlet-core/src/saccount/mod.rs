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

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use bon::Builder;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// A principal that has access to management resources.
#[derive(Builder, Debug, Clone)]
pub struct ServiceAccount {
    #[builder(into)]
    pub client_id: String,
    pub roles: HashSet<String>,
}

/// Trait representing a service account authorizer responsible for verifying whether a client holds all required roles.
#[async_trait]
pub trait ServiceAccountAuthorizer: Send + Sync {
    async fn authorize(&self, client_id: &str, required_roles: &HashSet<&str>) -> Result<bool, AuthError>;
}

/// In-memory implementation of [`ServiceAccountAuthorizer`] preloaded at construction time.
pub struct MemoryServiceAccountStore {
    accounts: HashMap<String, HashSet<String>>,
}

impl MemoryServiceAccountStore {
    pub fn from_accounts(accounts: impl IntoIterator<Item = ServiceAccount>) -> Self {
        Self {
            accounts: accounts.into_iter().map(|sa| (sa.client_id, sa.roles)).collect(),
        }
    }
}

#[async_trait]
impl ServiceAccountAuthorizer for MemoryServiceAccountStore {
    async fn authorize(&self, client_id: &str, required_roles: &HashSet<&str>) -> Result<bool, AuthError> {
        Ok(self.accounts.get(client_id).map_or(false, |roles| {
            required_roles.is_subset(&roles.iter().map(String::as_str).collect())
        }))
    }
}

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("General error: {0}")]
    GeneralError(String),
}
