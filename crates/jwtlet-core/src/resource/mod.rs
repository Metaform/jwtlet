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

pub mod mem;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use bon::Builder;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;

#[async_trait]
pub trait ResourceStore: Send + Sync {
    async fn resolve_mapping(
        &self,
        client_identifier: &str,
        participant_context: &str,
    ) -> Result<Option<ResourceMapping>, ResourceError>;

    async fn save_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError>;
    async fn update_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError>;
    async fn remove_mapping(&self, client_identifier: &str, participant_context: &str) -> Result<(), ResourceError>;
    async fn remove_mappings_for(&self, client_identifier: &str) -> Result<(), ResourceError>;
}

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Mapping not found for client: {0}")]
    NotFound(String),
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMapping {
    pub client_identifier: String,
    pub participant_context: String,
    pub scopes: HashSet<String>,
}

#[derive(Builder)]
pub struct ResourceService {
    store: Arc<dyn ResourceStore>,
}

impl ResourceService {
    pub async fn verify(
        &self,
        client_identifier: &str,
        participant_context: &str,
        scopes: Vec<String>,
    ) -> Result<bool, ResourceError> {
        let Some(mapping) = self
            .store
            .resolve_mapping(client_identifier, participant_context)
            .await?
        else {
            return Ok(false);
        };
        Ok(scopes.iter().all(|s| mapping.scopes.contains(s)))
    }

    pub async fn save(&self, mapping: ResourceMapping) -> Result<(), ResourceError> {
        self.store.save_mapping(mapping).await
    }

    pub async fn update(&self, mapping: ResourceMapping) -> Result<(), ResourceError> {
        self.store.update_mapping(mapping).await
    }

    pub async fn remove(&self, client_id: &str, context: &str) -> Result<(), ResourceError> {
        self.store.remove_mapping(client_id, context).await
    }

    pub async fn remove_for(&self, client_id: &str) -> Result<(), ResourceError> {
        self.store.remove_mappings_for(client_id).await
    }
}
