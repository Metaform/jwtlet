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
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;

#[async_trait]
pub trait ResourceStore: Send + Sync {
    async fn resolve_mapping(
        &self,
        client_identifier: &str,
        participant_context: &str,
    ) -> Result<Option<MappingPair>, ResourceError>;

    async fn save_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError>;
    async fn update_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError>;
    async fn remove_mapping(&self, client_identifier: &str, participant_context: &str) -> Result<(), ResourceError>;
    async fn remove_mappings_for(&self, client_identifier: &str) -> Result<(), ResourceError>;

    async fn save_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError>;
    async fn update_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError>;
    async fn delete_scope_mapping(&self, scope: &str) -> Result<(), ResourceError>;
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

#[derive(Builder, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeMapping {
    pub scope: String,
    pub claims: Map<String, Value>,
}

pub struct MappingPair {
    pub resource_mapping: ResourceMapping,
    pub scope_mappings: HashMap<String, ScopeMapping>,
}

#[derive(Builder)]
pub struct ResourceService {
    store: Arc<dyn ResourceStore>,
}

pub struct VerificationResult {
    pub verified: bool,
    pub claims: HashMap<String, Value>,
}

impl ResourceService {
    pub async fn verify(
        &self,
        client_identifier: &str,
        participant_context: &str,
        scopes: Vec<String>,
    ) -> Result<VerificationResult, ResourceError> {
        let Some(pair) = self
            .store
            .resolve_mapping(client_identifier, participant_context)
            .await?
        else {
            return Ok(VerificationResult {
                verified: false,
                claims: HashMap::new(),
            });
        };
        if !scopes.iter().all(|s| pair.resource_mapping.scopes.contains(s)) {
            return Ok(VerificationResult {
                verified: false,
                claims: HashMap::new(),
            });
        }
        let claims = scopes
            .iter()
            .filter_map(|s| pair.scope_mappings.get(s))
            .flat_map(|sm| sm.claims.iter().map(|(k, v)| (k.clone(), v.clone())))
            .collect();
        Ok(VerificationResult { verified: true, claims })
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

    pub async fn save_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError> {
        self.store.save_scope_mapping(mapping).await
    }

    pub async fn update_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError> {
        self.store.update_scope_mapping(mapping).await
    }

    pub async fn delete_scope_mapping(&self, scope: &str) -> Result<(), ResourceError> {
        self.store.delete_scope_mapping(scope).await
    }
}
