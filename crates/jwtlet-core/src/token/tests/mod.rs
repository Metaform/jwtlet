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

use crate::resource::{MappingPair, ResourceError, ResourceMapping, ResourceService, ResourceStore, ScopeMapping};
use crate::token::{ExchangeError, TokenExchangeService};
use async_trait::async_trait;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwtGenerationError, JwtGenerator, JwtVerificationError, JwtVerifier, TokenClaims};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

const CLIENT_AUDIENCE: &str = "https://kubernetes.default.svc";
const TOKEN_AUDIENCE: &str = "https://my-service.example.com";
const PARTICIPANT_CONTEXT: &str = "test-context";
const CLIENT_SUB: &str = "system:serviceaccount:default:test-sa";
const CLIENT_ISS: &str = "https://kubernetes.default.svc";

#[tokio::test]
async fn exchange_token_returns_generated_token_on_success() {
    let result = make_service(ok_verifier(), ok_generator(), mapping_store(mapping(&["read"])))
        .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
        .await;
    assert_eq!(result.unwrap(), "generated.jwt.token");
}

#[tokio::test]
async fn exchange_token_returns_unauthorized_when_no_mapping_found() {
    let result = make_service(ok_verifier(), ok_generator(), empty_store())
        .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
        .await;
    assert!(matches!(result, Err(ExchangeError::Unauthorized)));
}

#[tokio::test]
async fn exchange_token_returns_unauthorized_when_scope_not_granted() {
    let result = make_service(ok_verifier(), ok_generator(), mapping_store(mapping(&["write"])))
        .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
        .await;
    assert!(matches!(result, Err(ExchangeError::Unauthorized)));
}

#[tokio::test]
async fn exchange_token_propagates_verification_error() {
    let result = make_service(err_verifier(), ok_generator(), empty_store())
        .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
        .await;
    assert!(matches!(result, Err(ExchangeError::TokenVerification(_))));
}

#[tokio::test]
async fn exchange_token_propagates_store_error() {
    let result = make_service(ok_verifier(), ok_generator(), err_store())
        .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
        .await;
    assert!(matches!(result, Err(ExchangeError::ServiceError(_))));
}

#[tokio::test]
async fn exchange_token_propagates_generation_error() {
    let result = make_service(ok_verifier(), err_generator(), mapping_store(mapping(&["read"])))
        .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
        .await;
    assert!(matches!(result, Err(ExchangeError::Generation(_))));
}

#[tokio::test]
async fn exchange_token_sets_participant_context_as_sub_and_configured_audience() {
    let sink = Arc::new(Mutex::new(None));
    make_service(
        ok_verifier(),
        capturing_generator(Arc::clone(&sink)),
        mapping_store(mapping(&["read"])),
    )
    .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
    .await
    .unwrap();

    let claims = sink.lock().unwrap().take().unwrap();
    assert_eq!(claims.sub, PARTICIPANT_CONTEXT);
    assert_eq!(claims.aud, TOKEN_AUDIENCE);
}

#[tokio::test]
async fn exchange_token_includes_actor_claim_with_client_sub_and_iss() {
    let sink = Arc::new(Mutex::new(None));
    make_service(
        ok_verifier(),
        capturing_generator(Arc::clone(&sink)),
        mapping_store(mapping(&["read"])),
    )
    .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
    .await
    .unwrap();

    let claims = sink.lock().unwrap().take().unwrap();
    let act = claims.custom["act"].as_object().unwrap();
    assert_eq!(act["sub"].as_str().unwrap(), CLIENT_SUB);
    assert_eq!(act["iss"].as_str().unwrap(), CLIENT_ISS);
}

#[tokio::test]
async fn exchange_token_includes_claims_from_scope_mappings() {
    let sink = Arc::new(Mutex::new(None));

    let mut scope_claims = serde_json::Map::new();
    scope_claims.insert("role".to_string(), Value::String("editor".to_string()));
    let mut scope_mappings = HashMap::new();
    scope_mappings.insert(
        "read".to_string(),
        ScopeMapping::builder()
            .scope("read".to_string())
            .claims(scope_claims)
            .build(),
    );

    make_service(
        ok_verifier(),
        capturing_generator(Arc::clone(&sink)),
        mapping_store_with_scopes(mapping(&["read"]), scope_mappings),
    )
    .exchange_token(PARTICIPANT_CONTEXT, vec!["read".to_string()], "input-token")
    .await
    .unwrap();

    let claims = sink.lock().unwrap().take().unwrap();
    assert_eq!(claims.custom["role"], Value::String("editor".to_string()));
}

struct StubVerifier(Box<dyn Fn() -> Result<TokenClaims, JwtVerificationError> + Send + Sync>);

#[async_trait]
impl JwtVerifier for StubVerifier {
    async fn verify_token(&self, _: &str, _: &str) -> Result<TokenClaims, JwtVerificationError> {
        (self.0)()
    }
}

struct StubGenerator(Box<dyn Fn(TokenClaims) -> Result<String, JwtGenerationError> + Send + Sync>);

#[async_trait]
impl JwtGenerator for StubGenerator {
    async fn generate_token(&self, _: &ParticipantContext, claims: TokenClaims) -> Result<String, JwtGenerationError> {
        (self.0)(claims)
    }
}

struct StubStore(Box<dyn Fn() -> Result<Option<MappingPair>, ResourceError> + Send + Sync>);

#[async_trait]
impl ResourceStore for StubStore {
    async fn resolve_mapping(&self, _: &str, _: &str) -> Result<Option<MappingPair>, ResourceError> {
        (self.0)()
    }
    async fn save_mapping(&self, _: ResourceMapping) -> Result<(), ResourceError> {
        unimplemented!()
    }
    async fn update_mapping(&self, _: ResourceMapping) -> Result<(), ResourceError> {
        unimplemented!()
    }
    async fn remove_mapping(&self, _: &str, _: &str) -> Result<(), ResourceError> {
        unimplemented!()
    }
    async fn remove_mappings_for(&self, _: &str) -> Result<(), ResourceError> {
        unimplemented!()
    }
    async fn save_scope_mapping(&self, _: ScopeMapping) -> Result<(), ResourceError> {
        unimplemented!()
    }
    async fn update_scope_mapping(&self, _: ScopeMapping) -> Result<(), ResourceError> {
        unimplemented!()
    }
    async fn delete_scope_mapping(&self, _: &str) -> Result<(), ResourceError> {
        unimplemented!()
    }
}

fn ok_verifier() -> StubVerifier {
    StubVerifier(Box::new(|| Ok(client_claims())))
}

fn err_verifier() -> StubVerifier {
    StubVerifier(Box::new(|| {
        Err(JwtVerificationError::VerificationFailed("bad token".into()))
    }))
}

fn ok_generator() -> StubGenerator {
    StubGenerator(Box::new(|_| Ok("generated.jwt.token".to_string())))
}

fn err_generator() -> StubGenerator {
    StubGenerator(Box::new(|_| {
        Err(JwtGenerationError::GenerationError("vault error".into()))
    }))
}

/// Generator that captures the claims it receives so the test can inspect them.
fn capturing_generator(sink: Arc<Mutex<Option<TokenClaims>>>) -> StubGenerator {
    StubGenerator(Box::new(move |claims| {
        *sink.lock().unwrap() = Some(claims);
        Ok("token".to_string())
    }))
}

fn mapping_store(m: ResourceMapping) -> StubStore {
    mapping_store_with_scopes(m, HashMap::new())
}

fn mapping_store_with_scopes(m: ResourceMapping, scope_mappings: HashMap<String, ScopeMapping>) -> StubStore {
    StubStore(Box::new(move || {
        Ok(Some(MappingPair {
            resource_mapping: m.clone(),
            scope_mappings: scope_mappings.clone(),
        }))
    }))
}

fn empty_store() -> StubStore {
    StubStore(Box::new(|| Ok(None)))
}

fn err_store() -> StubStore {
    StubStore(Box::new(|| {
        Err(ResourceError::DatabaseError("connection failed".into()))
    }))
}

fn client_claims() -> TokenClaims {
    TokenClaims::builder()
        .sub(CLIENT_SUB)
        .iss(CLIENT_ISS)
        .aud(CLIENT_AUDIENCE)
        .exp(9999999999i64)
        .build()
}

fn mapping(scopes: &[&str]) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier(CLIENT_SUB.to_string())
        .participant_context(PARTICIPANT_CONTEXT.to_string())
        .scopes(scopes.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
        .build()
}

fn make_service(verifier: StubVerifier, generator: StubGenerator, store: StubStore) -> TokenExchangeService {
    TokenExchangeService::builder()
        .client_audience(CLIENT_AUDIENCE)
        .audience(TOKEN_AUDIENCE)
        .verifier(Box::new(verifier))
        .generator(Box::new(generator))
        .resource_service(
            ResourceService::builder()
                .store(Arc::new(store) as Arc<dyn ResourceStore>)
                .build(),
        )
        .build()
}
