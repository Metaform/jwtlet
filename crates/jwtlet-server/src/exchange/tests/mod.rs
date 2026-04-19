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

use crate::exchange::{TOKEN_EXCHANGE_GRANT_TYPE, TokenExchangeForm, token_exchange};
use async_trait::async_trait;
use axum::body::to_bytes;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwtGenerationError, JwtGenerator, JwtVerificationError, JwtVerifier, TokenClaims};
use jwtlet_core::resource::{ResourceError, ResourceMapping, ResourceService, ResourceStore};
use jwtlet_core::token::TokenExchangeService;
use std::collections::HashSet;
use std::sync::Arc;

const CLIENT_AUDIENCE: &str = "https://kubernetes.default.svc";
const TOKEN_AUDIENCE: &str = "https://my-service.example.com";
const PARTICIPANT_CONTEXT: &str = "test-context";

#[tokio::test]
async fn exchange_token_returns_200_with_token_on_success() {
    let service = make_service(ok_verifier(), ok_generator(), mapping_store(mapping(&["read"])));
    let response = token_exchange(State(Arc::new(service)), Form(form(Some("read")))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["access_token"], "generated.jwt.token");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["issued_token_type"], "urn:ietf:params:oauth:token-type:jwt");
}

#[tokio::test]
async fn exchange_token_returns_400_for_wrong_grant_type() {
    let service = make_service(ok_verifier(), ok_generator(), empty_store());
    let mut f = form(None);
    f.grant_type = "client_credentials".to_string();
    let response = token_exchange(State(Arc::new(service)), Form(f)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn exchange_token_returns_403_for_unauthorized() {
    let service = make_service(ok_verifier(), ok_generator(), empty_store());
    let response = token_exchange(State(Arc::new(service)), Form(form(None))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = json_body(response).await;
    assert_eq!(body["error"], "unauthorized_client");
}

#[tokio::test]
async fn exchange_token_returns_400_for_token_verification_failure() {
    let service = make_service(err_verifier(), ok_generator(), empty_store());
    let response = token_exchange(State(Arc::new(service)), Form(form(None))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn exchange_token_returns_500_for_service_error() {
    let service = make_service(ok_verifier(), ok_generator(), err_store());
    let response = token_exchange(State(Arc::new(service)), Form(form(None))).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = json_body(response).await;
    assert_eq!(body["error"], "server_error");
}

#[tokio::test]
async fn exchange_token_returns_500_for_generation_error() {
    let service = make_service(ok_verifier(), err_generator(), mapping_store(mapping(&[])));
    let response = token_exchange(State(Arc::new(service)), Form(form(None))).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = json_body(response).await;
    assert_eq!(body["error"], "server_error");
}

#[tokio::test]
async fn exchange_token_parses_scope_as_space_separated_list() {
    let service = make_service(ok_verifier(), ok_generator(), mapping_store(mapping(&["read", "write"])));
    let response = token_exchange(State(Arc::new(service)), Form(form(Some("read write")))).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn exchange_token_passes_empty_scopes_when_scope_absent() {
    let service = make_service(ok_verifier(), ok_generator(), mapping_store(mapping(&[])));
    let response = token_exchange(State(Arc::new(service)), Form(form(None))).await;
    assert_eq!(response.status(), StatusCode::OK);
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn form(scope: Option<&str>) -> TokenExchangeForm {
    TokenExchangeForm {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE.to_string(),
        subject_token: "input.jwt.token".to_string(),
        resource: PARTICIPANT_CONTEXT.to_string(),
        scope: scope.map(str::to_string),
    }
}

fn make_service(verifier: StubVerifier, generator: StubGenerator, store: StubStore) -> TokenExchangeService {
    TokenExchangeService::builder()
        .client_audience(CLIENT_AUDIENCE)
        .audience(TOKEN_AUDIENCE)
        .verifier(Box::new(verifier))
        .generator(Box::new(generator))
        .resource_service(ResourceService::builder().store(Arc::new(store) as Arc<dyn ResourceStore>).build())
        .build()
}

fn ok_verifier() -> StubVerifier {
    StubVerifier(Box::new(|| Ok(client_claims())))
}

fn err_verifier() -> StubVerifier {
    StubVerifier(Box::new(|| Err(JwtVerificationError::VerificationFailed("bad token".into()))))
}

fn ok_generator() -> StubGenerator {
    StubGenerator(Box::new(|_| Ok("generated.jwt.token".to_string())))
}

fn err_generator() -> StubGenerator {
    StubGenerator(Box::new(|_| Err(JwtGenerationError::GenerationError("vault error".into()))))
}

fn mapping_store(m: ResourceMapping) -> StubStore {
    StubStore(Box::new(move || Ok(Some(m.clone()))))
}

fn empty_store() -> StubStore {
    StubStore(Box::new(|| Ok(None)))
}

fn err_store() -> StubStore {
    StubStore(Box::new(|| Err(ResourceError::DatabaseError("connection failed".into()))))
}

fn client_claims() -> TokenClaims {
    TokenClaims::builder()
        .sub("system:serviceaccount:default:test-sa")
        .iss("https://kubernetes.default.svc")
        .aud(CLIENT_AUDIENCE)
        .exp(9_999_999_999i64)
        .build()
}

fn mapping(scopes: &[&str]) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier("system:serviceaccount:default:test-sa".to_string())
        .participant_context(PARTICIPANT_CONTEXT.to_string())
        .scopes(scopes.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
        .build()
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

struct StubStore(Box<dyn Fn() -> Result<Option<ResourceMapping>, ResourceError> + Send + Sync>);

#[async_trait]
impl ResourceStore for StubStore {
    async fn resolve_mapping(&self, _: &str, _: &str) -> Result<Option<ResourceMapping>, ResourceError> {
        (self.0)()
    }
    async fn save_mapping(&self, _: ResourceMapping) -> Result<(), ResourceError> { unimplemented!() }
    async fn update_mapping(&self, _: ResourceMapping) -> Result<(), ResourceError> { unimplemented!() }
    async fn remove_mapping(&self, _: &str, _: &str) -> Result<(), ResourceError> { unimplemented!() }
    async fn remove_mappings_for(&self, _: &str) -> Result<(), ResourceError> { unimplemented!() }
}
