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

use crate::management::{ManagementState, management_routes};
use async_trait::async_trait;
use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::{Router, body::Body, body::to_bytes};
use dsdk_facet_core::jwt::{JwtVerificationError, JwtVerifier, TokenClaims};
use jwtlet_core::resource::ResourceService;
use jwtlet_core::resource::mem::MemoryResourceStore;
use jwtlet_core::saccount::{AuthError, ServiceAccountAuthorizer};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;
use tower::ServiceExt;

const MGMT_CLIENT_ID: &str = "system:serviceaccount:test:mgmt-sa";
const MGMT_TOKEN: &str = "valid-mgmt-token";

// ============================================================================
// Stubs
// ============================================================================

struct StubVerifier(Box<dyn Fn() -> Result<TokenClaims, JwtVerificationError> + Send + Sync>);

#[async_trait]
impl JwtVerifier for StubVerifier {
    async fn verify_token(&self, _: &str, _: &str) -> Result<TokenClaims, JwtVerificationError> {
        (self.0)()
    }
}

struct StubAuthorizer(Box<dyn Fn() -> Result<bool, AuthError> + Send + Sync>);

#[async_trait]
impl ServiceAccountAuthorizer for StubAuthorizer {
    async fn authorize(&self, _: &str, _: &HashSet<&str>) -> Result<bool, AuthError> {
        (self.0)()
    }
}

fn ok_verifier() -> StubVerifier {
    StubVerifier(Box::new(|| {
        Ok(TokenClaims::builder()
            .sub(MGMT_CLIENT_ID)
            .iss("https://kubernetes.default.svc.cluster.local")
            .aud("test-audience")
            .exp(9999999999i64)
            .build())
    }))
}

fn err_verifier() -> StubVerifier {
    StubVerifier(Box::new(|| {
        Err(JwtVerificationError::VerificationFailed("bad token".into()))
    }))
}

fn authorized() -> StubAuthorizer {
    StubAuthorizer(Box::new(|| Ok(true)))
}

fn unauthorized() -> StubAuthorizer {
    StubAuthorizer(Box::new(|| Ok(false)))
}

// ============================================================================
// Router helpers
// ============================================================================

fn make_router() -> Router {
    make_router_with_auth(ok_verifier(), authorized())
}

fn make_router_with_auth(
    verifier: impl JwtVerifier + 'static,
    authorizer: impl ServiceAccountAuthorizer + 'static,
) -> Router {
    let resource_service = Arc::new(
        ResourceService::builder()
            .store(Arc::new(MemoryResourceStore::new()))
            .build(),
    );
    let state = ManagementState {
        resource_service,
        authorizer: Arc::new(authorizer),
        verifier: Arc::new(verifier),
        client_audience: "test-audience".to_string(),
    };
    management_routes(state)
}

fn mapping_json(client_id: &str, context: &str) -> Value {
    json!({
        "clientIdentifier": client_id,
        "participantContext": context,
        "scopes": ["read"]
    })
}

fn scope_mapping_json(scope: &str) -> Value {
    json!({ "scope": scope, "claims": {} })
}

fn scope_mapping_with_claims_json(scope: &str, claims: Value) -> Value {
    json!({ "scope": scope, "claims": claims })
}

async fn post_mapping(router: &Router, body: Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mappings")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {MGMT_TOKEN}"))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn put_mapping(router: &Router, client_id: &str, context: &str, body: Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/mappings/{client_id}/{context}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {MGMT_TOKEN}"))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post_scope(router: &Router, body: Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scopes")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {MGMT_TOKEN}"))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn put_scope(router: &Router, scope: &str, body: Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/scopes/{scope}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {MGMT_TOKEN}"))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn delete_scope(router: &Router, scope: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/scopes/{scope}"))
                .header(header::AUTHORIZATION, format!("Bearer {MGMT_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

// ============================================================================
// Authorization tests
// ============================================================================

#[tokio::test]
async fn returns_401_when_no_authorization_header() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scopes")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&scope_mapping_json("read")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn returns_401_when_bearer_token_is_invalid() {
    let router = make_router_with_auth(err_verifier(), authorized());
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scopes")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer bad-token")
                .body(Body::from(serde_json::to_string(&scope_mapping_json("read")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn returns_403_when_caller_lacks_management_write_role() {
    let router = make_router_with_auth(ok_verifier(), unauthorized());
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scopes")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {MGMT_TOKEN}"))
                .body(Body::from(serde_json::to_string(&scope_mapping_json("read")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ============================================================================
// Existing scope mapping tests (now with auth header)
// ============================================================================

#[tokio::test]
async fn create_scope_mapping_returns_201() {
    let router = make_router();
    let response = post_scope(&router, scope_mapping_json("read")).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn update_scope_mapping_returns_204_after_create() {
    let router = make_router();
    post_scope(&router, scope_mapping_json("read")).await;

    let response = put_scope(
        &router,
        "read",
        scope_mapping_with_claims_json("read", json!({"role": "admin"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_scope_mapping_returns_404_when_not_found() {
    let router = make_router();
    let response = put_scope(&router, "ghost", scope_mapping_json("ghost")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_scope_mapping_returns_204() {
    let router = make_router();
    post_scope(&router, scope_mapping_json("write")).await;

    let response = delete_scope(&router, "write").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_scope_mapping_returns_204_for_nonexistent_scope() {
    let router = make_router();
    let response = delete_scope(&router, "nonexistent").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ============================================================================
// H5 — duplicate mapping returns 409
// ============================================================================

#[tokio::test]
async fn create_mapping_returns_201_on_first_post() {
    let router = make_router();
    let resp = post_mapping(&router, mapping_json("client1", "ctx1")).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn create_mapping_returns_409_on_duplicate() {
    let router = make_router();
    post_mapping(&router, mapping_json("client1", "ctx1")).await;
    let resp = post_mapping(&router, mapping_json("client1", "ctx1")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_mapping_allows_same_client_in_different_contexts() {
    let router = make_router();
    let r1 = post_mapping(&router, mapping_json("client1", "ctx1")).await;
    let r2 = post_mapping(&router, mapping_json("client1", "ctx2")).await;
    assert_eq!(r1.status(), StatusCode::CREATED);
    assert_eq!(r2.status(), StatusCode::CREATED);
}

// ============================================================================
// H4 — update_mapping validates path params match body
// ============================================================================

#[tokio::test]
async fn update_mapping_returns_204_when_path_and_body_match() {
    let router = make_router();
    post_mapping(&router, mapping_json("client1", "ctx1")).await;
    let resp = put_mapping(&router, "client1", "ctx1", mapping_json("client1", "ctx1")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn update_mapping_returns_400_when_client_id_mismatches() {
    let router = make_router();
    post_mapping(&router, mapping_json("client1", "ctx1")).await;
    let body = mapping_json("OTHER_CLIENT", "ctx1");
    let resp = put_mapping(&router, "client1", "ctx1", body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_mapping_returns_400_when_context_mismatches() {
    let router = make_router();
    post_mapping(&router, mapping_json("client1", "ctx1")).await;
    let body = mapping_json("client1", "OTHER_CTX");
    let resp = put_mapping(&router, "client1", "ctx1", body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ============================================================================
// M3 — Bearer prefix is case-insensitive
// ============================================================================

#[tokio::test]
async fn returns_200_with_lowercase_bearer_scheme() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scopes")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("bearer {MGMT_TOKEN}"))
                .body(Body::from(serde_json::to_string(&scope_mapping_json("read")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn returns_200_with_uppercase_bearer_scheme() {
    let router = make_router();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scopes")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("BEARER {MGMT_TOKEN}"))
                .body(Body::from(serde_json::to_string(&scope_mapping_json("read")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn create_scope_with_reserved_claim_returns_400() {
    let router = make_router();
    let body = json!({ "scope": "read", "claims": { "sub": "injected" } });
    let response = post_scope(&router, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_scope_with_reserved_claim_returns_400() {
    let router = make_router();
    post_scope(&router, scope_mapping_json("read")).await;

    let body = json!({ "scope": "read", "claims": { "iss": "evil.example.com" } });
    let response = put_scope(&router, "read", body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_scope_with_non_reserved_claims_returns_201() {
    let router = make_router();
    let body = json!({ "scope": "read", "claims": { "role": "reader", "department": "eng" } });
    let response = post_scope(&router, body).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

// ============================================================================
// H3 — DatabaseError body is not exposed
// ============================================================================

#[tokio::test]
async fn database_error_does_not_expose_internal_message_in_response_body() {
    use async_trait::async_trait;
    use jwtlet_core::resource::{ResourceError, ResourceMapping, ResourceStore, ScopeMapping};

    struct ErrStore;

    #[async_trait]
    impl ResourceStore for ErrStore {
        async fn resolve_mapping(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<jwtlet_core::resource::MappingPair>, ResourceError> {
            Err(ResourceError::DatabaseError("secret internal error".into()))
        }
        async fn save_mapping(&self, _: ResourceMapping) -> Result<(), ResourceError> {
            Err(ResourceError::DatabaseError("secret internal error".into()))
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

    let resource_service = Arc::new(
        ResourceService::builder()
            .store(Arc::new(ErrStore) as Arc<dyn jwtlet_core::resource::ResourceStore>)
            .build(),
    );
    let state = ManagementState {
        resource_service,
        authorizer: Arc::new(StubAuthorizer(Box::new(|| Ok(true)))),
        verifier: Arc::new(ok_verifier()),
        client_audience: "test-audience".to_string(),
    };
    let router = management_routes(state);

    let resp = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mappings")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {MGMT_TOKEN}"))
                .body(Body::from(serde_json::to_string(&mapping_json("c", "ctx")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        !body.contains("secret internal error"),
        "DB error message must not appear in response body"
    );
}
