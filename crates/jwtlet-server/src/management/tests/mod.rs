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

use crate::management::management_routes;
use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::{Router, body::Body};
use jwtlet_core::resource::mem::MemoryResourceStore;
use jwtlet_core::resource::ResourceService;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

fn make_router() -> Router {
    let service = ResourceService::builder()
        .store(Arc::new(MemoryResourceStore::new()))
        .build();
    management_routes().with_state(Arc::new(service))
}

fn scope_mapping_json(scope: &str) -> Value {
    json!({ "scope": scope, "claims": {} })
}

fn scope_mapping_with_claims_json(scope: &str, claims: Value) -> Value {
    json!({ "scope": scope, "claims": claims })
}

async fn post_scope(router: &Router, body: Value) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/scopes")
                .header(header::CONTENT_TYPE, "application/json")
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
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

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

    let response = put_scope(&router, "read", scope_mapping_with_claims_json("read", json!({"role": "admin"}))).await;
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
