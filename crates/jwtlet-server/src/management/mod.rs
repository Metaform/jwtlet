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

use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodRouter, post, put},
};
use dsdk_facet_core::jwt::{JwtVerificationError, JwtVerifier};
use jwtlet_core::resource::{ResourceError, ResourceMapping, ResourceService, ScopeMapping};
use jwtlet_core::saccount::{AuthError, ServiceAccountAuthorizer};
use std::collections::HashSet;
use std::sync::Arc;

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct ManagementState {
    pub resource_service: Arc<ResourceService>,
    pub authorizer: Arc<dyn ServiceAccountAuthorizer>,
    pub verifier: Arc<dyn JwtVerifier>,
    pub client_audience: String,
}

pub fn management_routes(state: ManagementState) -> Router {
    Router::new()
        .route("/mappings", post(create_mapping))
        .route(
            "/mappings/{client_id}/{context}",
            put(update_mapping).delete(delete_mapping),
        )
        .route(
            "/mappings/{client_id}",
            MethodRouter::new().delete(delete_client_mappings),
        )
        .route("/scopes", post(create_scope_mapping))
        .route(
            "/scopes/{scope}",
            put(update_scope_mapping).delete(delete_scope_mapping),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state.resource_service)
}

async fn authorize(State(state): State<ManagementState>, request: Request, next: Next) -> Response {
    let token = match extract_bearer_token(request.headers()) {
        Some(t) => t.to_owned(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let claims = match state.verifier.verify_token(&state.client_audience, &token).await {
        Ok(c) => c,
        Err(JwtVerificationError::VerificationFailed(_) | JwtVerificationError::InvalidSignature) => {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let required: HashSet<&str> = HashSet::from(["management:write"]);
    match state.authorizer.authorize(&claims.sub, &required).await {
        Ok(true) => next.run(request).await,
        Ok(false) => StatusCode::FORBIDDEN.into_response(),
        Err(AuthError::GeneralError(_)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let lower = v.to_ascii_lowercase();
            lower.strip_prefix("bearer ").map(|_| &v["bearer ".len()..])
        })
}

async fn create_mapping(State(service): State<Arc<ResourceService>>, Json(mapping): Json<ResourceMapping>) -> Response {
    match service.save(mapping).await {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => resource_error_response(e),
    }
}

async fn update_mapping(
    State(service): State<Arc<ResourceService>>,
    Path((client_id, context)): Path<(String, String)>,
    Json(mapping): Json<ResourceMapping>,
) -> Response {
    if client_id != mapping.client_identifier || context != mapping.participant_context {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match service.update(mapping).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => resource_error_response(e),
    }
}

async fn delete_mapping(
    State(service): State<Arc<ResourceService>>,
    Path((client_id, context)): Path<(String, String)>,
) -> Response {
    match service.remove(&client_id, &context).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => resource_error_response(e),
    }
}

async fn delete_client_mappings(
    State(service): State<Arc<ResourceService>>,
    Path(client_id): Path<String>,
) -> Response {
    match service.remove_for(&client_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => resource_error_response(e),
    }
}

async fn create_scope_mapping(
    State(service): State<Arc<ResourceService>>,
    Json(mapping): Json<ScopeMapping>,
) -> Response {
    match service.save_scope_mapping(mapping).await {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => resource_error_response(e),
    }
}

async fn update_scope_mapping(
    State(service): State<Arc<ResourceService>>,
    Path(_scope): Path<String>,
    Json(mapping): Json<ScopeMapping>,
) -> Response {
    match service.update_scope_mapping(mapping).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => resource_error_response(e),
    }
}

async fn delete_scope_mapping(State(service): State<Arc<ResourceService>>, Path(scope): Path<String>) -> Response {
    match service.delete_scope_mapping(&scope).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => resource_error_response(e),
    }
}

fn resource_error_response(err: ResourceError) -> Response {
    match err {
        ResourceError::NotFound(_) => StatusCode::NOT_FOUND.into_response(),
        ResourceError::Conflict(_) => StatusCode::CONFLICT.into_response(),
        ResourceError::ReservedClaim(key) => {
            (StatusCode::BAD_REQUEST, format!("Claim key '{key}' is reserved and cannot be set via scope mapping"))
                .into_response()
        }
        ResourceError::DatabaseError(msg) => {
            tracing::error!("Storage error: {msg}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        ResourceError::ClaimConflict(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
