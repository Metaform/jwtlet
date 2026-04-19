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
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{MethodRouter, post, put},
};
use jwtlet_core::resource::{ResourceError, ResourceMapping, ResourceService, ScopeMapping};
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub fn management_routes() -> Router<Arc<ResourceService>> {
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
        .route("/scopes/{scope}", put(update_scope_mapping).delete(delete_scope_mapping))
}

async fn create_mapping(State(service): State<Arc<ResourceService>>, Json(mapping): Json<ResourceMapping>) -> Response {
    match service.save(mapping).await {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => resource_error_response(e),
    }
}

async fn update_mapping(
    State(service): State<Arc<ResourceService>>,
    Path((_client_id, _context)): Path<(String, String)>,
    Json(mapping): Json<ResourceMapping>,
) -> Response {
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

async fn delete_scope_mapping(
    State(service): State<Arc<ResourceService>>,
    Path(scope): Path<String>,
) -> Response {
    match service.delete_scope_mapping(&scope).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => resource_error_response(e),
    }
}

fn resource_error_response(err: ResourceError) -> Response {
    match err {
        ResourceError::NotFound(_) => StatusCode::NOT_FOUND.into_response(),
        ResourceError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
    }
}
