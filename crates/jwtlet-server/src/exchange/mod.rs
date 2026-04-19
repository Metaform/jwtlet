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

use axum::{
    Json,
    extract::{Form, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use jwtlet_core::token::{ExchangeError, TokenExchangeService};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ISSUED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// RFC 8693 token exchange request (form-encoded).
#[derive(Deserialize)]
pub struct TokenExchangeForm {
    grant_type: String,
    subject_token: String,
    /// Identifies the participant context the caller is requesting a token for.
    resource: String,
    #[serde(default)]
    scope: Option<String>,
}

/// RFC 8693 token exchange response.
#[derive(Serialize)]
pub struct TokenExchangeResponse {
    access_token: String,
    issued_token_type: &'static str,
    token_type: &'static str,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Serialize)]
struct OAuthErrorResponse {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

pub async fn token_exchange(
    State(service): State<Arc<TokenExchangeService>>,
    Form(form): Form<TokenExchangeForm>,
) -> Response {
    if form.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", None);
    }

    let scopes: Vec<String> = form
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_string)
        .collect();

    match service
        .exchange_token(&form.resource, scopes, &form.subject_token)
        .await
    {
        Ok(token) => (
            StatusCode::OK,
            Json(TokenExchangeResponse {
                access_token: token,
                issued_token_type: ISSUED_TOKEN_TYPE,
                token_type: "Bearer",
                expires_in: service.token_ttl_secs(),
                scope: form.scope,
            }),
        )
            .into_response(),
        Err(e) => exchange_error_response(e),
    }
}

fn exchange_error_response(err: ExchangeError) -> Response {
    match err {
        ExchangeError::TokenVerification(_) => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", Some(err.to_string()))
        }
        ExchangeError::Unauthorized => oauth_error(StatusCode::FORBIDDEN, "unauthorized_client", None),
        ExchangeError::ServiceError(_) | ExchangeError::Generation(_) => {
            tracing::error!("Token exchange internal error: {err}");
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", None)
        }
    }
}

fn oauth_error(status: StatusCode, error: &'static str, description: Option<String>) -> Response {
    (
        status,
        Json(OAuthErrorResponse {
            error,
            error_description: description,
        }),
    )
        .into_response()
}
