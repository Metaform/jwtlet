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

//! End-to-end tests for jwtlet RFC 8693 token exchange.

use crate::fixtures::jwtlet::ensure_jwtlet_deployed;
use serde_json::{Value, json};

const PARTICIPANT_CONTEXT: &str = "test-context";
const SA_NAME: &str = "test-app-sa";
// subject_token audience must match jwtlet's token.client_audience config
const CLIENT_AUDIENCE: &str = "https://kubernetes.default.svc.cluster.local";

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_jwtlet_health() -> anyhow::Result<()> {
    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://127.0.0.1:{}/health", jwtlet.token_exchange_port))
        .send()
        .await?;
    assert!(resp.status().is_success(), "health check failed: {}", resp.status());

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_token_exchange() -> anyhow::Result<()> {
    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();

    let token_url = format!("http://127.0.0.1:{}", jwtlet.token_exchange_port);
    let mgmt_url = format!("http://127.0.0.1:{}", jwtlet.management_port);
    let namespace = crate::utils::E2E_NAMESPACE;
    let client_identifier = format!("system:serviceaccount:{namespace}:{SA_NAME}");

    // Register the SA → participant context mapping
    let mapping = json!({
        "clientIdentifier": client_identifier,
        "participantContext": PARTICIPANT_CONTEXT,
        "scopes": ["read"]
    });
    let resp = client
        .post(format!("{mgmt_url}/api/v1/mappings"))
        .json(&mapping)
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 201, "create mapping failed: {}", resp.status());

    // Get a bounded SA token with the expected audience
    let sa_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;

    // POST /token (RFC 8693 token exchange)
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", sa_token.as_str()),
        ("resource", PARTICIPANT_CONTEXT),
        ("scope", "read"),
    ];
    let resp = client.post(format!("{token_url}/token")).form(&params).send().await?;

    assert!(resp.status().is_success(), "token exchange failed: {}", resp.status());

    let body: Value = resp.json().await?;
    assert!(body["access_token"].is_string(), "missing access_token");
    assert_eq!(body["token_type"].as_str(), Some("Bearer"));
    assert_eq!(
        body["issued_token_type"].as_str(),
        Some("urn:ietf:params:oauth:token-type:jwt")
    );
    assert!(body["expires_in"].is_number(), "missing expires_in");

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_token_exchange_unauthorized() -> anyhow::Result<()> {
    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();
    let token_url = format!("http://127.0.0.1:{}", jwtlet.token_exchange_port);
    let namespace = crate::utils::E2E_NAMESPACE;

    // Get a valid SA token but request a context with no mapping
    let sa_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;

    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", sa_token.as_str()),
        ("resource", "no-such-context"),
        ("scope", "read"),
    ];
    let resp = client.post(format!("{token_url}/token")).form(&params).send().await?;

    // Expect 403 Forbidden for unmapped context
    assert_eq!(resp.status().as_u16(), 403, "expected 403 for unauthorized context");

    Ok(())
}
