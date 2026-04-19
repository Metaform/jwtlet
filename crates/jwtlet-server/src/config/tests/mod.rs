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

use crate::config::{
    DEFAULT_BIND_ADDRESS, DEFAULT_MANAGEMENT_PORT, DEFAULT_PARTICIPANT_CONTEXT_CLAIM,
    DEFAULT_SA_TOKEN_FILE, DEFAULT_TOKEN_EXCHANGE_PORT, DEFAULT_TOKEN_TTL_SECS, JwtletConfig,
    K8sConfig, StorageBackend, TokenConfig, ValidationError, VaultConfig,
};

fn valid_config() -> JwtletConfig {
    JwtletConfig {
        token_exchange_port: 8080,
        management_port: 8081,
        bind: DEFAULT_BIND_ADDRESS,
        storage_backend: StorageBackend::Memory,
        k8s: K8sConfig {
            api_server_url: Some("https://kubernetes.default.svc".to_string()),
            cluster_issuer: Some("https://kubernetes.default.svc.cluster.local".to_string()),
            token_file: DEFAULT_SA_TOKEN_FILE.to_string(),
        },
        token: TokenConfig {
            client_audience: Some("https://kubernetes.default.svc.cluster.local".to_string()),
            audience: Some("https://my-service.example.com".to_string()),
            participant_context_claim: DEFAULT_PARTICIPANT_CONTEXT_CLAIM.to_string(),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
        },
        vault: VaultConfig {
            url: Some("https://vault.example.com:8200".to_string()),
            token: Some("root".to_string()),
            token_file: None,
        },
    }
}

fn assert_error_contains(cfg: &JwtletConfig, fragment: &str) {
    let err = cfg.validate().expect_err("expected validation to fail");
    assert!(
        err.messages().iter().any(|m| m.contains(fragment)),
        "expected an error containing {fragment:?}, got: {:?}",
        err.messages()
    );
}

#[test]
fn default_config_has_expected_values() {
    let cfg = JwtletConfig::default();
    assert_eq!(cfg.token_exchange_port, DEFAULT_TOKEN_EXCHANGE_PORT);
    assert_eq!(cfg.management_port, DEFAULT_MANAGEMENT_PORT);
    assert_eq!(cfg.bind, DEFAULT_BIND_ADDRESS);
    assert_eq!(cfg.k8s.token_file, DEFAULT_SA_TOKEN_FILE);
    assert_eq!(cfg.token.participant_context_claim, DEFAULT_PARTICIPANT_CONTEXT_CLAIM);
    assert_eq!(cfg.token.token_ttl_secs, DEFAULT_TOKEN_TTL_SECS);
    assert!(cfg.vault.url.is_none());
    assert!(cfg.vault.token.is_none());
    assert!(cfg.vault.token_file.is_none());
}

#[test]
fn valid_config_passes_validation() {
    assert!(valid_config().validate().is_ok());
}

#[test]
fn vault_token_file_accepted_instead_of_literal_token() {
    let mut cfg = valid_config();
    cfg.vault.token = None;
    cfg.vault.token_file = Some("/vault/secrets/.vault-token".to_string());
    assert!(cfg.validate().is_ok());
}

#[test]
fn validate_fails_when_vault_url_missing() {
    let mut cfg = valid_config();
    cfg.vault.url = None;
    assert_error_contains(&cfg, "vault.url is required");
}

#[test]
fn validate_fails_when_vault_url_invalid() {
    let mut cfg = valid_config();
    cfg.vault.url = Some("not-a-url".to_string());
    assert_error_contains(&cfg, "vault.url is not a valid URL");
}

#[test]
fn validate_fails_when_vault_token_and_token_file_both_missing() {
    let mut cfg = valid_config();
    cfg.vault.token = None;
    cfg.vault.token_file = None;
    assert_error_contains(&cfg, "vault.token or vault.token_file is required");
}

#[test]
fn validate_fails_when_k8s_api_server_url_missing() {
    let mut cfg = valid_config();
    cfg.k8s.api_server_url = None;
    assert_error_contains(&cfg, "k8s.api_server_url is required");
}

#[test]
fn validate_fails_when_k8s_api_server_url_invalid() {
    let mut cfg = valid_config();
    cfg.k8s.api_server_url = Some("not-a-url".to_string());
    assert_error_contains(&cfg, "k8s.api_server_url is not a valid URL");
}

#[test]
fn validate_fails_when_k8s_cluster_issuer_missing() {
    let mut cfg = valid_config();
    cfg.k8s.cluster_issuer = None;
    assert_error_contains(&cfg, "k8s.cluster_issuer is required");
}

#[test]
fn validate_fails_when_k8s_token_file_empty() {
    let mut cfg = valid_config();
    cfg.k8s.token_file = String::new();
    assert_error_contains(&cfg, "k8s.token_file cannot be empty");
}

#[test]
fn validate_fails_when_client_audience_missing() {
    let mut cfg = valid_config();
    cfg.token.client_audience = None;
    assert_error_contains(&cfg, "token.client_audience is required");
}

#[test]
fn validate_fails_when_audience_missing() {
    let mut cfg = valid_config();
    cfg.token.audience = None;
    assert_error_contains(&cfg, "token.audience is required");
}

#[test]
fn validate_fails_when_participant_context_claim_empty() {
    let mut cfg = valid_config();
    cfg.token.participant_context_claim = String::new();
    assert_error_contains(&cfg, "token.participant_context_claim cannot be empty");
}

#[test]
fn validate_fails_when_token_ttl_zero() {
    let mut cfg = valid_config();
    cfg.token.token_ttl_secs = 0;
    assert_error_contains(&cfg, "token.token_ttl_secs must be positive");
}

#[test]
fn validate_fails_when_token_ttl_negative() {
    let mut cfg = valid_config();
    cfg.token.token_ttl_secs = -1;
    assert_error_contains(&cfg, "token.token_ttl_secs must be positive");
}

#[test]
fn validate_fails_when_postgres_url_empty() {
    let mut cfg = valid_config();
    cfg.storage_backend = StorageBackend::Postgres { url: String::new() };
    assert_error_contains(&cfg, "storage_backend.url is required for Postgres backend");
}

#[test]
fn validate_accepts_postgres_with_url() {
    let mut cfg = valid_config();
    cfg.storage_backend = StorageBackend::Postgres {
        url: "postgres://localhost/jwtlet".to_string(),
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn validate_fails_when_token_exchange_port_is_zero() {
    let mut cfg = valid_config();
    cfg.token_exchange_port = 0;
    assert_error_contains(&cfg, "token_exchange_port cannot be 0");
}

#[test]
fn validate_fails_when_management_port_is_zero() {
    let mut cfg = valid_config();
    cfg.management_port = 0;
    assert_error_contains(&cfg, "management_port cannot be 0");
}

#[test]
fn validate_fails_when_ports_are_identical() {
    let mut cfg = valid_config();
    cfg.management_port = cfg.token_exchange_port;
    assert_error_contains(&cfg, "token_exchange_port and management_port cannot be the same");
}

#[test]
fn validate_collects_all_errors_before_returning() {
    // A config missing vault URL, k8s fields, and token fields should report every error.
    let cfg = JwtletConfig::default();
    let err = cfg.validate().expect_err("expected validation to fail");
    assert!(err.error_count() > 1, "expected multiple errors, got {}", err.error_count());
    let msgs = err.messages();
    assert!(msgs.iter().any(|m| m.contains("vault.url")));
    assert!(msgs.iter().any(|m| m.contains("k8s.api_server_url")));
    assert!(msgs.iter().any(|m| m.contains("token.client_audience")));
}

#[test]
fn validation_error_single_has_count_one() {
    let e = ValidationError::single("oops");
    assert_eq!(e.error_count(), 1);
    assert_eq!(e.messages(), vec!["oops"]);
}

#[test]
fn validation_error_multiple_reports_all_messages() {
    let e = ValidationError::Multiple(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    assert_eq!(e.error_count(), 3);
    assert_eq!(e.messages(), vec!["a", "b", "c"]);
}

#[test]
fn validation_error_display_includes_all_messages() {
    let e = ValidationError::Multiple(vec!["first error".to_string(), "second error".to_string()]);
    let display = e.to_string();
    assert!(display.contains("first error"));
    assert!(display.contains("second error"));
    assert!(display.contains('2'.to_string().as_str()));
}
