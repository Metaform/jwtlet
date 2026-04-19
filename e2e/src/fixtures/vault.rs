//  Copyright (c) 2026 Metaform Systems, Inc
//  SPDX-License-Identifier: Apache-2.0

//! Vault deployment fixture — port-forward to Vault for direct API access.

use anyhow::{Context, Result};
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, VaultAuthConfig};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

static VAULT: OnceCell<Arc<VaultFixture>> = OnceCell::const_new();

pub struct VaultFixture {
    pub vault_url: String,
    pub vault_client: Arc<HashicorpVaultClient>,
    _port_forward: Mutex<std::process::Child>,
    _token_file: std::path::PathBuf,
}

pub async fn ensure_vault_client() -> Result<Arc<VaultFixture>> {
    VAULT
        .get_or_try_init(|| async {
            crate::utils::verify_e2e_setup().await?;

            let local_port = get_available_port();
            let child = std::process::Command::new("kubectl")
                .args([
                    "port-forward",
                    "-n",
                    crate::utils::E2E_NAMESPACE,
                    "service/vault",
                    &format!("{local_port}:8200"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("Failed to start kubectl port-forward for vault")?;

            let vault_url = format!("http://localhost:{local_port}");

            let http = reqwest::Client::new();
            let start = std::time::Instant::now();
            loop {
                if start.elapsed().as_secs() > 30 {
                    anyhow::bail!("Vault port-forward on {local_port} did not become ready within 30s");
                }
                if http
                    .get(format!("{vault_url}/v1/sys/health"))
                    .timeout(std::time::Duration::from_secs(1))
                    .send()
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }

            let token_file = std::env::temp_dir().join("jwtlet_e2e_vault_root_token");
            std::fs::write(&token_file, "root").context("Failed to write vault root token file")?;

            let config = HashicorpVaultConfig::builder()
                .vault_url(&vault_url)
                .auth_config(VaultAuthConfig::KubernetesServiceAccount {
                    token_file_path: token_file.clone(),
                })
                .build();

            let mut client = HashicorpVaultClient::new(config).context("Failed to create vault client")?;
            client.initialize().await.context("Failed to initialize vault client")?;

            Ok(Arc::new(VaultFixture {
                vault_url,
                vault_client: Arc::new(client),
                _port_forward: Mutex::new(child),
                _token_file: token_file,
            }))
        })
        .await
        .map(Arc::clone)
}

fn get_available_port() -> u16 {
    use std::net::TcpListener;
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to port 0")
        .local_addr()
        .expect("Failed to get local address")
        .port()
}
