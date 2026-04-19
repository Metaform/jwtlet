//  Copyright (c) 2026 Metaform Systems, Inc
//  SPDX-License-Identifier: Apache-2.0

//! Jwtlet-specific kubectl utilities not present in dsdk-facet-e2e-tests.

use std::process::Command;

/// Create a bounded ServiceAccount token with the given audience via the TokenRequest API.
pub fn create_service_account_token(sa: &str, namespace: &str, audience: &str) -> anyhow::Result<String> {
    let output = Command::new("kubectl")
        .args([
            "create",
            "token",
            sa,
            "-n",
            namespace,
            &format!("--audience={audience}"),
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("Failed to create token: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
