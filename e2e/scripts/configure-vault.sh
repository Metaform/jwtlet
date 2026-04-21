#!/bin/bash
#  Copyright (c) 2026 Metaform Systems, Inc
#  SPDX-License-Identifier: Apache-2.0

set -euo pipefail

E2E_NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"
VAULT_POD=$(kubectl get pods -n "$E2E_NAMESPACE" -l app=vault -o jsonpath='{.items[0].metadata.name}')

echo "Configuring Vault in pod $VAULT_POD..."

VAULT_ENV="VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root"

# Run a vault command in the pod (no stdin)
vexec() {
  kubectl exec "$VAULT_POD" -n "$E2E_NAMESPACE" -- env $VAULT_ENV vault "$@"
}

# Run a vault command in the pod with stdin piped in (-i required for heredocs)
vexec_stdin() {
  kubectl exec -i "$VAULT_POD" -n "$E2E_NAMESPACE" -- env $VAULT_ENV vault "$@"
}

# Enable Kubernetes auth method
vexec auth enable kubernetes 2>/dev/null || true

# Configure Kubernetes auth using Vault's own auto-rotating projected SA token.
# Omitting token_reviewer_jwt so Vault uses its mounted projected SA token
# (disable_local_ca_jwt=false), which Kubernetes auto-rotates — avoids the
# stale-token 403 that occurs when a captured token expires.
kubectl exec "$VAULT_POD" -n "$E2E_NAMESPACE" -- sh -c "
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
export SA_CA_CRT=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)

vault write auth/kubernetes/config \
  kubernetes_host='https://kubernetes.default.svc' \
  kubernetes_ca_cert=\"\${SA_CA_CRT}\" \
  disable_local_ca_jwt=false
"

# Policy: allow jwtlet to read key metadata and sign with its transit key
vexec_stdin policy write jwtlet-policy - <<'EOF'
path "transit/keys/signing-jwtlet_pc" {
  capabilities = ["read"]
}
path "transit/sign/signing-jwtlet_pc" {
  capabilities = ["update"]
}
path "sys/health" {
  capabilities = ["read"]
}
EOF

# Kubernetes auth role for jwtlet's service account
vexec write auth/kubernetes/role/jwtlet-role \
  bound_service_account_names=jwtlet-sa \
  bound_service_account_namespaces="$E2E_NAMESPACE" \
  policies=jwtlet-policy \
  ttl=1h

# Enable transit secrets engine
vexec secrets enable transit 2>/dev/null || true

# Create Ed25519 signing key used by jwtlet (key name = "{prefix}-{participant_context_claim}")
# With defaults: prefix="signing", claim="jwtlet_pc" -> key="signing-jwtlet_pc"
vexec write -f transit/keys/signing-jwtlet_pc type=ed25519 2>/dev/null || true

echo "Vault configuration complete"
