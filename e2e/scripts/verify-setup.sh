#!/bin/bash
#  Copyright (c) 2026 Metaform Systems, Inc
#  SPDX-License-Identifier: Apache-2.0

set -euo pipefail

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
E2E_NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"

ERRORS=0
ok()   { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; ERRORS=$((ERRORS + 1)); }

echo "Verifying E2E setup (cluster: $KIND_CLUSTER_NAME, namespace: $E2E_NAMESPACE)"
echo ""

kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$" \
  && ok "Kind cluster exists" || fail "Kind cluster not found"

kubectl cluster-info &>/dev/null \
  && ok "kubectl configured" || fail "kubectl not configured"

kubectl get namespace "$E2E_NAMESPACE" &>/dev/null \
  && ok "Namespace exists" || fail "Namespace not found"

for sa in jwtlet-sa test-app-sa vault; do
  kubectl get serviceaccount "$sa" -n "$E2E_NAMESPACE" &>/dev/null \
    && ok "ServiceAccount $sa exists" || fail "ServiceAccount $sa not found"
done

for cm in vault-agent-config-jwtlet jwtlet-config; do
  kubectl get configmap "$cm" -n "$E2E_NAMESPACE" &>/dev/null \
    && ok "ConfigMap $cm exists" || fail "ConfigMap $cm not found"
done

for dep in vault; do
  READY=$(kubectl get deployment "$dep" -n "$E2E_NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
  [ "${READY:-0}" -ge 1 ] \
    && ok "Deployment $dep ready" || fail "Deployment $dep not ready"
done

if [ $ERRORS -eq 0 ]; then
  VAULT_POD=$(kubectl get pods -n "$E2E_NAMESPACE" -l app=vault -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  if [ -n "$VAULT_POD" ]; then
    kubectl exec "$VAULT_POD" -n "$E2E_NAMESPACE" -- vault auth list 2>/dev/null | grep -q kubernetes \
      && ok "Vault Kubernetes auth enabled" || fail "Vault Kubernetes auth not enabled"
    kubectl exec "$VAULT_POD" -n "$E2E_NAMESPACE" -- vault secrets list 2>/dev/null | grep -q transit \
      && ok "Vault transit engine enabled" || fail "Vault transit engine not enabled"
  fi
fi

echo ""
if [ $ERRORS -eq 0 ]; then
  echo "All checks passed. Run: make e2e-test"
else
  echo "$ERRORS check(s) failed. Run: make e2e-setup"
  exit 1
fi
