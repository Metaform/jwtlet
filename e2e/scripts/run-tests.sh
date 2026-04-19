#!/bin/bash
#  Copyright (c) 2026 Metaform Systems, Inc
#  SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${E2E_DIR}/.." && pwd)"

E2E_SKIP_SETUP="${E2E_SKIP_SETUP:-false}"
E2E_SKIP_CLEANUP="${E2E_SKIP_CLEANUP:-false}"
E2E_NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"

if [ "$E2E_SKIP_SETUP" != "true" ]; then
  echo "Running setup..."
  "${E2E_DIR}/scripts/setup.sh"
fi

cd "$WORKSPACE_ROOT"
echo "Running E2E tests..."

# Detect if cargo-nextest is available
if command -v cargo-nextest &> /dev/null; then
  echo "Using cargo-nextest for test execution..."
  cargo nextest run --package jwtlet-e2e-tests --features e2e --no-capture
  TEST_RESULT=$?
else
  echo "cargo-nextest not found, falling back to cargo test"
  echo "For faster test execution, install nextest:"
  echo "  cargo install cargo-nextest --locked"
  echo ""
  # --test-threads=1: all tests share one process; OnceCell initialized once across them
  cargo test --package jwtlet-e2e-tests --features e2e -- --test-threads=1 --nocapture
  TEST_RESULT=$?
fi

if [ $TEST_RESULT -eq 0 ] && [ "$E2E_SKIP_CLEANUP" != "true" ]; then
  echo "Cleaning up..."
  "${E2E_DIR}/scripts/cleanup.sh"
else
  if [ $TEST_RESULT -ne 0 ]; then
    echo "Tests failed — preserving environment for debugging"
    echo ""
    echo "Pod status:"
    kubectl get pods -n "$E2E_NAMESPACE" || true
    echo ""
    echo "Vault logs:"
    kubectl logs -l app=vault -n "$E2E_NAMESPACE" --tail=50 || true
    echo ""
    echo "Jwtlet logs:"
    kubectl logs -l app=jwtlet -n "$E2E_NAMESPACE" -c jwtlet --tail=50 || true
  fi
fi

exit $TEST_RESULT
