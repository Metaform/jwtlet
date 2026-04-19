#!/bin/bash
#  Copyright (c) 2026 Metaform Systems, Inc
#  SPDX-License-Identifier: Apache-2.0

set -euo pipefail

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"

echo "Cleaning up E2E environment (cluster: $KIND_CLUSTER_NAME)..."

if kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
  kind delete cluster --name "$KIND_CLUSTER_NAME"
  echo "Cluster deleted"
else
  echo "Cluster $KIND_CLUSTER_NAME not found — nothing to clean up"
fi
