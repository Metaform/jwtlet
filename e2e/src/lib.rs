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

//! End-to-End tests for jwtlet — Kubernetes + Vault integration.
//!
//! Tests require a Kind cluster with Vault already deployed. See e2e/scripts/setup.sh.
//!
//! Run with:
//! ```sh
//! cargo test --package jwtlet-e2e-tests --features e2e -- --test-threads=1
//! ```

pub mod utils;

#[cfg(all(test, feature = "e2e"))]
pub mod fixtures;

#[cfg(all(test, feature = "e2e"))]
mod tests;
