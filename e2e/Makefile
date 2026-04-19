.PHONY: setup build test test-fast test-verbose all cleanup verify

KIND_CLUSTER_NAME ?= vault-e2e
E2E_NAMESPACE    ?= vault-e2e-test

WORKSPACE_ROOT := $(shell cd .. && pwd)

setup:
	./scripts/setup.sh

build:
	./scripts/build-and-load-jwtlet.sh

test: build
	./scripts/run-tests.sh

test-fast:
	E2E_SKIP_SETUP=true ./scripts/run-tests.sh

test-verbose:
	cd $(WORKSPACE_ROOT) && cargo test --package jwtlet-e2e-tests --features e2e -- --test-threads=1 --nocapture

all: setup test cleanup

cleanup:
	./scripts/cleanup.sh

verify:
	./scripts/verify-setup.sh
