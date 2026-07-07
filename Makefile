# magus-cli developer tasks. The default `test` target is hermetic (no podman,
# no network); `integration` boots real containers and is opt-in.

.PHONY: build test cover integration fmt

# Stamp version/commit into the binary so a host-deployed `magus version`
# self-identifies. Falls back to dev/none outside a git checkout.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

build:
	go build -ldflags "$(LDFLAGS)" ./...

# Hermetic unit suite — what CI gates on.
test:
	go test ./...

# Coverage for the hermetic suite. The project floor is 70% per package that
# has tests; see docs/implementation-plan.md.
cover:
	go test -cover ./...

# Real-environment apply/diff/status against the bootc conformance target
# (registry.wabash.place/chuck/core-base by default; override with
# MAGUS_IT_IMAGE). Requires podman with a systemd-capable machine. Each test
# boots a fresh privileged container, so this is slow — generous timeout.
integration:
	go test -tags integration -v -timeout 1200s ./internal/integration/

fmt:
	gofmt -w .
