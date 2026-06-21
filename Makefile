# magus-cli developer tasks. The default `test` target is hermetic (no podman,
# no network); `integration` boots real containers and is opt-in.

.PHONY: build test cover integration fmt

build:
	go build ./...

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
