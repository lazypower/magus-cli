# magus-cli developer tasks. The default `test` target is hermetic (no podman,
# no network); `integration` boots real containers and is opt-in.

.PHONY: build test cover integration vm-e2e-remote fmt

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

# Real-FCOS e2e (pave -> adopt -> day2 -> reboot) on a remote KVM host, driven
# from here. Needs MAGUS_VM_HOST=<ssh-host> and an open ssh window; the remote
# does all VM work in a disposable container and red carries the VM console back.
# Extra flags via VM_E2E_ARGS (e.g. --no-reboot, --arch aarch64). See
# hack/vm/README.md and docs/adr-0001-test-substrate.md.
vm-e2e-remote:
	@test -n "$(MAGUS_VM_HOST)" || { echo "set MAGUS_VM_HOST=<ssh-host>"; exit 1; }
	MAGUS_VM_HOST="$(MAGUS_VM_HOST)" hack/vm/fcos-remote $(VM_E2E_ARGS)

fmt:
	gofmt -w .
