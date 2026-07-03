# AGENTS.md

Working guide for humans and agents contributing to **magus-cli** — the day-2
Butane reconciler. Read `docs/spec-reconciler.md` for the authority model and
contract; `docs/implementation-plan.md` for how v1 was built.

## Layout

- `cmd/magus` — CLI (`validate`/`plan`/`apply`/`status`/`adopt`/`reclaim`); composition root.
- `internal/ir` — Butane → IR, plus pure naming helpers (unit / quadlet generated-service names).
- `internal/policy` — the pre-flight authority gate: `file_roots`, `deny`, reserved state paths, quadlet/unit rules, orphan-on-deny.
- `internal/diff` — joins IR ∪ manifest ∪ disk into a plan; symlink-resolved containment.
- `internal/apply` — executes the plan; drives systemd; observes unit state.
- `internal/manifest` — the ownership ledger (`/var/lib/magus/manifest.json`).
- `internal/status` — the last-apply observation (`/var/lib/magus/status.json`).
- `internal/explain` — `plan --explain` diff rendering.
- `internal/hostfs` / `internal/systemd` — filesystem + systemctl seams (real impls + test fakes).
- `internal/integration` — real-container suite (`//go:build integration`).

## Build & test

- `make test` / `go test ./...` — hermetic unit suite; this is the PR gate.
- `make cover` — coverage. **Floor: every package ≥ 70%** (CI enforces it).
- `make integration` — real-environment suite: runs the `magus` binary inside a
  privileged systemd `core-base` container via podman (~3 min). Needs podman +
  the image; NOT part of the hermetic gate.
  - `TestQuadletRuntime` (a quadlet container actually pulling + running) is
    **skipped unless `MAGUS_IT_RUNTIME=1`** — double-nested podman
    (microVM → core-base → workload) can't run a container in CI; it's a
    real-bootc-host check. Run it on the substrate:
    `MAGUS_IT_RUNTIME=1 go test -tags integration -run TestQuadletRuntime ./internal/integration/`.
- `gofmt` and `go vet ./...` must be clean.

## CI (gitea)

- **`Test`** (golang runner) — gates every PR and push to `main`: gofmt, vet,
  build, compile the integration harness, `go test` with the 70% coverage floor.
- **`Integration`** (buildah runner) — the real-environment suite. Runs
  **nightly** and on **manual dispatch**, and on a PR **only when it carries the
  `integration` label** (below). Not a required check by default.

## The `integration` label

Add the **`integration`** label to a PR to run the real-container integration
suite as a check on it (it re-runs on each new commit while the label stays).
Unlabeled PRs skip it and pay only the fast hermetic gate.

**Apply it when the change touches a "risky seam"** — anywhere real systemd /
filesystem behavior can diverge from the in-memory fakes the unit tests use:

- `internal/apply` mechanics — write/delete ordering, daemon-reload, enable / start / restart.
- `internal/diff` — symlink containment, the diff model, or equivalence/canonicalization rules.
- `internal/policy` authority — `file_roots`, `deny`, symlink resolution, reserved paths, quadlet/unit gating, orphaning.
- `internal/manifest` — ownership or orphan-state transitions.
- `internal/hostfs` (atomic writes, symlink handling) or `internal/systemd` (systemctl interaction).
- quadlet handling, or anything that changes **what magus writes to disk or asks systemd to do**.

**Skip it for** pure refactors with no behavior change, docs, tests-only, CI
config, or changes confined to `cmd` output formatting — the hermetic gate
covers those.

When in doubt on an apply/diff/policy change, label it: a 3-minute real-env
confirmation is cheap insurance against a fakes-only blind spot.

## Conventions

- Preserve the package seams above: pure helpers live in `ir`; `policy` has no
  filesystem access; `diff`/`apply` keep their policy-aware entry points
  (`ComputeWithPolicy`, `ApplyWithPolicy`) separate from the churn-free base ones.
- New safety behavior ships with a test that proves it — unit where possible, and
  an `internal/integration` test when it's a real-systemd/filesystem invariant.
- Deferred (not v1, per the spec's Open Questions): rollback, `passwd.users`,
  `magus relinquish`, empty-directory deletion, precompiled IR.
