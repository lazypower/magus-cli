# Project plan — test substrate & apply graph

**Status:** Proposed
**Date:** 2026-07-12
**Decisions this executes:** `docs/adr-0001-test-substrate.md`, `docs/adr-0002-apply-graph.md`
**Relationship to `docs/implementation-plan.md`:** that plan's Phases 1–5 hardened the v1
contract; this plan is the next arc. Same loop applies (build → hermetic gate → adversarial
review → triage → PR), same coverage floor (70%), same PR-boundary checkpoints.

Two workstreams. **A (substrate)** and **B (graph)** are independent until B3, which wants
A1 landed as its regression net. Work packages are sized S (≤1 day), M (2–3 days),
L (up to a week), and written to be delegable — each has a crisp deliverable and
acceptance criteria, and names the files it touches.

---

## Workstream A — substrate

### A1 — `ignition-apply` handoff fixtures in the tier-0 harness  (M)

The highest-value/lowest-cost item in the plan: makes the Ignition → magus adoption
handoff a tested invariant using only the existing podman harness.

- Add a `butane` render step to the integration harness (vendor the binary into the
  container or render on the host; the Go butane library is already a dependency — a tiny
  `magus internal-render` test helper or direct library call both work).
- New tests in `internal/integration/`: render fixture `.bu` → run
  `/usr/libexec/ignition-apply <cfg>` inside a fresh container → run `magus apply --yes` →
  assert every declared resource rows as `[adopt]`, zero filesystem writes (hash disk
  before/after), second apply exits 0 with all `[skip]`.
- Include a canonicalization-boundary fixture: unit with comments/whitespace noise, so
  Ignition's actual output exercises the equivalence rules (spec "Why this matters for
  adoption").
- Guard: skip with a visible reason when the image's Ignition lacks `ignition-apply`
  (present since 2.14; core-base inherits FCOS's).

**Accept:** `make integration` proves the handoff end-to-end in containers; a
deliberately-broken canonicalization (test-only) fails it.
**Touches:** `internal/integration/`, fixtures dir.

### A2 — VM scripts: fetch + boot + ssh, host-fungible  (M)

- `hack/vm/fcos-fetch`: download + verify (sig/sha from stream metadata) the qemu qcow2
  for a given arch/stream into a cache dir; pin the tested release in a versioned file.
- `hack/vm/fcos-run`: boot a throwaway VM with an Ignition file. Localhost: qemu with
  HVF (darwin/arm64) or KVM (linux/amd64), `-snapshot`,
  `-fw_cfg name=opt/com.coreos/config,file=…`, user-net ssh port-forward. Remote:
  `MAGUS_VM_HOST=<ssh-host>` runs the same qemu invocation over ssh (scp the ign; image
  cached remotely by `fcos-fetch`). Prints ssh coordinates; `--destroy-after` for CI.
- `make vm-e2e`: render fixture butane → boot → wait-ssh → scp magus binary (GOARCH from
  the guest) → run the day-2 cycle (adopt-all → mutate → apply → assert) → optional
  `--reboot` flag: reboot the guest and re-assert declared state (the spec's unit of
  correctness).
- Bring-up may use the Framework desktop as the first `MAGUS_VM_HOST`; nothing may
  reference it by name outside local env files.

**Accept:** `make vm-e2e` passes on a Mac (HVF, aarch64) and against a Linux KVM host via
`MAGUS_VM_HOST`, from the same scripts.
**Touches:** `hack/vm/`, `Makefile`, fixtures.

### A3 — GitHub Actions real-VM workflow  (M; needs A2)

- `.github/workflows/vm-e2e.yml`: ubuntu-latest; enable `/dev/kvm` (documented udev rule);
  restore qcow2 from actions cache keyed on the pinned release; run `make vm-e2e --reboot`
  (x86_64). Nightly + workflow_dispatch + opt-in PR label, mirroring the Gitea
  integration workflow's trigger philosophy so the mirror doesn't gate day-to-day PRs.
- One nightly-only aarch64 TCG smoke job (boot + adopt + exit) — arch coverage without
  gating on emulation speed.

**Accept:** green run on the mirror including the reboot-persistence assertion; failure
uploads the VM console log as an artifact.
**Touches:** `.github/workflows/`.

### A4 — Ephemeral Hetzner conformance harness  (M, optional / cost-gated)

- `hack/vm/fcos-cloud`: hcloud API — create smallest suitable instance from the official
  FCOS hetzner image (x86_64 and aarch64) with the fixture Ignition as user-data → ssh →
  run the same e2e cycle → destroy (destroy in `trap`, always). Budget guard: refuse to
  start if instances tagged `magus-e2e` already exist.
- Wire as manual `make cloud-e2e` + optional weekly Gitea scheduled job (token as secret).

**Accept:** full cycle on a real Ignition-provisioned cloud FCOS instance, both arches,
with verified teardown; cost per run documented in the script header.
**Touches:** `hack/vm/`, `.gitea/workflows/`.

### A5 — Substrate docs  (S; needs A2)

`docs/testing.md`: the tier map (what each tier proves and doesn't), how to run each
locally, `MAGUS_VM_HOST` contract, image pinning/refresh procedure. README gains a short
"Testing" pointer.

---

## Workstream B — apply graph

### B1 — `internal/graph`: DAG core  (M)

- Node/edge types with the three kinds (`order`, `require`, `notify`); Kahn stable
  toposort; Tarjan SCC with full-cycle, edge-provenance error rendering; reverse-edge
  derivation for deletes. No external deps. Property tests: toposort respects every edge;
  determinism across shuffled insertion; every cycle reported exactly once.
- Pure package: no imports from `apply`/`diff` beyond shared types (mind the existing
  `diff↔apply` seam notes in implementation-plan Phase 5).

**Accept:** ≥90% coverage (it's pure logic); fuzz/property tests green.
**Touches:** `internal/graph/` (new).

### B2 — Edge derivation over the plan  (M; needs B1)

- Implement the ADR-0002 autorequire table: directory containment, drop-in→body,
  unit/quadlet-write → daemon-reload barrier → service ops, quadlet `Network=`/`Volume=`
  references, `EnvironmentFile=` notify edges, reversed delete edges. Soft-edge rule
  throughout (both endpoints declared/owned, else no edge).
- INI key extraction reuses the canonicalizer's parsing so there's one opinion about
  unit-file shape.
- Table-driven tests per derivation rule, plus a "reproduces current phase order" test:
  for representative v1 plans, graph order must be a valid interleaving of today's
  phases (1a → 1b → reload → service ops).

**Accept:** derivation-rule tests + phase-equivalence test green; cycle provenance renders
correctly for a crafted cycle.
**Touches:** `internal/graph/`, small read-only hooks in `internal/ir` / `internal/diff`.

### B3 — Execute apply via the graph  (L; needs B2 + A1 as net)

- Replace apply's phase loops with a graph walk; `unitEvents` bookkeeping becomes edge
  traversal state. `require`-failure skips render as `skipped: dependency <path> failed`
  (exit-code semantics unchanged: skip → 2).
- The daemon-reload-once, disable-before-unlink, stop-before-quadlet-removal, and
  TOCTOU-recheck behaviors are preserved as graph structure/node behavior — assert each
  with the existing unit + integration suites.
- Notify edges close the `EnvironmentFile=` gap: env-file-only change restarts an active
  consumer (new integration test in A1's harness proves it against real systemd).

**Accept:** entire existing unit + integration suite green unmodified except where
ordering was asserted incidentally; new propagation tests green; coverage floor holds.
**Touches:** `internal/apply/`, `internal/diff/`.

### B4 — Plan surface: disruption column, `magus graph --dot`  (M; needs B2)

- Plan rows gain the disruption action (`none`/`daemon-reload`/`restart`) with the notify
  provenance in the reason (`notify → restart ollama.service`); footer reports max
  disruption. `plan --json` grows the same fields (additive keys only).
- `magus graph [--dot] <source>`: serialize the derived graph; plain mode lists edges with
  provenance.

**Accept:** golden-file tests for plan output; `--json` additions documented; dot output
renders (checked in a test by parsing, not by graphviz).
**Touches:** `cmd/magus/`, `internal/explain/`.

### B5 — Spec + docs update  (S; needs B3, B4)

`spec-reconciler.md` gains an "Ordering & propagation" section (edge table, disruption
lattice, cycle = input-bad, notify semantics); Apply-mechanics phase text rewritten in
graph terms; README one-liner. Spec changes reviewed in the same PR as nothing — this is
a docs-only PR after the behavior lands, so the spec never leads the code.

---

## Sequencing & delegation

```
A1 ──────────────┐            (independent starters: A1, A2, B1)
A2 ── A3 ── A4   ├── B3 ── B4 ── B5
B1 ── B2 ────────┘
A5 after A2
```

Suggested delegation slices (each hands an agent/contributor a closed scope): A1; A2+A5;
A3; A4; B1; B2; B3 (the one senior-attention item — it rewrites apply's core loop);
B4+B5. Adversarial review (the codex seat) is mandatory on A1 (it defines the handoff
invariant), B2 (edge rules are the new attack surface: a wrong edge is a wrong write
order on a root-privileged tool), and B3.

Decision gates for Chuck, in order: (1) approve both ADRs; (2) after A3 is green — decide
whether A4's cloud spend is wanted now or parked; (3) after B2 — review the derived-edge
rules against a real core-base plan before B3 rewrites apply around them.
