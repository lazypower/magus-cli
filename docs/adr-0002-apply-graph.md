# ADR-0002 — Apply graph: derived edges over the IR, executed in deterministic topological order

**Status:** Proposed
**Date:** 2026-07-12
**Companion to:** `docs/spec-reconciler.md` (Apply mechanics), `internal/apply/apply.go`

## Context

Apply today runs a **fixed phase pipeline**: (1a) service-aware deletes, (1b) all other
mutations in plan order, (2) one `daemon-reload`, (3) per-unit/quadlet state
reconciliation, (4) observe. That is a hardcoded topological order over an *implicit*
dependency graph — the same trick Ignition uses (its stage order disks → raid → luks →
filesystems → mounts-by-depth → users → files-by-depth → hardlinks-last → units is
hardcoded phase ordering over structural references, verified in
[ignition/internal/exec/stages](https://github.com/coreos/ignition/blob/main/internal/exec/stages/files/filesystemEntries.go)).

The pipeline is correct for what v1 shipped, but three real gaps have no home in it:

1. **Change propagation.** A unit restarts only when its *own* body/drop-in changed
   (`unitEvents.hasContentMut`). A managed file consumed via `EnvironmentFile=` can change
   without the consuming service restarting — the system converges on bytes but not on
   behavior, silently.
2. **Cross-resource ordering.** A `.container` quadlet referencing a declared `.network`/
   `.volume` has no first-start ordering guarantee within an apply; a file declared inside
   a declared directory depends on plan-emission order for its parent's mode/ownership to
   be settled first.
3. **Delete ordering.** Deletes should walk dependencies in reverse (stop/remove consumers
   before providers); today they're just phase 1a vs 1b.

Prior art (full survey with citations: research notes, 2026-07-12):

- **Terraform** infers edges from expression references so users rarely declare
  dependencies; its [`internal/dag`](https://github.com/hashicorp/terraform/blob/main/internal/dag/dag.go)
  provides Tarjan-SCC cycle detection, transitive reduction, and a parallel walker whose
  failed vertices poison descendants only. Standalone extraction:
  [sourcegraph/tf-dag](https://github.com/sourcegraph/tf-dag) (MPL-2.0).
- **Puppet's autorequire** is the edge-derivation philosophy: resource *types* declare
  implied references (a file autorequires its parent directory and its owner user/group);
  edges materialize only when both endpoints are in the catalog; explicit edges override
  ([file type docs](https://www.puppet.com/docs/puppet/7/types/file.html)).
- **systemd** separates *ordering* (`Before=`/`After=`) from *requirement*
  (`Wants=`/`Requires=`) — schedule order and failure propagation are different relations.
- **Salt `watch` / Puppet `notify`** add a third relation: change-triggered refresh.
- **OpenShift MCO** — the closest shipped analogue of magus — uses **no general DAG**: a
  fixed pipeline over a deliberately restricted reconcilable subset, plus a **disruption
  action lattice** (`none < reload < restart < reboot`; the plan's answer is the max over
  all diffs), user-tunable per-path/per-unit since 4.17 via
  [NodeDisruptionPolicy](https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/machine_configuration/machine-config-node-disruption_machine-configs-configure).
  MCO also *refuses* day-2 storage mutation outright — independent validation of the
  spec's Rejected-IR contract.

## Decision

Introduce `internal/graph`: a small, dependency-free DAG over **plan rows** (not IR
declarations), with structurally derived edges, three edge kinds, and deterministic serial
execution. The existing phase semantics are preserved as graph structure — this is a
refactor of ordering from *implicit* to *explicit*, not a new execution model.

### Nodes

One node per `diff.ResourceAction` (file/dir/unit-body/drop-in/quadlet action rows),
one node per service operation (enable/disable/start/restart decisions, today's phase 3),
plus two synthetic nodes:

- **`daemon-reload` barrier** — keeps the "exactly once, after all unit/quadlet writes,
  before service ops" invariant from the spec as explicit edges: every unit/quadlet write
  node → `daemon-reload` → every service-op node that needs it.
- **root** — so the walk has a single entry; mirrors Terraform's RootTransformer.

### Edge kinds

| Kind | Semantics | Borrowed from |
|---|---|---|
| `order` | B runs after A if both are scheduled; no failure coupling | systemd `After=` |
| `require` | order + failure propagation: if A fails, B is skipped (`skipped: dependency failed`) | systemd `Requires=`, Terraform walker |
| `notify` | if A **changed** (create/update, not adopt/skip), B's refresh action is scheduled (restart-if-active) | Puppet `notify` / Salt `watch` |

Failure propagation follows `require` edges only. This *refines* the spec's per-resource
skip posture rather than replacing it: independent branches still converge when one
resource fails — but a resource whose declared prerequisite failed no longer pretends to
be independent.

### Derived edges (autorequire table for the magus IR)

Edges are derived from structural references already present in the IR; both endpoints
must be declared (or manifest-owned, for deletes) or the edge silently doesn't exist —
Puppet's soft-edge rule. No user-facing dependency syntax in v1.

| From → To | Kind | Derivation |
|---|---|---|
| directory → file/dir/quadlet whose path it prefixes | `require` | longest declared path prefix (parent dirs settle mode/ownership before children land) |
| unit body → its drop-ins | `order` | same unit name |
| unit/quadlet write → `daemon-reload` | `require` | any content mutation (spec batching rule) |
| `daemon-reload` → service ops | `require` | existing phase 2→3 boundary |
| declared `.network`/`.volume` quadlet → `.container` service start | `require` | `Network=`/`Volume=` keys in the `.container` INI naming a *declared* quadlet |
| managed file → service op of unit/quadlet referencing it | `notify` | `EnvironmentFile=` (units and quadlets) whose path is IR-declared |
| service stop/removal → delete of things it depended on | `require`, reversed | deletes take the **reverse** of the create-order edges (Terraform reverse-topo destroy) |

The `notify` derivation deliberately parses only `EnvironmentFile=` (and quadlet
`Network=`/`Volume=`) — keys magus already canonicalizes, values that are plain paths/
names. General unit-content dependency mining (`ExecStart=` paths etc.) is rejected: too
heuristic, and MCO's precedent says a small honest subset beats a clever guess. If real
gaps appear, the escape hatch is an explicit dependency table in `policy.yaml` (which is
already the reconciler-config surface) — not a Butane extension, which its strict parser
would reject.

### Execution

**Serial, in stable topological order** (Kahn's algorithm; ties broken by
(kind, path) sort so plan and apply output are deterministic run-to-run — same D9
rationale as the manifest sweep sort). Parallel walking is explicitly rejected for v1:
every action is a host-local syscall or `systemctl` call where parallelism buys
milliseconds and costs determinism, and Terraform's walker exists to hide network latency
magus doesn't have.

**Cycle detection:** Tarjan SCC at plan time. A cycle is input-bad (halts, exit 1) and the
error prints the **entire cycle with each edge's provenance** — Terraform's `Error: Cycle:`
UX plus Puppet's edge-source reporting:

```
error: dependency cycle:
  /etc/magus.d/a.env → ollama.container  (EnvironmentFile= reference)
  ollama.container → /etc/magus.d/a.env  (directory containment)
```

**`magus graph --dot`** emits the graph in Graphviz form — the #1 debugging tool both
Terraform and Puppet ship. Cheap: the graph exists at plan time; this just serializes it.

### Plan surface: the disruption column

Adopt MCO's action lattice, sized to magus's vocabulary: `none < daemon-reload < restart`
(`reboot` reserved for a future where kargs/storage ever enter scope — they are not in
v1's, per the spec's Rejected IR and MCO's matching precedent). Each plan row gains its
computed disruption action; the plan footer reports the max:

```
  [update]  /etc/magus.d/ollama.env      (notify → restart ollama.service)
  [update]  /etc/systemd/system/x.timer  (daemon-reload)
  max disruption: restart (ollama.service)
```

This makes `plan` an honest preview of *behavioral* impact, not just byte-diffs — the same
promise the enablement-preview rows already make, extended to propagation. A future
per-path override table (NodeDisruptionPolicy-shaped) slots into `policy.yaml` when
someone needs "this file may change without restarting that service."

### Library choice

Hand-rolled, in-repo, ~400 lines: Kahn toposort + Tarjan SCC + stable ordering + the
edge-kind walk semantics above. Rationale: the graph is tens of nodes over four resource
kinds; `sourcegraph/tf-dag` is battle-tested but MPL-2.0, includes a parallel walker we
don't want, and its algorithms are the textbook ones anyway. The project currently has
four direct dependencies and a security posture that favors auditable-over-imported.
tf-dag remains the reference implementation to crib walker semantics from.

## What this deliberately does not do

- No user-declared dependencies in Butane (strict parser; two-consumer contract).
- No parallel apply.
- No day-2 storage/kargs vocabulary — the graph makes adding them *possible* later
  (Ignition's disks→raid→luks→filesystems edges are already written down in the research
  notes), but MCO's `Reconcilable()` precedent says live storage mutation is where
  reconcilers stop, and the spec already made that call.
- No daemon/watch mode. Kubernetes-style level-triggered reconciliation suits a persistent
  controller; magus is a one-shot CLI under a timer. If a daemon mode ever lands it shares
  the diff engine, not the walk.

## Consequences

- The `EnvironmentFile=` gap closes: config-only changes now restart their consumers, and
  `plan` says so before `apply` does it.
- Quadlet first-start ordering and delete ordering become guaranteed rather than
  incidental.
- Apply's phase code (`unitEvents`, phases 1a/1b/2/3) is subsumed by graph structure —
  a refactor with the Phase-1 integration net already under it (tests-before-refactor,
  same rule as implementation-plan Phase 5).
- Plan output grows a disruption column and ordering becomes part of the contract —
  spec-reconciler.md needs an "Ordering & propagation" section (spec change accompanies
  code change, per house rules).
- New failure mode to test: `require`-skip cascades must be visible (`skipped: dependency
  /x failed`) and counted in exit-code semantics (skip → exit 2, unchanged).
