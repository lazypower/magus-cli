# Magus Reconciler — v1 Completion Plan

**Status:** Draft (for approval)
**Companion to:** `docs/spec-reconciler.md`
**Loop:** codex-loop (Claude builds, Codex breaks, Claude triages)

## Step 0 — Frame (the governor)

**Product promise.** Magus is the day-2 reconciler half of the two-consumer Butane
model: take a desired-state declaration and continuously, *additively* converge a
running bootc/FCOS host toward it — authoritative inside its namespace, blind
outside it. "Implementation complete" = the **v1 contract in `spec-reconciler.md`
is fully and faithfully implemented and proven against a real host environment.**

**Threat model — IN scope (defend this).** The user/LLM surface: the Butane IR, the
`policy.yaml` boundary, the manifest ownership contract, and the CLI verbs. Magus
must never:
- write or delete outside its declared authority (`file_roots` ∩ not-`deny`, manifest ownership);
- silently overwrite a resource it doesn't own (conflicts skip, never clobber);
- escalate privilege (setuid/setgid/world-writable beyond policy);
- be tricked past the path allowlist via symlinks.

**Threat model — OUT of scope.** Filesystem omnipotence. An actor who already owns
`/etc` or `/var/lib/magus` can corrupt the manifest or place hostile files directly
— hardening against every malicious local-FS arrangement is bunker cosplay. Magus
trusts root-owned config it reads; it defends the *CLI/IR/policy* surface, not the
disk against its own administrator. Also out: runtime supervision (start/stop/
watchdog beyond first-create — that's systemd's job, per spec), and all deferred
items below.

**Definition of done.** Per phase: (1) the spec behavior is implemented; (2) Codex
Mode B finds no in-scope correctness/safety defect; (3) coverage ≥ 70% per package
touched; (4) podman integration proves the real-environment path where applicable.
NOT "Codex can no longer invent an attack."

**Explicitly deferred (not v1, per spec Open Questions):** rollback/backup-on-delete,
`passwd.users`, `magus relinquish`, empty-directory deletion, precompiled IR,
Magus-native IR vocabulary.

## Phases

Each phase: branch off `main` (worktree where parallelism helps) → build → `go test`
→ Codex review (`codex review --base main` + frame prompt) → triage via rubric →
commit → push → PR to gitea `origin`. Checkpoint with the human at PR boundaries.

### Phase 1 — Podman integration harness (safety net FIRST)
**Why first:** the user wants real-environment apply/diff testing, and it gives us
end-to-end characterization coverage *before* we refactor internals (tests-before-
refactor). 
- A `//go:build integration` test package that runs the real `magus` binary inside a
  rootful podman container with `systemd` as PID 1 (`podman run --systemd=always`)
  against fixture Butane files.
- **Conformance target: the bootc substrate
  `registry.wabash.place/chuck/core-base:latest`** (FCOS-based; the image magus
  actually runs on — canonical location for now). Image is selectable via
  `MAGUS_IT_IMAGE`, defaulting to that ref. Fallback chain when the LAN registry is
  unreachable from a dev box: (1) pull `core-base:latest`; (2) `just build` it
  locally from `../core-image`;
  (3) `quay.io/fedora/fedora-coreos:stable` (core-base's own base) as a dev bootstrap
  — **fallback only, not the conformance target.**
- **Run against the real policy.** Use `../core-image/config/magus/policy.yaml`
  (workload-layer bounds: `file_roots` = `/etc/containers/systemd`, `/etc/core`,
  `/var/lib/magus`; denies the fleet/agent secrets and substrate units) as the
  primary fixture, so the harness proves the actual deployment boundary, not a toy.
- Asserts the full loop on a real host: `apply` creates files/units/quadlets, second
  `apply` is a clean no-op (idempotence), enablement reconciles, delete-on-omission
  works, conflicts skip, adoption is a no-op. Diff/plan exit codes verified.
- **Ignition-only-ignore fixture (Codex #12):** a shared Butane file carrying
  `storage.disks` / `storage.filesystems` / `passwd.users` must `validate` and
  `apply` cleanly (ignored, not rejected) — the two-consumer promise.
- A `make integration` / script target; skipped in the default `go test ./...` gate
  (no podman in unit CI). Gated so unit runs stay hermetic.
- Deliverable: `internal/integration/` (or `test/integration/`) + a fixtures dir + a
  runner script. Pin the base image by digest for reproducibility.

### Phase 2 — Authority & policy correctness (the safety core)
The biggest phase: every path by which Magus could write/delete outside its authority
or escalate. Codex Mode A expanded this from "two bugs" to the full authority surface.
**Each item ships with its own unit tests in this phase (Codex #10) — safety
invariants are not deferred to Phase 5.**

- **Quadlet policy enforcement (Codex #8/#9, corrected by ground truth).**
  `policy.Check()` currently skips quadlets entirely. Correct boundary, confirmed
  against the real `core-image` policy:
  - quadlet **source path** → validate against `file_roots` + `deny.paths` +
    mode-escalation (like any file);
  - quadlet **generated-service name** → validate against `deny.units` **only**, NOT
    `unit_patterns`. The real policy's `unit_patterns` is just `*.d/10-magus.conf`;
    checking generated services (`ollama.service`, …) against it would reject every
    quadlet on a real host. `deny.units` still applies so a quadlet can't generate a
    denied service (e.g. `core-reconcile.*`, `sshd.*`).
  - Spec-doc fix only: the spec's *inline* example `file_roots` omits
    `/etc/containers/systemd` — add it. `policy.example.yaml` already has it; no code
    exception needed.
- **Symlink resolution (Hard Rule 1; Codex #1/#2/#3).** Resolution feeds **both** the
  allowlist and the `deny` decision. Algorithm: resolve the **longest existing
  ancestor** of the target; that resolved ancestor must stay within `file_roots` and
  clear of `deny`; refuse partial-path symlink escape (e.g. `/var/data/link/new`
  where `link` is a symlink out of bounds). Genuine resolution errors fail closed;
  a non-existent *leaf* (normal create) does not. Close the leaf TOCTOU with
  `O_NOFOLLOW` on the final open/write so a swapped leaf is refused, not followed.
  Bounded deliberately — full `openat2(RESOLVE_NO_SYMLINKS)` is rejected as
  complexity-disproportionate (a same-privilege root swap mid-apply is out of scope).
- **Manifest↔policy contention / orphaning (Codex #4).** When policy newly denies a
  path Magus owns, transition the manifest entry `active → orphaned` (sticky, audit
  retained, excluded from diff/apply, warned every plan/apply). Removing the deny
  does NOT auto-restore — only `magus reclaim` does. Aged-out cleanup when the file
  is gone. Verify against current implementation; this is v1 contract and may be
  missing.
- **Reserved state paths (Codex #6).** `/var/lib/magus/manifest.json` and
  `status.json` (and whatever `--manifest`/`--policy` point at) must be **reserved**:
  an IR that declares them is a parse-time validation error. Magus never manages its
  own state through the IR even though it lives inside a `file_root`. (This bug
  already exists for the manifest today.)
- **Write-capable verb authority (Codex #5).** `magus adopt` and `reclaim --force`
  write to disk; route both through the same policy + `deny` + symlink-safe write
  gate as `apply`, with confirmation preserved. Add tests proving they can't bypass
  conflict-skip or path authority.

### Phase 3 — `magus plan --explain`
- Add the flag. For `[update]`/`[conflict]`: unified text diff over the bytes used
  for hashing (canonicalized for units, raw for files); sha256-of-each-side fallback
  when either side is non-text/binary; mode & ownership deltas as single lines.
- Pure planner output — no new system access. Unit-tested against fixtures.
- **DECIDED (Codex #11 — Chuck):** conflicts are *unowned*, so dumping their content
  is an info-leak into logs/automation. **Default: hashes-only for `[conflict]`
  rows** (sha256 of each side). Owned `[update]` rows still show full diffs. An
  explicit `-v` / `--verbose` flag reveals the conflict diff for an operator running
  interactively — secures logs by default, keeps human-in-the-loop ergonomics. Update
  `spec-reconciler.md` to match (the line-343 example becomes hashes-only unless `-v`
  is set).

### Phase 4 — `magus status` completion + observation state
**Design decision (Mode A):** the manifest is the *ownership* contract and must stay
that — conflicts/errors are not owned resources. Introduce a separate **observation
file** `/var/lib/magus/status.json` written at the end of every `apply`, capturing
`last_apply`, `result`, per-unit state, `conflicts[]` (carrying `first_seen` forward
across applies), and `errors[]`. `magus status` reads it; absent file → "never
applied" degraded view.
- Clean seam: `manifest` = what Magus placed; `status` = what last apply observed.
- **Crash-consistency (Codex #7):** written atomically (tmp+rename); `first_seen` is
  carried forward by reading the prior status before writing. Status reflects the
  last *completed* apply — honest on crash, not stale-success. Per-resource status
  journaling is rejected as out-of-scope complexity (rollback is deferred).
- **Reserved path (Codex #6):** `status.json` is covered by the Phase-2 reserved-path
  rule — an IR cannot declare it.
- Completes the spec's `status --json` shape exactly.

### Phase 5 — Module seams + cmd/systemd/hostfs coverage
- **Refactor for testability with a regression net already in place** (Phases 1–4
  added it). Extract the `runX` command bodies behind an injectable env (stdout/
  stderr/stdin, clock, `hostfs`, `systemd`) so `cmd/` is unit-testable without
  shelling the binary.
- Review ownership boundaries: `diff↔apply` (shared `Kind`/hash duplication),
  `manifest↔diff` kind translation, `cmd` orchestration. Refactor only where a seam
  is genuinely wrong; add regression tests once boundaries settle.
- **Safety net precondition (Codex #10):** the adversarial invariants from Phases 2–4
  (symlink containment, orphaning, reserved paths, adopt/reclaim authority, status
  consistency) already carry their own unit tests from their own phases. Phase 5 only
  moves code those tests already guard — it does not introduce safety behavior.
- Bring `cmd/`, `systemd` (osManager parse logic), `hostfs` (atomic-write, chown
  sentinels) to ≥70%. Keep the whole module ≥70%.

### Phase 6 — (OPTIONAL, propose) deployment units
- Ship `magus.service` + `magus.timer` (`apply --yes` on an interval) as the
  spec's production trigger model. Small; gated on approval — arguably packaging,
  not reconciler logic.

## Sequencing notes
- Phases 2–4 are independent feature branches; Phase 5 lands after them (it refactors
  the surface they touch). Phase 1 lands first as the net.
- Codex is the BREAK seat at every PR (cross-model, read-only). Claude never
  adversarially reviews its own work.
- Coverage gate enforced per phase; `go test ./...` stays green and hermetic.
</content>
</invoke>
