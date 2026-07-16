# ADR-0003 — Principal and rootless-workload reconciliation: day-2 user lifecycle inside magus's authority

**Status:** Proposed
**Date:** 2026-07-16
**Companion to:** `docs/spec-reconciler.md` (Authority model), `docs/adr-0002-apply-graph.md` (the DAG this rides on), `docs/scope-and-status-honesty.md` (the gap this closes)

## Context

magus is a day-2 reconciler for bootc/FCOS. Today it manages files, directories,
system units, and **system** podman quadlets (under `/etc/containers/systemd/`),
all as root. It deliberately ignores Butane's `passwd.users` — a v1 deferral
that treated user creation as a first-boot (Ignition) concern.

The motivating workload is **argus**: a rootless podman swarm worker running as
the unprivileged `argus` user, its quadlets under
`/var/home/argus/.config/containers/systemd/`, activated by argus's *user*
systemd manager (`user@1000.service`), not the system instance.

We ran magus's derived apply-graph (ADR-0002) over the committed `argus.bu` and
it made the gap concrete — 6 declared resources, **5 isolated**:

```
/argus.bu → 8 nodes, 2 edges
  /etc/systemd/system/system.slice.d/10-magus.conf → daemon-reload  [require]
  daemon-reload → system.slice                                       [require]
isolated:
  /etc/subgid, /etc/subuid
  …/argusd.container, …/argus-egress.network, …/argus.slice
```

magus sees almost none of the workload. The rootless quadlets are `kind: file`
(magus only auto-promotes quadlets under `/etc/containers/systemd/`), so it
stages the bytes but never sees `Network=argus-egress.network`, never derives a
generated service, never gates against `deny.units`, never orders the worker's
start — and never creates the `argus` account those files are useless without.

**The problem this ADR solves.** A day-2 reconciler that cannot add a user
without reimaging is not a reconciler — it is a slower `rpm-ostree`. Staging the
files is pointless if reaching a *running* argusd still requires an Ignition
first boot. The tool is too narrow to be useful in reality without owning the
principal's lifecycle.

**The boundary was mis-drawn.** The two-consumer line is not system-vs-user or
identity-vs-config. It is **"can this converge on a running box?"**:

- `useradd` / `usermod` / `groupadd` / `loginctl enable-linger` / `systemctl --user` —
  **yes, day-2.** These are ordinary post-boot operations.
- `storage.disks` / `storage.filesystems` / `luks` / raw device setup — **no.**
  You cannot repartition a live root. These are irreversible-on-a-running-system
  and stay Ignition-only, permanently.

Filesystem mounts sit on the *convergeable* side: a mount is a `.mount` unit,
which magus already reconciles — so NFS/bind mounts need nothing special.

`passwd.users` was never on the boot-only side of that line. It was deferred, not
disqualified. This ADR un-defers it.

Prior art:

- **Puppet** reconciles `user` and `group` as first-class day-2 resource types
  (`ensure => present`, managed attributes, `membership => minimum|inclusive` for
  the additive-vs-owned group question) — the closest shipped model to what we
  want ([user type](https://www.puppet.com/docs/puppet/7/types/user.html)).
- **systemd-sysusers** provisions system users declaratively but is one-shot and
  system-scoped; we want it as a *reconciled* resource, not a boot generator.
- **shadow-utils** (`useradd`/`usermod`) already allocate and track subordinate
  UID/GID ranges per user in `/etc/subuid`/`/etc/subgid` — we lean on that rather
  than hand-editing those shared files.
- **rootless podman + Quadlet** under `~/.config/containers/systemd/` activated by
  the per-user manager with **lingering** is the documented rootless-at-boot path
  ([podman rootless](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)).
- **cloud-init** `users-and-groups` is the reference for the declared-attribute
  surface (name/uid/groups/shell/home/lock) an operator expects.

## Decision

Extend magus's authority to reconcile **principals** (users and groups) and the
**rootless workloads** they own, day-2, as convergeable resources — reusing the
adopt/manifest/policy machinery already in place and the ADR-0002 graph for
cross-scope ordering. Ignition remains the bootstrap; magus converges the same
Butane on a running host, resolving overlap by adoption, exactly as it does for
files.

### Principals as reconciled resources

A principal is diffed like any other resource: declared (Butane `passwd.users` /
`passwd.groups`) vs actual (`getent passwd`/`group`), producing the familiar
verbs.

- **create** → `useradd`/`groupadd`; **converge** → `usermod`/`groupmod`;
  **adopt** → an existing principal whose attributes already match (Ignition made
  `core`; a prior apply made `argus`) is claimed into the manifest with no write.
- **No auto-delete.** `userdel -r` destroys home and data — the same asymmetry as
  directories (ADR-era spec). Omission leaves the principal in place with a warn;
  removal is an explicit `magus reclaim`, never a sweep.
- **Consumed attribute subset (v1):** name, **uid** (required — see below),
  primary group, supplementary groups, shell, home dir, and a locked/system flag.
  **Deferred:** `password_hash` (secret material — gated by policy if ever), and
  `ssh_authorized_keys` (an identity-adjacent file concern, separable).

### Rootless capability is *provisioned*, not declared

This is the key simplification, and it directly retires the `argus.bu`
subuid conflict we observed (a whole-file `/etc/subuid` declaration clobbers
`core`'s line).

`/etc/subuid`, `/etc/subgid`, and lingering are **not** operator-declared knobs.
They are *consequences* magus derives from a single fact: **this principal owns
rootless workloads** (it has declared user quadlets/units under its home). When
that holds, magus provisions the prerequisites deterministically:

- **subuid/subgid** via `usermod --add-subuids` / shadow-utils allocation —
  per-principal, **preserving every other user's line**. `/etc/subuid` is never a
  managed file; it is a shared, line-oriented registry that only the shadow tools
  edit. (This retires the "shared line-oriented files" edge case entirely.)
- **linger** via `loginctl enable-linger <name>`, because `user@<uid>.service`
  must run at boot for the workload to exist without a login session.

So a future `argus.bu` shrinks to: declare the `argus` principal + its rootless
quadlets. magus infers and provisions subuid + linger. The operator stops
hand-rolling shared-file surgery.

### The rootless spine, on the ADR-0002 graph

Everything the graph bought us pays off here. A user quadlet's activation node
takes `require` edges up a spine magus **owns end to end** — no hand-off to
Ignition mid-chain (one authority per question):

```
principal(argus) ⊳ subuid/subgid ⊳ linger ⊳ user@1000.service reachable ⊳ user-quadlet activation
```

- **Scope is path-derived**, exactly as system-quadlet detection is today: a
  quadlet/unit under `<home>/.config/containers/systemd/` or
  `<home>/.config/systemd/user/` is `user:<name>`, not system.
- **The transport is settled empirically.** User-scope `systemctl` runs as
  `runuser -u <name> -- env XDG_RUNTIME_DIR=/run/user/<uid> systemctl --user …`.
  We proved `runuser`+XDG works and `-M user@` fails (systemd-machined is inactive
  on FCOS). No open question here.
- **`user@<uid>` reachability is a probe-with-timeout** (`/run/user/<uid>` present
  and `systemctl --user is-system-running` answers) — the same shape as waiting
  for a system quadlet's generated service.
- **Honest-skip falls out of the `require` cascade.** If any prerequisite is
  unmet, activation renders `skipped: dependency <x> failed` and status reports
  the workload as **staged, not activated** — never a green that lies. This is
  precisely the gap `scope-and-status-honesty.md` named, now closed by graph
  structure rather than prose.

### The policy dimension — the adversarial core

Creating and modifying principals as root is privilege-escalation-adjacent: a
hostile Butane could declare uid 0, add a workload account to `wheel`, or set a
login shell with an unlocked password. The safety of this whole feature lives in
one new boundary, analogous to `file_roots`/`unit_patterns`:

- **`manage_users`** — an allowlist of principals magus may create/modify (e.g.
  `argus`). Absent from the allowlist ⇒ a declared principal is a validation
  error, not a silent skip.
- **Hard denies (always, even if allowlisted):** `root`/uid 0; system range
  (uid < 1000) magus did not create; and *escalating* an existing principal magus
  does not own.
- **Privileged-group gate.** Adding a managed principal to a root-equivalent group
  (`wheel`, `sudo`, `docker`, …) is **denied unless policy explicitly permits it**
  for that principal. Adding `argus` to `wheel` is root; it must be a conscious,
  auditable grant.
- **Safe defaults for created principals:** password locked, shell `nologin`, no
  supplementary privileged groups — unless each is explicitly declared *and*
  permitted. A workload account is not a login account.
- **Reserved principals:** magus's own service identity and the substrate accounts
  are un-manageable through the IR, mirroring the reserved-path rule.

### Group membership: additive-only in v1

Group membership is many-to-many and shared — dropping `wheel` from a declaration
should not silently *remove* a membership another actor added. v1 is
**additive-only**: magus adds declared memberships and records in the manifest
exactly which it added; it never removes a membership it does not own.
Full inclusive ownership (Puppet's `membership => inclusive`) is deferred until a
real need appears. Removal of a magus-added membership is a `reclaim`.

### Deterministic UIDs

A managed principal **must** declare its uid (and primary gid). Fleet-wide, the
uid is load-bearing — subuid ranges, `/run/user/<uid>`, and every file's
ownership key off it, so an auto-allocated uid that drifts host-to-host is a
latent fleet bug. A declared uid already taken by a *different* principal is a
**conflict** (surfaced, skipped), never a clobber.

## What this deliberately does not do

- **No disk / filesystem / LUKS / device management.** The permanent Ignition-only
  set — irreversible on a live root.
- **No auto-delete of principals or group memberships.** Destructive; `reclaim`
  only.
- **No implicit uid allocation** for managed principals.
- **No secret material in v1** — `password_hash` deferred (policy-gated if ever);
  created accounts are password-locked.
- **No inclusive group-membership ownership in v1** — additive-only.
- **No arbitrary `--user` unit vocabulary** beyond declared user units and the
  rootless quadlets under a principal's home. The user transport is not a general
  remote-exec surface.
- **No new Butane vocabulary.** subuid/subgid and linger are provisioned, not
  declared; the strict two-consumer parser is unchanged.

## Consequences

- **The two-consumer model becomes symmetric.** Ignition bootstraps; magus
  converges the same Butane day-2 — files, units, quadlets, *and* principals —
  overlap resolved by adoption. The Ignition-only carve-out shrinks to boot-only
  storage. This is a cleaner, smaller boundary than the old system-vs-user split.
- **A new adversarial surface exists and is the review focus:** identity creation
  as root. The `manage_users` boundary and the privileged-group gate get the same
  Codex-seat scrutiny Phase 2 gave path authority. A wrong edge here is a
  privilege escalation, not a mis-ordered write.
- **The manifest grows** a principal dimension (owned users/groups, origin,
  magus-added group memberships) so ownership, adoption, and reclaim work for
  identities exactly as for files.
- **`status` gains honest rootless reporting** — staged-vs-activated per user
  workload, via the transport — closing the honesty gap end to end.
- **The rootless quadlet stops being an opaque file.** Path-derived scope turns
  the isolated nodes from the argus.bu graph into real quadlet nodes with
  `Network=`/`Volume=` references and generated-service reconciliation, ordered
  behind the principal spine.
- **argus deploys day-2, no reimage** — the acceptance test for whether this ADR
  was worth building.

## Validation gate (proof before mechanism)

Before any reconcile-loop change, a capability-and-honesty fixture on real FCOS
must pass — the same rigor as the A1 handoff proof:

1. Fresh host, **no `argus` user**. Apply a Butane declaring the `argus` principal
   (explicit uid) + its rootless quadlets. Assert argusd's generated service
   reaches `active` under `user@1000` — **day-2, no reimage**.
2. Flip linger off (or hold the user manager down). Assert magus reports
   **staged, not activated** with the dependency reason — never green.
3. A second principal already present (Ignition-made) is **adopted**, not
   recreated; a uid collision is a **conflict**, not a clobber.
4. A denied escalation (declaring `argus` into `wheel` without policy grant) is
   **rejected at validate**.

If the transport, linger timing, or shadow-utils subuid handling fights us on real
iron, we learn it on the fixture — and this ADR is cheap to drop before the loop
is touched.
