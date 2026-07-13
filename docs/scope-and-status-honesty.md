# magus is system-scope — and its status is honest about what it checked, silent about what it didn't

> magus will report a clean, converged, honest `status` while a rootless workload
> does nothing.

That sentence is the whole hazard. It is not a bug. `magus status` is a verifier
that is **honest about what it checked and silent about what it didn't** — and if
you deploy a rootless (user-scope) workload with magus, everything it checks can
be green while the thing you actually wanted to run is dead. This note makes that
boundary discoverable so the next operator meets it in the docs instead of
excavating it on a live host.

## What magus's scope actually is

magus operates entirely in **system (root) scope**. Concretely, and by
construction:

- Unit bodies and drop-ins are written under `/etc/systemd/system/`
  (`internal/diff/diff.go:513`).
- Quadlet sources are recognized **only** under a hardcoded system root,
  `/etc/containers/systemd/` (`internal/ir/butane.go:117`); a `.container` file
  anywhere else is treated as an ordinary file, not a quadlet
  (`internal/ir/butane.go:204`).
- The systemd manager shells out to the **system** `systemctl` for every
  `enable` / `start` / `restart` / `show`. There is no `--user` anywhere in
  `internal/systemd/`.
- It reads **exactly one** Butane source per invocation
  (`cmd/magus/apply.go`, `fs.NArg() != 1` → usage error; `internal/ir/butane.go`,
  `LoadButane` takes a single path/URL). There is no compose, merge, glob, or
  `hosts/<hostname>` resolution — those live in whatever wrapper invokes magus,
  not in magus.
- It ignores every Ignition-only field — `passwd.users`, `ignition.config.merge`,
  etc. — silently and on purpose (`docs/spec-reconciler.md:126-135`).

magus has **zero user-scope reach**. It cannot write to
`~user/.config/containers/systemd/` *as a quadlet*, cannot
`systemctl --user daemon-reload`, and cannot start — or even **observe** — a
user manager's units.

## Why that collides with rootless workloads

A rootless workload (the argus swarm is the motivating case) runs containers
under a dedicated unprivileged user's systemd manager, isolated by `subuid`,
`--userns=nomap`, and lingering. That is a **user-scope** deployment. magus is a
**system-scope** tool. The two do not meet, and the tool does not get to pick the
security posture: hoisting the workload into root-podman to make magus's life
easy would trade away the isolation that justified running untrusted code in the
first place.

So do not expect magus to *deploy* a rootless workload. Expect it to **stage**
one:

| magus owns (system scope)                          | out of band (user scope)                     |
|----------------------------------------------------|----------------------------------------------|
| the account (via `install.bu`, or a oneshot)       | the user manager starting at boot            |
| the `subuid` / `subgid` grant (append, see below)  | `daemon-reload` of the user generator        |
| linger enablement                                  | start of the rootless quadlet services       |
| the `.container` sources, as **ordinary files**    | actual container liveness                    |

"magus deploys the swarm" was never true. **magus stages it.** Bring-up happens
in the user manager at boot, triggered by linger, on a path magus neither fires
nor watches. Put that in writing wherever the workload is specified.

## The observability gap, named in verifier terms

magus's own health signal is `ObserveUnits`, which queries the is-active state of
the units magus manages and records it to `/var/lib/magus/status.json`
(`internal/apply/apply.go:263`, `internal/status/status.go`). Those are **system**
units. Rootless quadlet services are **user** units. They are not in the set magus
observes, so their convergence is not merely *unverified* — it is
**un-observable by magus at all.**

This is one instance of a shape worth recognizing everywhere, because it recurs:

- `magus validate` — honest about **policy admissibility**, silent about convergence.
- `magus status` — honest about **system units**, silent about user units.

A green that is honest about what it checked and silent about what it didn't is
still a lie if the reader assumes it checked everything. The defense is not to
make one verifier omniscient; it is to make each verifier **state its own
boundary** — and, where a boundary matters, to build a check that crosses it.

## Closing the gap through the boundary magus *does* own

You do not need magus to grow `--user`. You need a **system-scope probe unit,
owned by magus, whose job is to interrogate user scope** — because `ObserveUnits`
can see *that* unit's state:

```ini
# argus-liveness.service — magus owns it (system scope); it reports user scope.
[Service]
Type=simple
Restart=on-failure
# stays active while argusd is reachable; exits (→ failed) the moment it isn't,
# so magus's on-demand `systemctl show` reads a LIVE verdict every apply.
ExecStart=/usr/bin/bash -c 'while systemctl --user -M argus@ is-active -q argusd.service; do sleep 30; done; exit 1'
```

This converts an un-observable into an observable without asking magus to change
scope. **One caveat that is itself the same failure shape:** a *oneshot* probe
reflects argusd's state only at its last trigger, and magus does **not** re-run an
unchanged oneshot on a steady-state apply (it fires units on create, on a
content-edit restart, and at boot — see `reconcileServiceState`,
`internal/apply/apply.go:702`). A stale probe magus faithfully reports is just the
lie relocated one level up. Use a long-running mirror (above) or a timer-driven
probe you accept is "as of last fire" — never a bare oneshot.

## General rule this generalizes to (keep this line)

**Replace-semantics means any multi-writer file must be edited by a oneshot,
never owned — `*.d/` drop-in dirs excepted.** magus owns files by whole-content
replacement: a managed file is rewritten to exactly its IR bytes every apply, and
`adopt` makes magus own the live file *then* replace it. `/etc/subuid` is the
canonical trap — own it and you overwrite every other stakeholder's ranges (and
`adopt` would replace `core`'s range with argus's alone, breaking every rootless
container on the box). The safe form is an idempotent append inside a oneshot:

```ini
ExecStart=/usr/bin/bash -c 'grep -q "^argus:" /etc/subuid || echo "argus:100000:65536" >> /etc/subuid'
```

Corollary for **multi-action** units: guard **each `ExecStart`** with a
state check (`id -u || useradd`, `grep -q || >>`, `enable-linger`, `chown -R` —
all clean no-ops on re-fire, so a content-edit restart can never land the unit
`failed`). Do **not** reach for `ExecCondition=` on a unit that does more than one
thing: it gates the *whole* unit, so "account already exists" would skip the
subuid, linger, and chown steps that must keep converging. `ExecCondition` is
right only for a single-action idempotent unit; per-`ExecStart` guards are
load-bearing for a converging multi-action one.

## Policy note

Expressing an account declaratively via `systemd-sysusers` (a `/etc/sysusers.d/`
drop-in file magus owns — the `*.d/` exception, so it is safe to own) is strictly
better than a guarded `useradd` oneshot: a declarative source of truth, eagerly
reconciled every apply. It requires the host policy's `file_roots`
(`internal/policy/policy.go:24`) to include `/etc/sysusers.d` (and
`/var/lib/systemd/linger` if you also want linger as a marker file rather than a
`loginctl` call). Absent those roots, magus halts the apply as a reserved/out-of-root
write rather than doing it silently — which is the policy gate behaving correctly.

## Pointers

- Authority model, manifest semantics, equivalence rules: `docs/spec-reconciler.md`
- Single-source loading: `internal/ir/butane.go` (`LoadButane`)
- System-scope quadlet root: `internal/ir/butane.go:117`
- Unit lifecycle (why an unchanged oneshot does not re-fire): `internal/apply/apply.go:702` (`reconcileServiceState`)
- What magus observes: `internal/apply/apply.go:263` (`ObserveUnits`) → `/var/lib/magus/status.json`
- Path authority (`file_roots`, deny, reserved): `internal/policy/`
