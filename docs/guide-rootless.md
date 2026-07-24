# Guide: Rootless workloads (subuid, linger, the user-scope spine)

`magus` reconciles a **principal**'s identity (see
[`guide-principals.md`](guide-principals.md)). This guide is the other half:
making a rootless workload actually **run** under that principal — day-2, on a
running bootc / FCOS host, **without reimaging**.

The motivating case is a rootless podman swarm worker (`argus`): unprivileged
containers under a dedicated user's *own* systemd manager, isolated by `subuid`,
`--userns`, and lingering — a security posture root-podman would throw away. magus
does not get to pick that posture; it converges toward it.

The full design rationale is [ADR-0003](adr-0003-principal-reconciliation.md);
this is the operator's how-to.

---

## What magus provisions — and what you declare

Rootless capability is a **consequence, not a knob**. You declare two things:

1. a **managed principal** with a **uid** and a **`home_dir`**, and
2. its **quadlets**, as files under `<home>/.config/containers/systemd/`.

From the single fact *this principal owns rootless workloads*, magus derives and
provisions the prerequisites — you never declare them:

| magus derives & provisions        | how                                             |
|-----------------------------------|-------------------------------------------------|
| subuid / subgid range             | `usermod --add-subuids/--add-subgids` (detect-then-provision; preserves every other line in the shared `/etc/subuid`) |
| lingering                         | `loginctl enable-linger <name>` (so `user@<uid>` runs at boot without a login session) |
| the user-scope quadlet activation | reconciled through the principal's user manager |

There is **no new Butane vocabulary** for any of this. subuid and linger are
provisioned, not declared.

## `home_dir` is required (and load-bearing)

Scope is **path-derived**: a quadlet is user-scope only if magus can place it
under a declared principal's home. **If the owning principal does not declare
`home_dir`, magus cannot derive the scope and the `.container` file silently
degrades to an ordinary file** — no subuid, no linger, no activation. Always
declare `home_dir` for a rootless owner:

```yaml
passwd:
  users:
    - name: argus
      uid: 1000
      home_dir: /var/home/argus   # REQUIRED for rootless scope derivation
      shell: /usr/sbin/nologin
```

magus writes the quadlet source — and the `.config` parent tree it creates —
**owned by the principal**, because rootless podman refuses a config path it does
not own. The `useradd`-made home above it is left exactly as found.

## A complete example

```yaml
variant: fcos
version: 1.5.0
passwd:
  users:
    - name: argus
      uid: 1000
      home_dir: /var/home/argus
      shell: /usr/sbin/nologin
storage:
  files:
    - path: /var/home/argus/.config/containers/systemd/argusd.container
      mode: 0644
      contents:
        inline: |
          [Unit]
          Description=argus worker
          [Container]
          Image=quay.io/argus/argusd:latest
          Exec=/usr/bin/argusd
```

Policy must **manage the principal** and **root its home** so the source can be
written there:

```yaml
# /etc/magus/policy.yaml
manage_users:
  - argus
file_roots:
  - /var/home/argus
```

Apply it and magus creates `argus`, grants its subuid/subgid range, enables
linger, writes the quadlet, and activates `argusd.service` under `user@1000`.

## Convergence takes a tick or two — by design

`loginctl enable-linger` starts `user@<uid>` **asynchronously**. On the *first*
apply the manager usually isn't up yet, so magus honestly reports the workload
**`staged, not activated`** (exit 2) rather than pretending. The next reconcile
tick — once `user@<uid>` is operational — activates it. On a timer-driven host
(`core-reconcile.timer`) this is seconds, no reimage. This is normal reconciler
behavior: converge toward the declared state over ticks.

## The honest skip: `staged, not activated`

A user workload can only activate when its user manager is **operational**:
`/run/user/<uid>` present and `systemctl --user is-system-running` in
`{running, degraded}`. When it isn't — linger not yet effective, `user@<uid>`
masked or held down — magus reports each workload:

```
✗ .../argusd.container  (skipped: staged, not activated: /run/user/1000 not present …)
```

and exits **2**. It never reports a green while a rootless workload does nothing —
the gap [`scope-and-status-honesty.md`](scope-and-status-honesty.md) named, now
closed. If a prerequisite fails mid-apply (e.g. `enable-linger`), the principal is
still recorded and a **re-apply resumes** from it — linger retried, no orphan, no
recreate.

## The transport (for the curious)

magus reaches a principal's user manager over the transport proven on FCOS:

```
runuser -u <name> -- env XDG_RUNTIME_DIR=/run/user/<uid> systemctl --user <op>
```

It deliberately does **not** use `systemctl --user -M <name>@`, which needs
`systemd-machined` (inactive by default on FCOS) and fails on real iron while
passing a nested-VM shim.

## What magus still does not do

- **No disk / filesystem / LUKS / device management** — permanently Ignition-only.
- **No auto-delete** of a principal or its group memberships — `magus reclaim` only.
- **No secret material** (`password_hash`) — created accounts are password-locked.
- **No arbitrary `--user` surface** — only the declared user quadlets under a
  principal's home are reconciled; the transport is not a general remote-exec.

## Proving it

- Unit suites drive the whole spine through in-memory fakes
  (`internal/principal`, `internal/systemd`, `internal/apply`).
- `internal/integration/rootless_test.go` proves it end-to-end on **real
  logind** (skips where the kernel can't provide it — nested libkrun on macOS).
- `hack/rootless-proof.sh` is the live driver used to certify the acceptance
  criteria on a real-kernel host.
