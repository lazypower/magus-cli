# Guide: Managing principals (users & groups)

`magus` reconciles operating-system **principals** — users and groups — as day-2
resources, the same way it reconciles files, directories, and units. This means
you can add a user (or bring an existing one under management) on a running
bootc / FCOS host **without reimaging**.

This guide covers declaring and reconciling the *identity*. Making a rootless
workload actually **run** under that identity (subuid/subgid ranges, linger, the
user-scope service spine) is a separate concern — see
[`guide-rootless.md`](guide-rootless.md).

The full design rationale is [ADR-0003](adr-0003-principal-reconciliation.md);
this is the operator's how-to.

---

## The boundary: `manage_users`

magus touches a principal **only** if policy's `manage_users` allowlist names it.
This is the identity analogue of `file_roots` and `unit_patterns`: a declared
principal that is *not* in the allowlist is invisible to magus — it's Ignition's
concern (like `storage.disks`), not magus's to create or modify.

```yaml
# /etc/magus/policy.yaml
manage_users:
  - argus            # magus may create/modify the argus user and the argus group
```

A principal you declare in Butane but omit from `manage_users` is silently
ignored. Nothing to undo, nothing to fear — magus just doesn't look at it.

---

## Step 1 — declare the principal in Butane

Principals are read from the standard Butane `passwd.users` / `passwd.groups`
sections. There is **no new vocabulary** — the same Butane file Ignition applies
at first boot is what magus converges day-2.

```yaml
variant: fcos
version: 1.5.0

passwd:
  groups:
    - name: argus
      gid: 1234
  users:
    - name: argus
      uid: 1234
      primary_group: argus
      home_dir: /var/home/argus
      shell: /usr/sbin/nologin
      groups:
        - argus
```

Two hard requirements for a **managed** principal (enforced at `validate`):

- **A user must declare `uid`; a group must declare `gid`.** magus never
  auto-allocates. UIDs must be deterministic fleet-wide — an implicitly
  allocated uid would drift host-to-host and break every downstream thing keyed
  on it (file ownership, `subuid` ranges, `/run/user/<uid>`).
- **No `password_hash`, no `ssh_authorized_keys`.** Managed accounts are
  workload accounts, not login accounts. Both are refused at `validate` in v1
  (created accounts are password-locked). On an *unmanaged* principal these are
  Ignition's to apply and magus ignores them.

### What magus reads

| Butane field    | Class       | Reconciliation                                          |
|-----------------|-------------|---------------------------------------------------------|
| `uid` / `gid`   | identity    | set once at create; a later mismatch is a **conflict**  |
| `primary_group` | identity    | set once at create; a mismatch is a **conflict**        |
| `home_dir`      | identity    | set once at create; a mismatch is a **conflict**        |
| `shell`         | mutable     | converged every apply (`usermod -s`)                    |
| `groups`        | mutable     | **additive** — magus adds missing memberships, never removes |
| `system`        | create-time | passes `--system` to useradd/groupadd                   |

**Identity is immutable.** `uid`, `primary_group`, and `home_dir` key ownership
across the whole fleet, so magus sets them once and never mutates them in place.
If the declaration later disagrees with what's on the host, magus reports a
**conflict** and skips — it will not silently re-home or renumber an account. To
renumber, remove the principal and let magus recreate it clean.

**Mutable attributes converge.** If someone changes the shell or the account
drops out of a declared supplementary group, the next apply restores it.

---

## Step 2 — plan and apply

Principals flow through the same commands as every other resource:

```sh
magus validate ./host.bu      # boundary + gate checks, no host reads
magus plan     ./host.bu      # show the create/converge/adopt/conflict actions
magus apply    ./host.bu      # reconcile (prompts unless --yes)
```

`plan` classifies each managed principal into one of four actions:

| Action     | Meaning                                                            |
|------------|-------------------------------------------------------------------|
| `create`   | The principal doesn't exist. magus will `useradd` / `groupadd` it. |
| `converge` | It exists, identity matches, a mutable attribute drifted. `usermod`. |
| `adopt`    | It exists and already matches the declaration. Claimed, no write.  |
| `conflict` | It cannot converge safely. Surfaced and **skipped**, never forced. |

`plan` and `apply` share the reconciler's exit codes: `0` converged, `2` changes
pending or conflicts present, `1` errored or input-bad. `magus plan --json`
includes a `principals` array so a scriptable consumer sees identity work
before gating on `apply --yes`.

### Safe defaults for created accounts

Every account magus *creates* gets conservative defaults, regardless of what the
declaration omits:

- **Password locked** (`usermod -L`) — no interactive login.
- **`nologin` shell** unless the declaration sets one.
- **Home created** (`useradd -m`).

A workload account is not a login account. If you need a real shell, declare it
explicitly — but then it's your call, on the record.

---

## Privileged groups need an explicit grant

Adding a managed principal to a **root-equivalent group** is a privilege
escalation, so it is denied unless policy explicitly grants it per principal.
The built-in privileged set is always treated as root-equivalent:

```
root  wheel  sudo            # sudo vectors
docker  lxd  libvirt         # spawn privileged containers/VMs → host escape
disk  kmem  shadow  kvm       # raw device / kernel memory / password hashes
adm  systemd-journal          # logs routinely carry secrets
```

Extend the set for host-specific privileged groups with `privileged_groups`, and
grant a specific principal a specific membership with `group_grants`:

```yaml
# /etc/magus/policy.yaml
privileged_groups:            # optional — extends the built-in set
  - my-secrets-readers

group_grants:                 # required for any privileged membership
  argus:
    - docker
```

Without a matching grant, declaring `argus` into `docker` (or any privileged
group) is **rejected at `validate`**. The gate resolves groups by **identity**:
you must declare groups **by name**, because a numeric gid is refused outright —
magus can't verify that a bare number isn't a privileged group in disguise.

The gate also fires on **adoption**: if magus is asked to adopt an existing
principal that already sits in a privileged group without a grant, that's a
conflict — not a silent absorb. Resolve it by granting the membership in policy,
or by removing the principal so magus can recreate it clean.

---

## Adopting an Ignition-created principal

The common first-boot path: Ignition creates `argus` from the same Butane file,
then the first `magus apply` **adopts** it — if the on-host attributes match the
declaration, magus claims ownership and writes nothing. From that point magus
reconciles the principal forward like anything else it owns.

Adoption is silent and non-destructive. The only ways it *doesn't* happen:

- an identity attribute differs → **conflict** (see below)
- a mutable attribute drifted → **converge** (magus fixes it)
- a privileged membership lacks a grant → **conflict**

---

## Resolving conflicts

A conflict means magus found a state it will not paper over. It records the
conflict (visible in `magus status` as `user:<name>` / `group:<name>`), skips
the principal, and moves on — one contested identity never halts the rest of the
apply.

| Conflict                                            | Fix                                                              |
|-----------------------------------------------------|-----------------------------------------------------------------|
| declared `uid`/`gid` belongs to a different account | pick a free id, or remove the colliding account                 |
| existing account has a different `uid`/gid/home     | identity is immutable — remove & recreate to change it          |
| existing account in a privileged group, no grant    | add a `group_grants` entry, or remove the account               |

magus **never deletes a principal.** Removal is always a deliberate operator
action, never a side effect of reconciliation.

---

## What magus does *not* do (v1)

- **No principal deletion.** Omitting a once-declared principal does not remove
  it. (This mirrors directories, which are also never deleted on omission.)
- **No membership removal.** Group membership is additive-only — magus adds what
  you declare and records what it added; it never strips a membership it doesn't
  own.
- **No secrets.** `password_hash` / `ssh_authorized_keys` are deferred; managed
  accounts are password-locked.
- **No implicit ids.** Every managed principal declares its own uid/gid.

---

## See also

- [`guide-rootless.md`](guide-rootless.md) — running a rootless workload under a
  managed principal (subuid/subgid, linger, the user-scope spine).
- [ADR-0003](adr-0003-principal-reconciliation.md) — the design and its
  adversarial (policy) core.
- [`policy.example.yaml`](../policy.example.yaml) — annotated `manage_users` /
  `privileged_groups` / `group_grants`.
- [`spec-reconciler.md`](spec-reconciler.md) — the canonical authority model.
</content>
</invoke>
