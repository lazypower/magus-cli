# ADR-0001 — Test substrate: tiered, with a fungible KVM host

**Status:** Proposed
**Date:** 2026-07-12
**Companion to:** `docs/spec-reconciler.md`, `docs/implementation-plan.md` (Phase 1 shipped the tier-0 harness this ADR builds on)

## Context

magus is a day-2 reconciler for Fedora CoreOS / bootc hosts. Its correctness story has a
hole no unit test can fill: the **Ignition → magus adoption handoff** — first boot paves
the system from `magus.bu`, then the first `magus apply` must adopt everything Ignition
placed. Today that handoff is only simulated (the integration suite `put()`s files into a
podman container and applies). The spec's own unit of correctness — "the system will reach
the declared state on next boot" — is also unproven, because nothing in CI ever reboots.

Constraints:

- Development happens on an Apple Silicon Mac (arm64 darwin). The conformance image
  (`core-base`) is amd64, so the existing podman integration suite runs under emulation
  there — functional but slow, and `is-system-running` never settles.
- CI is self-hosted Gitea with Firecracker-backed runners. Firecracker cannot boot FCOS:
  no UEFI, no fw_cfg, and the upstream request for Firecracker-compatible FCOS artifacts
  was considered and never implemented
  ([coreos/fedora-coreos-tracker#624](https://github.com/coreos/fedora-coreos-tracker/issues/624)).
- The repo mirrors to GitHub (`.github/workflows/test.yml` exists).
- Local hardware (Framework desktop) is available only as a **time-boxed** bring-up host —
  it carries LLM workloads and cannot become the permanent substrate. A small cloud budget
  is acceptable.

## Decision

Three test tiers, plus one design rule that keeps the hardware question from ever being
load-bearing.

**Design rule: the VM tier targets an interface, not a machine.** Every VM-tier script
assumes only "a Linux host with `/dev/kvm`, qemu, and ssh access" — parameterized by
`MAGUS_VM_HOST` (empty = localhost). The Framework desktop is the first binding of that
interface during bring-up; a cloud box or a CI runner binds it later with zero script
changes. No component may assume a specific machine.

### Tier 0 — podman systemd container (exists; extend)

The `internal/integration` harness (privileged systemd container running `core-base`,
nightly + labeled-PR in Gitea CI) stays the inner loop: sub-second boots, arch-agnostic,
runs on the Mac and on the Firecracker runners.

**Extension — real Ignition fixtures via `ignition-apply`.** Ignition ships a container
entrypoint that applies an Ignition config inside a container, skipping disk/filesystem
stages: `/usr/libexec/ignition-apply` (shipped since Ignition 2.14/2.15,
[release notes](https://github.com/coreos/ignition/blob/main/docs/release-notes.md)).
That converts the simulated handoff into a real one, VM-free:

```
butane magus.bu > magus.ign
podman exec <ctr> /usr/libexec/ignition-apply /fixtures/magus.ign   # Ignition paves
podman exec <ctr> magus apply --yes <source>                        # magus adopts
```

Assert: every declared resource lands as `[adopt]`, zero writes, second apply is a clean
no-op. This makes the two-consumer contract (equivalence rules loose enough to adopt
Ignition's actual output) a tested invariant instead of a design intention.

Out of scope for this tier, permanently: real first-boot semantics, storage, kernel
args, reboots, bootloader, SELinux fidelity.

### Tier 1 — local VM on the Mac (on-demand inner loop)

**Primary: qemu + HVF with the official aarch64 qcow2, Ignition via fw_cfg** — the
canonical qemu-platform mechanism
([FCOS provisioning docs](https://docs.fedoraproject.org/en-US/fedora-coreos/provisioning-qemu/)):

```sh
qemu-system-aarch64 \
  -M virt -accel hvf -cpu host -m 2048 \
  -bios "$(dirname "$(which qemu-system-aarch64)")/../share/qemu/edk2-aarch64-code.fd" \
  -snapshot -drive if=virtio,file=fcos-aarch64-qemu.qcow2 \
  -fw_cfg name=opt/com.coreos/config,file=magus.ign \
  -nic user,model=virtio,hostfwd=tcp::2222-:22 -nographic
```

`-snapshot` makes every boot throwaway. Image fetched + verified from the stream metadata
([stable.json](https://builds.coreos.fedoraproject.org/streams/stable.json)). Crucially
this exercises `ignition.platform.id=qemu` — the **same platform the CI tier uses**, so
one Butane fixture set serves both. The HVF incantation is not in the official docs (they
document `qemu-kvm`), so the wrapper script lives in-repo and is treated as owned code.

**Secondary: vfkit with the official `applehv` raw image** (`vfkit --ignition magus.ign`,
[vfkit usage](https://github.com/crc-org/vfkit/blob/main/doc/usage.md)) — Apple
Virtualization.framework, faster boot, and the exact path podman machine uses. Kept as a
fallback/`applehv`-platform check, not the default: different Ignition platform id than
CI, raw+EFI-var-store management, and a history of `--ignition` bugs
([vfkit#241](https://github.com/crc-org/vfkit/issues/241)).

### Tier 2 — CI real-VM boots

Two bindings, both cheap, adopted in order:

**(a) GitHub mirror, `ubuntu-latest` + qemu-KVM — zero cost.** Standard GitHub-hosted
Linux runners have had working `/dev/kvm` since 2024
([changelog](https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/)),
and public-repo runners are 4 vCPU / 16 GB / free
([GitHub blog](https://github.blog/news-insights/product-news/github-hosted-runners-double-the-power-for-open-source/)).
The job: udev rule for `/dev/kvm`, fetch+cache the x86_64 qemu qcow2, boot with the same
`-fw_cfg` flag as Tier 1, ssh in, run the e2e day-2 suite (pave → adopt → mutate → apply →
**reboot → assert declared state persists**). Caveat: GitHub's arm64 runners have no KVM
([discussion](https://github.com/orgs/community/discussions/149673)); arm64 VM coverage in
CI is TCG-emulation-only (acceptable as an occasional nightly smoke, not a gate).

**(b) Ephemeral Hetzner FCOS instances — highest fidelity, pennies.** FCOS publishes an
**official `hetzner` artifact for x86_64 and aarch64** (verified in stable.json), with
Ignition delivered via Hetzner user-data. A small harness (hcloud API: create with
user-data → ssh → run suite → destroy) tests magus against a *genuinely
Ignition-provisioned, production-platform* FCOS machine — including real arm64 — at
~€0.01/hour with zero standing cost. No nested virt involved at all. This is the
conformance ceiling; adopt when (a) is green and the extra fidelity is wanted.

**(c) Optional later: persistent `kvm`-labeled Gitea runner** on a Hetzner x86 cloud box
(nested virt is community-verified there, ~€7–26/mo) if keeping VM CI on the self-hosted
side becomes important. Standard act_runner setup; nothing FCOS-specific. Not part of the
initial plan — (a) and (b) cover the need without standing cost.

Existing Firecracker runners keep doing exactly what they're good at: the hermetic unit
gate and the tier-0 container suite.

### Graduation path (noted, not committed)

kola external tests (`tests/kola/` executables run inside booted FCOS VMs,
[docs](https://github.com/coreos/coreos-assembler/blob/main/docs/kola/external-tests.md))
are the FCOS-ecosystem-standard harness and run fine on the KVM-enabled GitHub runner via
the cosa container. If magus wants ecosystem alignment later, the Tier-2 suite can be
repackaged as kola external tests. Not required for the contract-proving goal.

## Rejected alternatives

- **Vagrant** — no official FCOS boxes have ever existed; Apple Silicon support still
  rests on the third-party experimental
  [vagrant-qemu](https://github.com/ppggff/vagrant-qemu) plugin
  ([vagrant#12559](https://github.com/hashicorp/vagrant/issues/12559)); Vagrant's
  ssh-user/shared-folder provisioning model fights Ignition's first-boot model. It would
  be an unofficial box + a plugin wrapping qemu to do what a 10-line qemu script does
  directly.
- **Firecracker as the VM tier** — no UEFI/fw_cfg; upstream declined FCOS support
  (tracker #624). A theoretical live-PXE direct-kernel-boot exists but runs from RAM — the
  wrong fixture for a tool whose subject is an *installed* ostree system.
- **lima** — cloud-init-centric; FCOS/Ignition support is an open, unimplemented request
  ([lima#1406](https://github.com/lima-vm/lima/issues/1406)).
- **UTM / krunkit** — GUI-first / no documented Ignition path; vfkit covers the niche.
- **cloud-hypervisor** — fw_cfg exists but behind a compile-time feature and unproven for
  Ignition ([docs](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/fw_cfg.md));
  not worth pioneering here.
- **cosa/kola on the Mac** — cosa requires `/dev/kvm`; Linux-only by design
  ([building-fcos](https://coreos.github.io/coreos-assembler/building-fcos/)).
- **Testing Farm** — free managed infra, but the public ranch is scoped to
  Red Hat/Fedora/CentOS-maintained projects; eligibility doubtful and FCOS composes
  unverified.
- **Permanent local hardware** — explicitly excluded by constraint; the fungible-host rule
  exists so this never needs revisiting.

## Consequences

- One Butane fixture set drives all tiers; the qemu Ignition platform is shared between
  Tier 1 and Tier 2(a), so a fixture that passes locally means something in CI.
- The adoption handoff and reboot-persistence become CI-gated invariants — the two spec
  promises currently proven nowhere.
- The Mac stops being a second-class dev environment: tier 0 for logic, tier 1 for real
  boots, both local.
- New moving parts owned in-repo: the qemu wrapper scripts, the GH workflow, image
  fetch/cache/verify against stream metadata, and (later) the hcloud harness. Each is
  small; all are delegable (see `docs/plan-substrate-and-graph.md`).
- Costs: €0 standing. Hetzner runs are metered pennies; the Framework desktop is used only
  while it's convenient and owes the plan nothing.
