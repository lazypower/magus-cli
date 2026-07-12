# hack/vm — the FCOS VM harness (ADR-0001, tier 1 & 2)

One set of scripts, two packagings, three substrates:

| Where | How | Accel |
|---|---|---|
| Mac (inner loop) | scripts natively: `brew install qemu butane coreos-installer` | HVF, aarch64 |
| Linux box with `/dev/kvm` (Framework, cloud, act_runner) | the harness container | KVM |
| GitHub Actions `ubuntu-latest` | the harness container (`--device /dev/kvm`) | KVM, x86_64 |

The scripts detect acceleration themselves (`kvm` → `hvf` → loud-warning `tcg`).
Ignition goes in via fw_cfg (`opt/com.coreos/config`) — the canonical qemu-platform
mechanism — so every tier exercises the same Ignition platform (`qemu`). Images are
fetched by `coreos-installer` with signature verification and cached; every boot uses
`-snapshot`, so the cached image is never dirtied and teardown is `kill`.

## Pieces

- **`fcos-fetch`** — download + GPG-verify the official qemu qcow2 for an arch/stream
  into the cache; maintains a stable symlink and a `.version` pin file (CI cache key).
- **`fcos-run`** — boot a throwaway VM with an Ignition file. Foreground with serial
  console, or `--detach pidfile` with `--console log` for harness use.
- **`fcos-e2e`** — the lifecycle test: render fixture butane → wrap with a harness
  ssh key + `ignition.config.merge` → **Ignition paves at first boot** → install magus →
  assert the plan is **adopt-only** (no create, no conflict) → apply → idempotence →
  day-2 mutation → converge → optional `--reboot` and re-assert (the spec's "reaches
  declared state on next boot"). Fixture-specific post-conditions live in the fixture's
  executable `assert.sh` (gets `MAGUS_SSH_KEY`/`MAGUS_SSH_PORT`).
- **`fixtures/basic/`** — `day1.bu` (paved *and* adopted — the two-consumer duality is
  the fixture's whole point), `day2.bu` (mutations), `policy.yaml`, `assert.sh`.
- **`Containerfile`** — pins qemu/butane/coreos-installer/edk2 into one image.

## Quick start

Native (Mac or Linux):

```sh
brew install qemu butane coreos-installer   # macOS; dnf equivalents on Fedora
GOOS=linux GOARCH=$(uname -m | sed 's/arm64/arm64/;s/x86_64/amd64/') \
  go build -o /tmp/magus ./cmd/magus        # build magus FOR THE GUEST
hack/vm/fcos-e2e --fixture hack/vm/fixtures/basic --magus /tmp/magus --reboot
```

Containerized (any Linux host with /dev/kvm):

```sh
podman build -t magus-vm-harness -f hack/vm/Containerfile hack/vm/
GOOS=linux GOARCH=amd64 go build -o magus.linux ./cmd/magus
podman run --rm --device /dev/kvm \
  -v magus-vm-cache:/cache -v "$PWD:/work:z" \
  magus-vm-harness e2e --fixture /work/hack/vm/fixtures/basic \
                       --magus /work/magus.linux --reboot
```

Interactive VM for poking:

```sh
hack/vm/fcos-run --ignition boot.ign            # console on stdio, Ctrl-A X quits
ssh -i <key> -p 2222 core@127.0.0.1
```

## Suggested Makefile targets

```make
vm-harness:
	podman build -t magus-vm-harness -f hack/vm/Containerfile hack/vm/

vm-e2e: ## needs qemu+butane+coreos-installer (native) — see hack/vm/README.md
	GOOS=linux GOARCH=$(GUEST_ARCH) go build -o $(TMPDIR)/magus ./cmd/magus
	hack/vm/fcos-e2e --fixture hack/vm/fixtures/basic --magus $(TMPDIR)/magus --reboot
```

## CI sketch (GitHub mirror — plan WP A3)

```yaml
jobs:
  vm-e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Enable /dev/kvm
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
      - name: Restore image cache
        uses: actions/cache@v4
        with: { path: ~/.cache/magus-vm, key: fcos-${{ hashFiles('hack/vm/fixtures/**') }} }
      - name: Build guest binary
        run: GOOS=linux GOARCH=amd64 go build -o /tmp/magus ./cmd/magus
      - name: Install harness deps
        run: |
          sudo apt-get update && sudo apt-get install -y qemu-system-x86
          # butane + coreos-installer: fetch release binaries (pin versions)
      - name: e2e
        run: hack/vm/fcos-e2e --fixture hack/vm/fixtures/basic --magus /tmp/magus --reboot
      - name: Console log on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with: { name: console-log, path: /tmp/magus-e2e.*/console.log }
```

(Or run the harness container in the job instead of apt-installing — trade image pull
time for pinned tooling. Decide in WP A3.)

## What this tier proves / doesn't

Proves: real Ignition first-boot pave, the adopt-only handoff, enablement across a real
boot, restart-if-active against real systemd, reboot persistence. Doesn't prove (by
design, see ADR-0001): anything on the podman tier's turf (fast logic iteration), or
production-platform fidelity (that's the ephemeral-Hetzner conformance rung, WP A4).

Known limitation, on purpose: `fixtures/basic/day2.bu` changes the unit *and* its env
file, because an EnvironmentFile-only change does not yet restart the consumer — that is
the apply-graph's motivating gap (ADR-0002). When WP B3 lands, add `day3.bu` mutating
only `hello.env` and assert the restart here.
