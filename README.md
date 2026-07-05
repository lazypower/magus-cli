<p align="center">
  <img src="header.png" alt="magus">
</p>

# magus

`magus` is a day-2 reconciler for bootc / Fedora CoreOS hosts. It consumes the
IR subset of a [Butane](https://coreos.github.io/butane/) file and converges the
running system toward the declared state — files, directories, systemd units
(body + drop-ins), and Podman Quadlets — with a policy gate and a manifest that
records what magus owns.

It was extracted from the [magus OS image](https://github.com/lazypower/magus)
to stand on its own; the OS image is now just one consumer. The first intended
consumer is `core-base`.

## Commands

| Command    | What it does                                                  |
|------------|---------------------------------------------------------------|
| `validate` | Parse a Butane source and check it against the policy         |
| `plan`     | Show what `apply` would do (diff against manifest + disk)      |
| `apply`    | Reconcile the system toward the declared state                |
| `status`   | Print reconciler state from the manifest                      |
| `adopt`    | Take over an existing path that differs from the IR           |
| `reclaim`  | Restore an orphaned path to active reconciliation             |

A Butane source is either a local path or an `http(s)` URL (fetched on every
invocation, no caching). Run `magus <command> -h` for command-specific flags.

## What it reconciles

- **Files** — content, mode, ownership. Inline payloads are decoded from
  `data:` URLs and gunzipped when Butane auto-compresses them.
- **Directories** — created with declared mode/ownership; contents untouched.
- **Units** — body and drop-ins written under `/etc/systemd/system`, then
  `daemon-reload`, enable/disable, and start/restart-if-active per the IR.
- **Quadlets** — `.container` sources written to the Quadlet dir; magus drives
  the *generated* `.service` (the generator runs at `daemon-reload`).

Per-resource errors never halt the whole apply — one bad resource doesn't take
the system hostage. Exit codes: `0` clean, `2` skipped (conflict/orphan/drift),
`1` errored or input-bad.

## Defaults

- Policy: `/etc/magus/policy.yaml` (`--policy` to override). See
  [`policy.example.yaml`](policy.example.yaml).
- Manifest: `/var/lib/magus/manifest.json` (`--manifest` to override).

## Design

The authority model, manifest semantics, and equivalence rules live in
[`docs/spec-reconciler.md`](docs/spec-reconciler.md).

## Build

```sh
go build -o magus ./cmd/magus
go test ./...
```

The binary is static (`CGO_ENABLED=0`) and shells out to `systemctl`; on hosts
without systemd, unit/quadlet operations surface as per-resource errors rather
than crashing, so `validate`/`plan` work anywhere.

## License

[Apache License 2.0](LICENSE).
