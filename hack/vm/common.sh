#!/usr/bin/env bash
# common.sh — shared helpers for the magus FCOS VM harness.
#
# Everything here is host-fungible by design (ADR-0001): the same scripts run
# natively on macOS (HVF), natively on Linux (KVM), or inside the harness
# container (KVM via --device /dev/kvm). Nothing may assume a specific machine.

set -euo pipefail

log()  { printf '>> %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Cache directory for downloaded images. Inside the container this is /cache
# (a volume); natively it defaults to XDG cache.
cache_dir() {
  echo "${MAGUS_VM_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/magus-vm}"
}

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo x86_64 ;;
    arm64|aarch64) echo aarch64 ;;
    *) die "unsupported host arch: $(uname -m)" ;;
  esac
}

# accel <target-arch> → kvm | hvf | tcg
# KVM/HVF only accelerate same-arch guests; anything else is TCG (slow, warn).
accel() {
  local target="$1" os; os="$(uname -s)"
  if [ "$os" = Linux ] && [ -w /dev/kvm ] && [ "$target" = "$(host_arch)" ]; then
    echo kvm; return
  fi
  if [ "$os" = Darwin ] && [ "$target" = "$(host_arch)" ]; then
    echo hvf; return
  fi
  echo tcg
}

# aarch64 guests need EDK2 firmware; search the usual homes (Fedora pkg,
# homebrew qemu, generic).
find_aarch64_fw() {
  local c
  for c in \
    /usr/share/edk2/aarch64/QEMU_EFI.silent.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    "$(brew --prefix 2>/dev/null || true)/share/qemu/edk2-aarch64-code.fd" \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/edk2-aarch64-code.fd; do
    [ -f "$c" ] && { echo "$c"; return; }
  done
  die "no aarch64 EDK2 firmware found (install edk2-aarch64 / qemu via brew)"
}

# Canonical image path for an arch+stream, maintained by fcos-fetch.
image_link() {
  echo "$(cache_dir)/fcos-$1-$2.qcow2"
}

# ssh options for throwaway VMs: ephemeral key, no host-key noise.
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=5)

vm_ssh() { # vm_ssh <key> <port> <cmd...>
  local key="$1" port="$2"; shift 2
  ssh "${SSH_OPTS[@]}" -i "$key" -p "$port" core@127.0.0.1 "$@"
}

vm_scp() { # vm_scp <key> <port> <src> <dst>
  local key="$1" port="$2" src="$3" dst="$4"
  scp "${SSH_OPTS[@]}" -i "$key" -P "$port" "$src" "core@127.0.0.1:$dst"
}

# wait_ssh <key> <port> [timeout_s] — until sshd answers and systemd settles
# enough to be useful. `is-system-running` may legitimately report `degraded`
# on a stock image (e.g. a flaky vendor unit); reachability + a working
# systemctl is the readiness bar, mirroring the podman harness's daemon-reload
# probe.
wait_ssh() {
  local key="$1" port="$2" timeout="${3:-180}" start now state
  start=$(date +%s)
  while :; do
    if state=$(vm_ssh "$key" "$port" systemctl is-system-running 2>/dev/null); then
      log "guest systemd: $state"; return 0
    fi
    case "$state" in running|degraded) log "guest systemd: $state"; return 0 ;; esac
    now=$(date +%s)
    [ $((now - start)) -ge "$timeout" ] && return 1
    sleep 2
  done
}
