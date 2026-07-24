#!/usr/bin/env bash
# Live proof of ADR-0003's rootless spine on a real-kernel host (real logind).
# Acceptance #1: day-2 running argusd under user@1000 (converged over reconcile
# ticks). #2: staged-not-activated honesty when the user manager is down.
set -uo pipefail

IMG="quay.io/fedora/fedora-coreos:stable"
PODMAN="sudo podman"
FAIL=0
note() { printf '\n=== %s ===\n' "$*"; }
ok()   { printf 'PASS: %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; FAIL=1; }

POLICY='version: 1
file_roots:
  - /etc/core
  - /var/lib/magus
  - /var/home/argus
unit_patterns:
  - "magus-*"
manage_users:
  - argus
deny:
  paths:
    - /etc/shadow
    - /etc/passwd
'

# Container-only workload (no custom network) — isolates magus-driven activation
# from rootless-podman networking. No [Install]: magus itself starts it, proving
# magus drives activation rather than default.target pulling it in at boot.
BUTANE='variant: fcos
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
          Image=docker.io/library/busybox
          Network=none
          Exec=sleep 3600
'

uctl() { $PODMAN exec "$1" runuser -u argus -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user "${@:2}"; }
apply() { $PODMAN exec "$1" magus apply --yes --policy /policy.yaml /host.bu 2>&1; }

boot() {
  local n="$1"
  $PODMAN rm -f "$n" >/dev/null 2>&1
  $PODMAN run -d --name "$n" --privileged --systemd=always "$IMG" >/dev/null || { bad "podman run $n"; return 1; }
  for _ in $(seq 1 120); do $PODMAN exec "$n" systemctl daemon-reload >/dev/null 2>&1 && break; sleep 1; done
  $PODMAN cp /tmp/magus-amd64 "$n:/usr/bin/magus"
  $PODMAN cp /tmp/busybox.tar "$n:/tmp/busybox.tar"
  $PODMAN exec "$n" mkdir -p /var/lib/magus
  printf '%s' "$POLICY" | $PODMAN exec -i "$n" tee /policy.yaml >/dev/null
  printf '%s' "$BUTANE" | $PODMAN exec -i "$n" tee /host.bu >/dev/null
}

# preload_image loads busybox into argus's rootless store from the tar, so the
# workload needs no registry pull (the nested container has no egress DNS). This
# isolates the proof to magus's ACTIVATION, not the container's networking.
preload_image() {
  local n="$1"
  $PODMAN exec "$n" chown argus:argus /tmp/busybox.tar
  $PODMAN exec "$n" runuser -u argus -- env XDG_RUNTIME_DIR=/run/user/1000 podman load -i /tmp/busybox.tar >/dev/null 2>&1
}

wait_mgr() { # wait until user@1000 manager bus is reachable
  local n="$1"
  for _ in $(seq 1 40); do
    if $PODMAN exec "$n" test -d /run/user/1000; then
      s=$(uctl "$n" is-system-running 2>/dev/null | tr -d '[:space:]')
      { [ "$s" = running ] || [ "$s" = degraded ]; } && return 0
    fi
    sleep 2
  done
  return 1
}

probe_logind() {
  local n="$1"
  $PODMAN exec "$n" useradd -u 1234 -m lprobe >/dev/null 2>&1
  $PODMAN exec "$n" loginctl enable-linger lprobe >/dev/null 2>&1 || return 1
  for _ in $(seq 1 20); do
    if $PODMAN exec "$n" test -d /run/user/1234; then
      s=$($PODMAN exec "$n" runuser -u lprobe -- env XDG_RUNTIME_DIR=/run/user/1234 systemctl --user is-system-running 2>/dev/null | tr -d '[:space:]')
      { [ "$s" = running ] || [ "$s" = degraded ]; } && { $PODMAN exec "$n" userdel -r lprobe >/dev/null 2>&1; return 0; }
    fi
    sleep 2
  done
  $PODMAN exec "$n" userdel -r lprobe >/dev/null 2>&1; return 1
}

########################################################################
note "Acceptance #1 — fresh host: argus + rootless quadlet -> argusd active under user@1000, day-2"
C1=magus-rootless-1
boot "$C1" || exit 1
if ! probe_logind "$C1"; then echo "SKIP: no real user-scope logind"; $PODMAN rm -f "$C1" >/dev/null 2>&1; exit 3; fi
ok "real user-scope logind present"

echo "--- apply #1 (provisions identity+subuid+linger, writes quadlet; manager not up yet) ---"
A1=$(apply "$C1"); echo "$A1"
$PODMAN exec "$C1" id argus >/dev/null 2>&1 && ok "argus created" || bad "argus not created"
$PODMAN exec "$C1" grep -q '^argus:' /etc/subuid && $PODMAN exec "$C1" grep -q '^argus:' /etc/subgid && ok "subuid+subgid granted" || bad "no subuid/subgid"
$PODMAN exec "$C1" test -e /var/lib/systemd/linger/argus && ok "linger enabled" || bad "linger marker missing"

echo "--- wait for user@1000 to come up (linger), then reconcile again ---"
if wait_mgr "$C1"; then ok "user@1000 manager operational"; else bad "user@1000 never became operational"; fi
preload_image "$C1"
echo "--- apply #2 (manager up -> magus activates the workload) ---"
A2=$(apply "$C1"); echo "$A2"

ACTIVE=no
for _ in $(seq 1 40); do
  [ "$(uctl "$C1" is-active argusd.service 2>/dev/null | tr -d '[:space:]')" = active ] && { ACTIVE=yes; break; }
  sleep 3
done
if [ "$ACTIVE" = yes ]; then ok "argusd.service ACTIVE under user@1000 — day-2, no reimage"
else bad "argusd.service never reached active"; uctl "$C1" status argusd.service 2>&1 | head -25; fi
$PODMAN rm -f "$C1" >/dev/null 2>&1

########################################################################
note "Acceptance #2 — hold the user manager down (mask user@1000) -> staged, not activated"
C2=magus-rootless-2
boot "$C2" || exit 1
$PODMAN exec "$C2" systemctl mask user@1000.service >/dev/null 2>&1
OUT=$(apply "$C2"); CODE=$?; echo "$OUT"; echo "apply exit: $CODE"
echo "$OUT" | grep -q 'staged, not activated' && ok "reported staged, not activated" || bad "did not report staged"
[ "$CODE" = 2 ] && ok "exit 2 (skips present)" || bad "exit was $CODE, want 2"
[ "$(uctl "$C2" is-active argusd.service 2>/dev/null | tr -d '[:space:]')" != active ] && ok "argusd NOT active while manager down (honest)" || bad "argusd active though masked — lied"
$PODMAN rm -f "$C2" >/dev/null 2>&1

########################################################################
note "RESULT"
[ "$FAIL" = 0 ] && echo "ALL LIVE ACCEPTANCE CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $FAIL
