#!/usr/bin/env bash
# Post-condition assertions for the basic fixture. Runs on the harness side;
# fcos-e2e provides MAGUS_SSH_KEY / MAGUS_SSH_PORT. Called after day-2 apply
# and again after the optional reboot — both must hold.
set -euo pipefail

run() {
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR -i "$MAGUS_SSH_KEY" -p "$MAGUS_SSH_PORT" \
      core@127.0.0.1 "$@"
}

fail() { echo "assert: $*" >&2; exit 1; }

run grep -q 'GREETING=day2' /etc/magus.d/hello.env \
  || fail "hello.env does not carry day-2 content"
run test -f /etc/magus.d/extra.env \
  || fail "extra.env (day-2 create) missing"
run test -d /var/data/hello \
  || fail "declared directory missing"
[ "$(run systemctl is-active magus-hello.service)" = active ] \
  || fail "magus-hello.service is not active"
[ "$(run systemctl is-enabled magus-hello.service)" = enabled ] \
  || fail "magus-hello.service is not enabled"
run journalctl -u magus-hello.service --no-pager \
  | grep -q 'magus-hello: day2' \
  || fail "service did not restart with day-2 environment"

echo "assert: basic fixture post-conditions hold"
