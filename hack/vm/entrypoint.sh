#!/usr/bin/env bash
# entrypoint — thin subcommand dispatch for the harness container.
set -euo pipefail

cmd="${1:-help}"; shift || true
case "$cmd" in
  fetch) exec fcos-fetch "$@" ;;
  run)   exec fcos-run   "$@" ;;
  e2e)   exec fcos-e2e   "$@" ;;
  shell) exec bash "$@" ;;
  help|*)
    cat <<'EOF'
magus VM harness. Subcommands:
  fetch  [--arch A] [--stream S] [--refresh]     download+verify FCOS image
  run    --ignition cfg.ign [opts]               boot a throwaway FCOS VM
  e2e    --fixture DIR --magus BIN [--reboot]    full pave→adopt→day2 cycle
  shell                                          poke around

Needs --device /dev/kvm and a /cache volume. See hack/vm/README.md.
EOF
    ;;
esac
