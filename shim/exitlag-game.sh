#!/usr/bin/env bash
# Run a game inside exitlag.slice so ONLY its traffic is redirected through ExitLag
# Only needed with `run_exitlag.sh --scope cgroup` (default scope is uid, where
# ExitLag decides per process and no wrapper is required).
#   Direct:  ./shim/exitlag-game.sh <command> [args...]
#   Steam:   launch options ->  /path/to/exitlag_linux/shim/exitlag-game.sh %command%
set -euo pipefail
if [[ $# -lt 1 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi
exec systemd-run --user --slice=exitlag.slice --scope --collect -q -- "$@"
