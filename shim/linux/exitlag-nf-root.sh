#!/usr/bin/env bash
# Root supervisor run via pkexec/sudo: configures TPROXY nftables, runs
# exitlag-nf-redir, and guarantees firewall/route teardown on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NET="$ROOT/shim/linux/exitlag-nf-net.sh"
REDIR="$ROOT/shim/build/exitlag-nf-redir"

UID_NUM="${SUDO_UID:-1000}"
SCOPE="uid"
BYPASS_CGROUP=""
TCP_PORT=12345
UDP_PORT=12345
IPC_ADDR="127.0.0.1:19850"
VERBOSE_FLAG=()
ALIASES_ARG=()
PIDFILE=""
STOP_FILE=""
WATCH_PID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uid) UID_NUM="$2"; shift 2 ;;
    --scope) SCOPE="$2"; shift 2 ;;
    --bypass-cgroup) BYPASS_CGROUP="$2"; shift 2 ;;
    --tcp-port) TCP_PORT="$2"; shift 2 ;;
    --udp-port) UDP_PORT="$2"; shift 2 ;;
    --ipc) IPC_ADDR="$2"; shift 2 ;;
    --proc-aliases) ALIASES_ARG=(--proc-aliases "$2"); shift 2 ;;
    --pidfile) PIDFILE="$2"; shift 2 ;;
    --stop-file) STOP_FILE="$2"; shift 2 ;;
    --watch-pid) WATCH_PID="$2"; shift 2 ;;
    --verbose) VERBOSE_FLAG=(--verbose); shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

WATCHDOG_PID=""
cleanup() {
  if [[ -n "$WATCHDOG_PID" ]]; then
    kill "$WATCHDOG_PID" 2>/dev/null || true
  fi
  if [[ -n "$PIDFILE" ]]; then
    rm -f "$PIDFILE" 2>/dev/null || true
  fi
  if [[ -n "$STOP_FILE" ]]; then
    rm -f "$STOP_FILE" 2>/dev/null || true
  fi
  "$NET" down >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if [[ -n "$STOP_FILE" ]]; then
  rm -f "$STOP_FILE" 2>/dev/null || true
fi
if [[ -n "$PIDFILE" ]]; then
  echo "$$" > "$PIDFILE"
fi

NET_ARGS=(--uid "$UID_NUM" --scope "$SCOPE" --tcp-port "$TCP_PORT" --udp-port "$UDP_PORT")
if [[ -n "$BYPASS_CGROUP" ]]; then
  NET_ARGS+=(--bypass-cgroup "$BYPASS_CGROUP")
fi

"$NET" up "${NET_ARGS[@]}"

# Native-direct: native Linux processes that ExitLag reports as "<no-app>" get
# their sockets marked by eBPF so the kernel bypasses TPROXY for them; apps
# enabled in ExitLag (Steam, YouTube, Discord...) keep going through ExitLag.
# Run as a child, NOT `exec`: exec would replace this shell and the EXIT trap
# ("$NET" down) would never run, leaving TPROXY rules pointing at a dead port
# -> the whole desktop loses internet. Whatever way the redirector ends
# (crash, SIGTERM to this script, Ctrl+C), the rules are removed.
CHILD=""
forward_term() {
  if [[ -n "$CHILD" ]]; then kill -TERM "$CHILD" 2>/dev/null || true; fi
}
trap forward_term INT TERM

"$REDIR" \
  --listen-tcp "127.0.0.1:$TCP_PORT" \
  --listen-udp "127.0.0.1:$UDP_PORT" \
  --ipc "$IPC_ADDR" \
  --bpf-obj "$ROOT/shim/build/exitlag_direct.bpf.o" \
  --bpf-cgroup "/sys/fs/cgroup/user.slice/user-${UID_NUM}.slice" \
  --exitlag-log "$ROOT/extracted/app/client.log" \
  --native-tunnel "$ROOT/shim/state/native_tunnel.txt" \
  "${ALIASES_ARG[@]}" \
  "${VERBOSE_FLAG[@]}" &
CHILD=$!

if [[ -n "$STOP_FILE" || -n "$WATCH_PID" ]]; then
  (
    while kill -0 "$CHILD" 2>/dev/null; do
      if [[ -n "$STOP_FILE" && -f "$STOP_FILE" ]]; then
        kill -TERM "$CHILD" 2>/dev/null || true
        break
      fi
      if [[ -n "$WATCH_PID" && ! -d "/proc/$WATCH_PID" ]]; then
        kill -TERM "$CHILD" 2>/dev/null || true
        break
      fi
      sleep 0.2
    done
  ) &
  WATCHDOG_PID=$!
fi

# First wait returns early when a signal arrives; wait again for the real exit.
wait "$CHILD" || true
wait "$CHILD" 2>/dev/null || true
echo "exitlag-nf-redir exited; removing TPROXY rules"
# EXIT trap (cleanup) runs "$NET" down here.
