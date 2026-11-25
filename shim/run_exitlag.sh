#!/usr/bin/env bash
# Launch the official ExitLag.exe GUI on Linux with the drop-in NFSDK->TPROXY shim.
# Usage:
#   ./shim/run_exitlag.sh [--no-tproxy] [--verbose] [--scope uid|cgroup] [logfile]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Wine path (Z:\...) of the extracted ExitLag app directory
WINEPATH_APP="Z:${ROOT//\//\\}\\extracted\\app"
S="$ROOT/shim/state"
mkdir -p "$S"
chmod 700 "$S"

NO_TPROXY=0
VERBOSE=0
# uid (default, Windows-like): every process of this user is seen; Wine/Proton
# processes (games) are decided per connection by ExitLag, native Linux processes
# go direct and get kernel-bypassed by eBPF after their first socket.
# cgroup: only processes started via shim/exitlag-game.sh (exitlag.slice).
SCOPE="uid"
LOG_NAME="exitlag_official.log"
REDIR_LOG="$S/exitlag_nf_redir.log"
ROOT_PIDFILE="$S/exitlag_nf_root.pid"
ROOT_STOPFILE="$S/exitlag_nf_root.stop"
IPC_ADDR="${EXITLAG_NF_IPC:-127.0.0.1:19850}"
NF_LOG="$S/nfapi_shim.log"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-tproxy) NO_TPROXY=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    --scope) SCOPE="$2"; shift 2 ;;
    --restore-nfapi)
      if [[ -f "$ROOT/extracted/app/nfapi.dll.orig" ]]; then
        cp -f "$ROOT/extracted/app/nfapi.dll.orig" "$ROOT/extracted/app/nfapi.dll"
        echo "restored $ROOT/extracted/app/nfapi.dll from nfapi.dll.orig"
      else
        echo "error: missing $ROOT/extracted/app/nfapi.dll.orig" >&2
        exit 1
      fi
      exit 0
      ;;
    -h|--help)
      echo "usage: $0 [--no-tproxy] [--verbose] [--scope uid|cgroup] [--restore-nfapi] [logfile]"
      exit 0
      ;;
    *) LOG_NAME="$1"; shift ;;
  esac
done

WP="$ROOT/_tools/wineprefix"
APP_DIR="$ROOT/extracted/app"

if [[ ! -f "$APP_DIR/nfapi.dll.orig" ]]; then
  echo "error: missing $APP_DIR/nfapi.dll.orig safety backup" >&2
  exit 1
fi
if [[ ! -f "$ROOT/shim/build/nfapi.dll" ]]; then
  "$ROOT/shim/build_nf.sh"
fi
if [[ "$NO_TPROXY" -eq 0 && ! -x "$ROOT/shim/build/exitlag-nf-redir" ]]; then
  "$ROOT/shim/linux/build.sh"
fi

# Start a fresh wineserver inside exitlagbypass.slice so wineserver, services.exe,
# nfextlag_svc.exe, and ExitLag.exe all live in the bypass cgroup (never TPROXY'd).
# If no wineserver is running yet, systemd-run places it cleanly into exitlagbypass.slice.
ROOT_WRAPPER_PID=""
BYPASS_UNIT_ACTIVE=0

cleanup() {
  if [[ -n "$ROOT_WRAPPER_PID" ]]; then
    touch "$ROOT_STOPFILE" 2>/dev/null || true
    if [[ -f "$ROOT_PIDFILE" ]]; then
      RPID="$(cat "$ROOT_PIDFILE" 2>/dev/null || true)"
      if [[ -n "$RPID" ]]; then
        for _ in $(seq 1 50); do
          [[ -d "/proc/$RPID" ]] || break
          sleep 0.1
        done
        if [[ -d "/proc/$RPID" ]]; then
          pkexec kill -TERM "$RPID" 2>/dev/null || kill -TERM "$RPID" 2>/dev/null || true
        fi
      fi
    fi
    kill "$ROOT_WRAPPER_PID" 2>/dev/null || true
    rm -f "$ROOT_STOPFILE" 2>/dev/null || true
  fi
  if [[ "$BYPASS_UNIT_ACTIVE" -eq 1 ]]; then
    systemctl --user stop exitlag-bypass-anchor.service 2>/dev/null || true
    systemctl --user stop exitlag-target-anchor.service 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Clean up any leftover ExitLag/wineserver outside exitlagbypass.slice so bypass cgroup applies cleanly.
# Wine processes show up as plain "ExitLag.exe" in their cmdline, so match on the
# basename. Also stop the prefix's wineserver so a fresh one starts inside
# exitlagbypass.slice (otherwise a stale single instance swallows the new launch).
if pgrep -f 'ExitLag\.exe' >/dev/null 2>&1; then
  pkill -f 'ExitLag\.exe' 2>/dev/null || true
fi
WINEPREFIX="$WP" wineserver -k 2>/dev/null || true
for _ in $(seq 1 50); do
  pgrep -f 'ExitLag\.exe' >/dev/null 2>&1 || break
  sleep 0.1
done

# Sync built nfapi.dll atomically after stopping any existing ExitLag/Wine instance.
if ! cmp -s "$ROOT/shim/build/nfapi.dll" "$APP_DIR/nfapi.dll" 2>/dev/null; then
  cp -f "$ROOT/shim/build/nfapi.dll" "$APP_DIR/nfapi.dll.tmp"
  mv -f "$APP_DIR/nfapi.dll.tmp" "$APP_DIR/nfapi.dll"
fi

# Materialize exitlagbypass.slice before setting up nftables and launching Wine.
systemctl --user stop exitlag-bypass-anchor.service 2>/dev/null || true
systemd-run --user --slice=exitlagbypass.slice --unit=exitlag-bypass-anchor --collect \
  /bin/sleep 86400 >/dev/null 2>&1 || true
BYPASS_UNIT_ACTIVE=1

# In cgroup scope, keep exitlag.slice (target cgroup for games) alive too:
# nftables resolves the cgroup path when the rule is loaded, so it must exist.
if [[ "$SCOPE" == "cgroup" ]]; then
  systemctl --user stop exitlag-target-anchor.service 2>/dev/null || true
  systemd-run --user --slice=exitlag.slice --unit=exitlag-target-anchor --collect \
    /bin/sleep 86400 >/dev/null 2>&1 || true
fi

UID_NUM="$(id -u)"
BYPASS_CGROUP="user.slice/user-${UID_NUM}.slice/user@${UID_NUM}.service/exitlagbypass.slice"

if [[ "$NO_TPROXY" -eq 0 ]]; then
  rm -f "$ROOT_STOPFILE" 2>/dev/null || true
  ROOT_CMD=(
    "$ROOT/shim/linux/exitlag-nf-root.sh"
    --uid "$UID_NUM"
    --scope "$SCOPE"
    --bypass-cgroup "$BYPASS_CGROUP"
    --ipc "$IPC_ADDR"
    --pidfile "$ROOT_PIDFILE"
    --stop-file "$ROOT_STOPFILE"
    --watch-pid "$$"
  )
  if [[ "$VERBOSE" -eq 1 ]]; then
    ROOT_CMD+=(--verbose)
  fi
  : > "$REDIR_LOG"
  chmod 600 "$REDIR_LOG"
  if command -v pkexec >/dev/null 2>&1; then
    pkexec "${ROOT_CMD[@]}" > "$REDIR_LOG" 2>&1 &
  else
    sudo "${ROOT_CMD[@]}" > "$REDIR_LOG" 2>&1 &
  fi
  ROOT_WRAPPER_PID=$!
  # Up to 120s: leaves time to type the password into the polkit prompt.
  for _ in $(seq 1 1200); do
    if grep -q "NF REDIR READY" "$REDIR_LOG" 2>/dev/null; then
      break
    fi
    # Not `kill -0`: after polkit auth pkexec runs fully as root, so kill -0 from
    # this user fails with EPERM even though it is alive. /proc works for any uid.
    if [[ ! -d "/proc/$ROOT_WRAPPER_PID" ]]; then
      echo "error: exitlag-nf-root failed to start (see $REDIR_LOG)" >&2
      cat "$REDIR_LOG" >&2 || true
      exit 1
    fi
    sleep 0.1
  done
  if ! grep -q "NF REDIR READY" "$REDIR_LOG" 2>/dev/null; then
    echo "error: exitlag-nf-redir not ready after 120s (see $REDIR_LOG)" >&2
    exit 1
  fi
fi

# Ensure nfextlag service is running inside the Wine prefix (under exitlagbypass.slice).
systemd-run --user --slice=exitlagbypass.slice --scope --collect -q \
  env WINEPREFIX="$WP" WINEDEBUG=-all wine sc start nfextlag >/dev/null 2>&1 || true

NF_LOG_WIN="Z:${NF_LOG//\//\\}"
: > "$S/$LOG_NAME"
chmod 600 "$S/$LOG_NAME"
touch "$NF_LOG" && chmod 600 "$NF_LOG"

# --logging always: exitlag-nf-redir reads ExitLag's per-connection app decisions
# from client.log to decide which native processes can bypass TPROXY.
EXITLAG_ARGS=(--skip-update --logging)

cd "$APP_DIR"
# Use ExitLag's bundled opengl32sw.dll (Mesa llvmpipe) via OpenGL RHI so the GUI
# avoids Wine's unimplemented DirectComposition (0x80004001) and NVIDIA DRI2/EGL
# failures that freeze the D3D11 UI at 0%, while still supporting QML shaders/popups.
systemd-run --user --slice=exitlagbypass.slice --scope --collect -q \
  env -i HOME="$HOME" PATH=/usr/bin:/bin \
    DISPLAY="${DISPLAY:-:0}" \
    XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$UID_NUM}" \
    DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$UID_NUM/bus}" \
    WINEPREFIX="$WP" WINEDEBUG=-all \
    WINEPATH="$WINEPATH_APP" \
    EXITLAG_NF_IPC="$IPC_ADDR" \
    EXITLAG_NF_LOG="$NF_LOG_WIN" \
    QSG_RHI_BACKEND="${QSG_RHI_BACKEND:-opengl}" \
    QT_OPENGL="${QT_OPENGL:-software}" \
    QSG_RENDER_LOOP="${QSG_RENDER_LOOP:-basic}" \
    wine ExitLag.exe "${EXITLAG_ARGS[@]}" > "$S/$LOG_NAME" 2>&1
