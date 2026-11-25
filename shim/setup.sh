#!/usr/bin/env bash
# One-time setup: extract the official ExitLag installer, build the shims and
# prepare the dedicated Wine prefix (nfextlag service + nfapi.dll backup).
#
#   usage: shim/setup.sh /path/to/ExitLag-installer.exe
#
# Safe to re-run: every step is skipped when already done.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/extracted/app"
WP="$ROOT/_tools/wineprefix"
XWIN="$ROOT/_tools/xwin"
INSTALLER="${1:-}"

step() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

step "Checking tools"
missing=()
INNOEXTRACT="${INNOEXTRACT:-$(command -v innoextract || echo "$ROOT/_tools/innoextract/build/innoextract")}"
[[ -x "$INNOEXTRACT" ]] || missing+=("innoextract")
for t in wine wineserver clang clang-cl lld-link g++ pkg-config nft ip systemd-run pkexec; do
  command -v "$t" >/dev/null 2>&1 || missing+=("$t")
done
pkg-config --exists libbpf 2>/dev/null || missing+=("libbpf (dev headers)")
[[ ${#missing[@]} -eq 0 ]] || die "missing: ${missing[*]}"
echo "ok"

step "Extracting ExitLag"
if [[ -f "$APP/ExitLag.exe" ]]; then
  echo "already extracted: $APP"
else
  [[ -n "$INSTALLER" && -f "$INSTALLER" ]] || die "pass the ExitLag installer .exe (Inno Setup) as the first argument"
  mkdir -p "$ROOT/extracted"
  "$INNOEXTRACT" -s -d "$ROOT/extracted" "$INSTALLER"
  [[ -f "$APP/ExitLag.exe" ]] || die "innoextract did not produce $APP/ExitLag.exe"
fi

step "Backing up the original nfapi.dll"
if [[ -f "$APP/nfapi.dll.orig" ]]; then
  echo "already backed up"
else
  cp -n "$APP/nfapi.dll" "$APP/nfapi.dll.orig"
  echo "saved $APP/nfapi.dll.orig"
fi

step "Building"
[[ -d "$XWIN/crt" && -d "$XWIN/sdk" ]] || die "MSVC CRT/SDK not found in $XWIN.
  Install xwin (cargo install xwin) and run:
    xwin --accept-license splat --output \"$XWIN\""
"$ROOT/shim/build_nf.sh"
"$ROOT/shim/linux/build.sh"

step "Preparing Wine prefix ($WP)"
export WINEPREFIX="$WP" WINEDEBUG=-all
if [[ ! -f "$WP/system.reg" ]]; then
  mkdir -p "$WP"
  wineboot -i
  wineserver -w
fi
cp -f "$ROOT/shim/build/nfextlag_svc.exe" "$WP/drive_c/windows/system32/nfextlag_svc.exe"
if wine sc query nfextlag >/dev/null 2>&1; then
  echo "nfextlag service already registered"
else
  wine sc create nfextlag binpath= 'C:\windows\system32\nfextlag_svc.exe' type= own start= auto
fi
wineserver -w

mkdir -p "$ROOT/shim/state"
chmod 700 "$ROOT/shim/state"

cat <<EOF

Setup done. Start ExitLag with:
  $ROOT/shim/run_exitlag.sh --verbose
EOF
