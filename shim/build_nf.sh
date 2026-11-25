#!/usr/bin/env bash
# Cross-compile nfextlag_svc.exe and drop-in nfapi.dll shim for x86_64-pc-windows-msvc.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SHIM="$ROOT/shim"
XWIN="$ROOT/_tools/xwin"
OUT="$SHIM/build"
mkdir -p "$OUT"

CXXFLAGS=(
  /nologo /std:c++20 /EHsc /MD /O2 /Zc:__cplusplus /permissive-
  --target=x86_64-pc-windows-msvc
  -fms-compatibility-version=19.44
  /D_WIN32_WINNT=0x0A00 /DWIN32_LEAN_AND_MEAN /DNOMINMAX
  /imsvc "$XWIN/crt/include"
  /imsvc "$XWIN/sdk/include/ucrt"
  /imsvc "$XWIN/sdk/include/um"
  /imsvc "$XWIN/sdk/include/shared"
  -Wno-unused-command-line-argument
)
LDFLAGS_COMMON=(
  /nologo /machine:x64
  /libpath:"$XWIN/crt/lib/x86_64"
  /libpath:"$XWIN/sdk/lib/um/x86_64"
  /libpath:"$XWIN/sdk/lib/ucrt/x86_64"
)

clang-cl "${CXXFLAGS[@]}" /c "$SHIM/src/nfextlag_svc.cpp" /Fo"$OUT/nfextlag_svc.obj"
lld-link "${LDFLAGS_COMMON[@]}" /subsystem:console "$OUT/nfextlag_svc.obj" \
  advapi32.lib kernel32.lib /out:"$OUT/nfextlag_svc.exe"
echo "built $OUT/nfextlag_svc.exe"

if [[ -f "$SHIM/src/nfapi_shim.cpp" ]]; then
  clang-cl "${CXXFLAGS[@]}" /LD /c "$SHIM/src/nfapi_shim.cpp" /Fo"$OUT/nfapi_shim.obj"
  lld-link "${LDFLAGS_COMMON[@]}" /dll /def:"$SHIM/src/nfapi_shim.def" \
    "$OUT/nfapi_shim.obj" ws2_32.lib advapi32.lib kernel32.lib \
    /out:"$OUT/nfapi.dll"
  echo "built $OUT/nfapi.dll"
fi
