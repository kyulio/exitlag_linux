#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/shim/build"
mkdir -p "$OUT"

g++ -std=c++20 -O2 -Wall -Wextra -pthread \
  "$ROOT/shim/linux/exitlag_nf_redir.cpp" \
  -o "$OUT/exitlag-nf-redir" -lbpf
echo "built $OUT/exitlag-nf-redir"

clang -O2 -g -target bpf -c "$ROOT/shim/linux/exitlag_direct.bpf.c" \
  -o "$OUT/exitlag_direct.bpf.o"
echo "built $OUT/exitlag_direct.bpf.o"
