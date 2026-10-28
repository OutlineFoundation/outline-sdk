#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${CLANG:=clang-19}"
: "${WASM_LD:=wasm-ld-19}"
: "${VARIANT:=1}"
: "${FAULT:=0}"
: "${OUT:=bundle.wasm}"
"$CLANG" --target=wasm32-unknown-unknown -std=c11 -Oz -nostdlib -fno-builtin \
  -DVARIANT="$VARIANT" -DFAULT="$FAULT" -Werror -Wall -Wextra -c bundle.c -o "$OUT.o"
trap 'rm -f "$OUT.o"' EXIT
"$WASM_LD" --no-entry --export-dynamic --export-memory --initial-memory=131072 \
  --max-memory=16777216 --strip-all "$OUT.o" -o "$OUT"
sha256sum "$OUT"
