#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p ../testdata
VARIANT=1 OUT=bundle.wasm sh ./build.sh
VARIANT=2 OUT=bundle-v2.wasm sh ./build.sh
FAULT=1 OUT=../testdata/loop.wasm sh ./build.sh
FAULT=2 OUT=../testdata/trap.wasm sh ./build.sh
