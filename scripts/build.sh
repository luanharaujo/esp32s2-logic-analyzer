#!/usr/bin/env bash
# Builds the firmware without flashing. Output: firmware/build/s2la.bin
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/idf_env.sh"
cd "$ROOT/firmware"
if [ ! -f build/CMakeCache.txt ]; then
    idf set-target esp32s2 > build.log 2>&1 || { tail -20 build.log; exit 1; }
fi
idf build > build.log 2>&1 || { grep -E "error|Error" build.log | head -30; exit 1; }
grep -E "warning:" build.log | grep -v "IDF_TARGET" | head -20 || true
ls -l build/s2la.bin
