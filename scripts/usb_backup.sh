#!/usr/bin/env bash
# READ ONLY. Identifies the ESP32-S2 on USB and backs up the whole flash into backup/.
# Before running: devboard on USB-C in ROM download mode (hold BOOT while plugging in).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/idf_env.sh"
# The S2 ROM USB port stays busy for a moment between esptool calls, so retry.
esp() { for i in 1 2 3 4 5; do esptool "$@" && return 0; echo "… port busy, retrying in 3 s"; sleep 3; done; return 1; }
PORT="$("$IDF_PYTHON" "$ROOT/scripts/find_port.py")"
echo "▶ Port: $PORT"
mkdir -p "$ROOT/backup"
TS="$(date +%Y%m%d_%H%M%S)"
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset chip_id 2>&1 | tee "$ROOT/backup/${TS}_chip_id.txt"
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset flash_id 2>&1 | tee "$ROOT/backup/${TS}_flash_id.txt"
SIZE_MB="$(grep -Eo 'Detected flash size: [0-9]+MB' "$ROOT/backup/${TS}_flash_id.txt" | grep -Eo '[0-9]+' || echo 4)"
echo "▶ Backing up ${SIZE_MB} MB (a few minutes)..."
# esptool read_flash fails with "Corrupt data" on the S2 ROM USB: own block-wise read with MD5 instead.
"$IDF_PYTHON" "$ROOT/scripts/read_flash.py" "$PORT" "$ROOT/backup/${TS}_flash_${SIZE_MB}MB.bin" "$((SIZE_MB * 1048576))"
shasum -a 256 "$ROOT/backup/${TS}_flash_${SIZE_MB}MB.bin" | tee "$ROOT/backup/${TS}_flash.sha256"
strings -n 8 "$ROOT/backup/${TS}_flash_${SIZE_MB}MB.bin" | grep -iE "marauder|blackmagic|version|v[0-9]+\.[0-9]+\.[0-9]+" | head -20 > "$ROOT/backup/${TS}_strings.txt" || true
echo "▶ Hints about the previous firmware:"; head -10 "$ROOT/backup/${TS}_strings.txt"
echo "OK: backup in $ROOT/backup/"
