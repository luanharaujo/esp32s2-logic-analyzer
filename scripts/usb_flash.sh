#!/usr/bin/env bash
# FLASHES over USB (first time only; after that, everything goes by OTA). Erases the flash and
# writes bootloader + partition table + firmware. Requires a backup in backup/ (scripts/usb_backup.sh).
# Before running: devboard on USB-C in ROM download mode (hold BOOT while plugging in).
# After flashing: unplug and plug back in WITHOUT pressing anything (GPIO0 strap is only read at power-on).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/idf_env.sh"
ls "$ROOT"/backup/*_flash_*MB.bin >/dev/null 2>&1 || { echo "✗ no backup in backup/: run scripts/usb_backup.sh first"; exit 1; }
"$ROOT/scripts/build.sh"
# The S2 ROM USB sometimes stops answering between calls: a bus reset unblocks it, then retry.
esp() { for i in 1 2 3 4; do uv run -q "$ROOT/scripts/usb_reset.py" >/dev/null; esptool "$@" && return 0; echo "… retrying"; done; return 1; }
PORT="$("$IDF_PYTHON" "$ROOT/scripts/find_port.py")"
echo "▶ Port: $PORT"
cd "$ROOT/firmware/build"
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset erase_flash
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset write_flash @flash_args
echo "OK: flashed. Now unplug and plug the devboard back in WITHOUT pressing anything (or use a USB charger)."
