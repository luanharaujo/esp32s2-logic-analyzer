#!/usr/bin/env bash
# Builds the firmware and flashes it OVER THE NETWORK: the .bin goes by HTTP POST to
# logic-s2.local/ota, then the version is checked after the reboot. The new image is only
# marked valid once the network comes up; if not, the ESP rolls back on its own in ~3 min.
# Usage: ./ota_update.sh            (version from firmware/version.txt)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
"$ROOT/scripts/build.sh"
VER="$(tr -d '[:space:]' < "$ROOT/firmware/version.txt")"
echo "▶ OTA over the network, version $VER"
cd "$ROOT"
uv run -q agent/analyzer.py ota firmware/build/s2la.bin --expect "$VER"
