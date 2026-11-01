#!/usr/bin/env bash
# Compila e grava o firmware no analisador PELA REDE (o Mac envia o .bin por HTTP POST para
# logic-s2.local/ota). Confere a versão depois do reboot. O novo firmware só é validado se
# subir a rede; senão o ESP volta sozinho ao anterior em ~3 min (rollback).
# Uso: ./ota_update.sh            (versão em firmware/version.txt)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
"$ROOT/scripts/build.sh"
VER="$(tr -d '[:space:]' < "$ROOT/firmware/version.txt")"
echo "▶ OTA pela rede, versão $VER"
cd "$ROOT"
uv run -q agent/analyzer.py ota firmware/build/s2la.bin --expect "$VER"
