#!/usr/bin/env bash
# GRAVA pela USB (só na 1a vez; depois tudo por OTA). Apaga a flash inteira (Marauder) e grava
# bootloader + partições + firmware. Rodar só depois de scripts/usb_backup.sh.
# Pré-requisito: devboard na USB-C do Mac em modo download da ROM (segurar BOOT ao plugar).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/idf_env.sh"
# A porta USB da ROM do S2 fica ocupada alguns instantes entre uma chamada e outra do esptool: repete
esp() { for i in 1 2 3 4 5; do esptool "$@" && return 0; echo "… porta ocupada, nova tentativa em 3 s"; sleep 3; done; return 1; }
ls "$ROOT"/backup/*_flash_*MB.bin >/dev/null 2>&1 || { echo "✗ sem backup em backup/: rode scripts/usb_backup.sh antes"; exit 1; }
"$ROOT/scripts/build.sh"
PORT="$("$IDF_PYTHON" "$ROOT/scripts/porta_esp.py")"
echo "▶ Porta: $PORT"
cd "$ROOT/firmware/build"
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset erase_flash
# A ROM USB pode reenumerar depois do erase; reacha a porta
sleep 2; PORT="$("$IDF_PYTHON" "$ROOT/scripts/porta_esp.py")"
esp --chip esp32s2 -p "$PORT" --before no_reset --after watchdog_reset write_flash @flash_args
echo "OK: gravado. Se o LED não mudar em 5 s, aperte RESET na devboard."
