#!/usr/bin/env bash
# GRAVA pela USB (só com alguém na bancada; depois tudo por OTA). Apaga a flash e grava bootloader + partições +
# firmware. Exige backup em backup/ (scripts/usb_backup.sh).
# Pré-requisito: devboard na USB-C do Mac em modo download da ROM (segurar BOOT ao plugar).
# Depois de gravar: desplugar e replugar SEM apertar nada (o strap do GPIO0 só é relido no power-on).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/idf_env.sh"
ls "$ROOT"/backup/*_flash_*MB.bin >/dev/null 2>&1 || { echo "✗ sem backup em backup/: rode scripts/usb_backup.sh antes"; exit 1; }
"$ROOT/scripts/build.sh"
# A ROM USB do S2 às vezes para de responder entre chamadas: destrava com reset de barramento e repete
esp() { for i in 1 2 3 4; do uv run -q "$ROOT/scripts/usb_reset.py" >/dev/null; esptool "$@" && return 0; echo "… nova tentativa"; done; return 1; }
PORT="$("$IDF_PYTHON" "$ROOT/scripts/find_port.py")"
echo "▶ Porta: $PORT"
cd "$ROOT/firmware/build"
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset erase_flash
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset write_flash @flash_args
echo "OK: gravado. Agora desplugue e replugue a devboard SEM apertar nada (ou ligue no carregador)."
