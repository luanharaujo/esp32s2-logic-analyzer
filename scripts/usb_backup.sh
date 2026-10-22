#!/usr/bin/env bash
# SÓ LEITURA. Identifica o ESP32-S2 na USB e faz backup da flash inteira em backup/.
# Pré-requisito: devboard na USB-C do Mac em modo download da ROM (segurar BOOT ao plugar).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/idf_env.sh"
# A porta USB da ROM do S2 fica ocupada alguns instantes entre uma chamada e outra do esptool: repete
esp() { for i in 1 2 3 4 5; do esptool "$@" && return 0; echo "… porta ocupada, nova tentativa em 3 s"; sleep 3; done; return 1; }
PORT="$("$IDF_PYTHON" "$ROOT/scripts/porta_esp.py")"
echo "▶ Porta: $PORT"
mkdir -p "$ROOT/backup"
TS="$(date +%Y%m%d_%H%M%S)"
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset chip_id 2>&1 | tee "$ROOT/backup/${TS}_chip_id.txt"
esp --chip esp32s2 -p "$PORT" --before no_reset --after no_reset flash_id 2>&1 | tee "$ROOT/backup/${TS}_flash_id.txt"
SIZE_MB="$(grep -Eo 'Detected flash size: [0-9]+MB' "$ROOT/backup/${TS}_flash_id.txt" | grep -Eo '[0-9]+' || echo 4)"
echo "▶ Backup de ${SIZE_MB} MB (alguns minutos)..."
# read_flash do esptool dá "Corrupt data" na USB da ROM do S2: leitura própria em blocos com MD5
"$IDF_PYTHON" "$ROOT/scripts/ler_flash.py" "$PORT" "$ROOT/backup/${TS}_flash_${SIZE_MB}MB.bin" "$((SIZE_MB * 1048576))"
shasum -a 256 "$ROOT/backup/${TS}_flash_${SIZE_MB}MB.bin" | tee "$ROOT/backup/${TS}_flash.sha256"
strings -n 8 "$ROOT/backup/${TS}_flash_${SIZE_MB}MB.bin" | grep -iE "marauder|blackmagic|version|v[0-9]+\.[0-9]+\.[0-9]+" | head -20 > "$ROOT/backup/${TS}_strings.txt" || true
echo "▶ Pistas do firmware antigo:"; head -10 "$ROOT/backup/${TS}_strings.txt"
echo "OK: backup em $ROOT/backup/"
