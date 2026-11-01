"""Imprime a porta serial do ESP32-S2 na USB nativa (VID 0x303A, Espressif). Sai com erro se não houver
exatamente uma. O ST-Link (VID 0x0483) e outros seriais são ignorados, e o teclado USB (303a:4017) também."""
import sys
from serial.tools import list_ports

# 0x4017 = teclado USB (ESP32-S3 do teclado virtual): nunca mexer nele
ports = [p for p in list_ports.comports() if p.vid == 0x303A and p.pid != 0x4017]
for p in ports:
    print(f"# {p.device} VID:PID={p.vid:04x}:{p.pid:04x} {p.description}", file=sys.stderr)
if len(ports) != 1:
    print(f"esperava 1 porta Espressif (303a), achei {len(ports)}", file=sys.stderr)
    sys.exit(1)
print(ports[0].device)
