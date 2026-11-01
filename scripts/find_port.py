"""Prints the serial port of the ESP32-S2 on native USB (VID 0x303A, Espressif). Exits with an error
unless there is exactly one. ST-Link (VID 0x0483) and other serial ports are skipped, and so is
303a:4017 (an ESP32-S3 used as a USB keyboard on the same host)."""
import sys
from serial.tools import list_ports

# 0x4017: the ESP32-S3 USB keyboard. Never touch it.
ports = [p for p in list_ports.comports() if p.vid == 0x303A and p.pid != 0x4017]
for p in ports:
    print(f"# {p.device} VID:PID={p.vid:04x}:{p.pid:04x} {p.description}", file=sys.stderr)
if len(ports) != 1:
    print(f"expected 1 Espressif port (303a), found {len(ports)}", file=sys.stderr)
    sys.exit(1)
print(ports[0].device)
