# /// script
# dependencies = ["pyusb", "esptool==4.7.0"]
# ///
"""Socorro sem botão: se o ESP32-S2 caiu no bootloader da ROM USB (303a:0002) porque o strap do GPIO0
ficou travado em baixo desde o power-on com BOOT apertado, destrava a USB (reset de barramento pelo
libusb) e manda a ROM rodar o app da flash ("run user code"). Só um power-on sem BOOT resolve de vez.
Uso: uv run scripts/rom_run.py"""
import sys, time
import usb.core, usb.backend.libusb1
import esptool
from serial.tools import list_ports

be = usb.backend.libusb1.get_backend(find_library=lambda x: "/opt/homebrew/lib/libusb-1.0.0.dylib")
d = usb.core.find(idVendor=0x303A, idProduct=0x0002, backend=be)
if d is None:
    sys.exit("ESP não está no bootloader da ROM USB (303a:0002)")
try:
    d.reset()
except Exception as e:
    print("reset USB:", e)
time.sleep(2)
ports = [p.device for p in list_ports.comports() if p.vid == 0x303A and p.pid == 0x0002]
if not ports:
    sys.exit("porta da ROM sumiu depois do reset USB")
esp = esptool.cmds.detect_chip(ports[0], 115200, "no_reset", connect_attempts=5)
strap = esp.read_reg(0x3F404038)
esp.flash_begin(0, 0)
esp.flash_finish(False)  # FLASH_END com "run user code"
print(f"run enviado (strap={strap:#x}); o app deve subir em segundos")
