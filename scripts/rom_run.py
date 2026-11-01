# /// script
# dependencies = ["pyusb", "esptool==4.7.0"]
# ///
"""Rescue without a button: if the ESP32-S2 is stuck in the ROM USB bootloader (303a:0002) because
the GPIO0 strap was latched low at a power-on with BOOT held, unblock the USB (bus reset through
libusb) and tell the ROM to run the app from flash ("run user code"). Only a power-on without BOOT
fixes it for good. Usage: uv run scripts/rom_run.py"""
import sys, time
import usb.core, usb.backend.libusb1
import esptool
from serial.tools import list_ports

be = usb.backend.libusb1.get_backend(find_library=lambda x: "/opt/homebrew/lib/libusb-1.0.0.dylib")
d = usb.core.find(idVendor=0x303A, idProduct=0x0002, backend=be)
if d is None:
    sys.exit("ESP is not in the ROM USB bootloader (303a:0002)")
try:
    d.reset()
except Exception as e:
    print("USB reset:", e)
time.sleep(2)
ports = [p.device for p in list_ports.comports() if p.vid == 0x303A and p.pid == 0x0002]
if not ports:
    sys.exit("ROM port disappeared after the USB reset")
esp = esptool.cmds.detect_chip(ports[0], 115200, "no_reset", connect_attempts=5)
strap = esp.read_reg(0x3F404038)
esp.flash_begin(0, 0)
esp.flash_finish(False)  # FLASH_END with "run user code"
print(f"run sent (strap={strap:#x}); the app should start within seconds")
