# /// script
# dependencies = ["pyusb"]
# ///
"""Reset de barramento USB do ESP32-S2 no bootloader da ROM (303a:0002): destrava a ROM quando ela para
de responder entre sessões do esptool (visto em 22/10/2026). Não mexe no teclado USB nem no ST-Link."""
import time
import usb.core, usb.backend.libusb1
be = usb.backend.libusb1.get_backend(find_library=lambda x: "/opt/homebrew/lib/libusb-1.0.0.dylib")
d = usb.core.find(idVendor=0x303A, idProduct=0x0002, backend=be)
if d is None:
    print("sem ESP na ROM USB")
else:
    try:
        d.reset(); print("reset USB ok")
    except Exception as e:
        print("reset USB:", e)
    time.sleep(2)
