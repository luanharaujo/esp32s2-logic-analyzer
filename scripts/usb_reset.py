# /// script
# dependencies = ["pyusb"]
# ///
"""USB bus reset of the ESP32-S2 in the ROM bootloader (303a:0002): unblocks the ROM when it stops
answering between esptool sessions. Leaves other USB devices (keyboard, ST-Link) alone."""
import time
import usb.core, usb.backend.libusb1
be = usb.backend.libusb1.get_backend(find_library=lambda x: "/opt/homebrew/lib/libusb-1.0.0.dylib")
d = usb.core.find(idVendor=0x303A, idProduct=0x0002, backend=be)
if d is None:
    print("no ESP in ROM USB mode")
else:
    try:
        d.reset(); print("USB reset ok")
    except Exception as e:
        print("USB reset:", e)
    time.sleep(2)
