"""Gets the ESP32-S2 out of the ROM USB bootloader without a button: arms the RTC watchdog (full reset,
which reads the strap pins again). Only works if BOOT (GPIO0) is already released.
Usage: python reset_wdt.py PORT"""
import sys
import esptool

RTC = 0x3F408000
WDTCONFIG0, WDTCONFIG1, WDTWPROTECT, OPTION1 = RTC + 0x94, RTC + 0x98, RTC + 0xAC, RTC + 0x128
esp = esptool.cmds.detect_chip(sys.argv[1], 115200, "no_reset")
strap = esp.read_reg(0x3F404038)  # GPIO_STRAP_REG
print(f"strap at boot = {strap:#x} (GPIO0 was {'low' if not strap & 0x8 else 'high'} at the last reset)")
esp.write_reg(OPTION1, 0)  # no forced download mode
esp.write_reg(WDTWPROTECT, 0x50D83AA1)
esp.write_reg(WDTCONFIG1, 2000)
esp.write_reg(WDTCONFIG0, (1 << 31) | (4 << 28) | (7 << 16) | (7 << 13))
esp.write_reg(WDTWPROTECT, 0)
print("RTC watchdog armed: the chip resets in a moment")
