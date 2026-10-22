"""Tira o ESP32-S2 do bootloader da ROM USB sem botão: arma o watchdog RTC (reset completo, que relê os
pinos de strap). Só funciona se o BOOT (GPIO0) já estiver solto. Uso: python reset_wdt.py PORTA"""
import sys
import esptool

RTC = 0x3F408000
WDTCONFIG0, WDTCONFIG1, WDTWPROTECT, OPTION1 = RTC + 0x94, RTC + 0x98, RTC + 0xAC, RTC + 0x128
esp = esptool.cmds.detect_chip(sys.argv[1], 115200, "no_reset")
strap = esp.read_reg(0x3F404038)  # GPIO_STRAP_REG
print(f"strap no boot = {strap:#x} (GPIO0 era {'baixo' if not strap & 0x8 else 'alto'} no último reset)")
esp.write_reg(OPTION1, 0)  # sem download forçado
esp.write_reg(WDTWPROTECT, 0x50D83AA1)
esp.write_reg(WDTCONFIG1, 2000)
esp.write_reg(WDTCONFIG0, (1 << 31) | (4 << 28) | (7 << 16) | (7 << 13))
esp.write_reg(WDTWPROTECT, 0)
print("watchdog RTC armado: o chip reinicia em instantes")
