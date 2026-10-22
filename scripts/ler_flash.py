"""Backup da flash pelo USB da ROM do ESP32-S2. O read_flash do esptool falha com 'Corrupt data' na
USB-OTG do S2 (64 pacotes de 4 KB em voo); aqui: pacotes de 1 KB, 1 em voo, blocos de 16 KB conferidos
por MD5 do stub, com repetição. Uso: python ler_flash.py PORTA SAIDA [TAMANHO]"""
import hashlib, struct, sys, time
import esptool
from esptool.util import hexify

port, out = sys.argv[1], sys.argv[2]
size = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x400000
BLOCK, PKT = 0x4000, 0x400

esp = esptool.cmds.detect_chip(port, 115200, "no_reset")
esp = esp.run_stub()

def read_block(off, length):
    esp.check_command("read flash", esp.ESP_READ_FLASH, struct.pack("<IIII", off, length, PKT, 1))
    data = b""
    while len(data) < length:
        p = esp.read()
        if len(p) != PKT:
            raise RuntimeError(f"pacote de {len(p)} bytes")
        data += p
        esp.write(struct.pack("<I", len(data)))
    dig = esp.read()
    if len(dig) != 16 or hexify(dig).upper() != hashlib.md5(data).hexdigest().upper():
        raise RuntimeError("md5 diferente")
    return data

def drain():
    time.sleep(1)
    esp._port.reset_input_buffer()
    try:
        esp.sync()
    except Exception as e:
        print("sync:", e, flush=True)
    esp._port.reset_input_buffer()

data = bytearray()
t0 = time.time()
for off in range(0, size, BLOCK):
    for tent in range(10):
        try:
            data += read_block(off, BLOCK)
            break
        except Exception as e:
            print(f"bloco {off:#x} tentativa {tent+1}: {e}", flush=True)
            drain()
    else:
        open(out + ".parcial", "wb").write(data)
        sys.exit(f"falhou no bloco {off:#x}")
    if (off // BLOCK) % 16 == 15:
        print(f"{(off+BLOCK)*100//size}% em {time.time()-t0:.0f} s", flush=True)
open(out, "wb").write(data)
print("ok sha256", hashlib.sha256(data).hexdigest())
