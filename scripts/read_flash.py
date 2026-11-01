"""Flash backup over the ESP32-S2 ROM USB. esptool read_flash fails with 'Corrupt data' on the S2
USB-OTG (64 packets of 4 KB in flight); here: 1 KB packets, 1 in flight, 16 KB blocks checked
against the stub's MD5, with retries. Usage: python read_flash.py PORT OUTPUT [SIZE]"""
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
            raise RuntimeError(f"got a {len(p)} byte packet")
        data += p
        esp.write(struct.pack("<I", len(data)))
    dig = esp.read()
    if len(dig) != 16 or hexify(dig).upper() != hashlib.md5(data).hexdigest().upper():
        raise RuntimeError("md5 mismatch")
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
            print(f"block {off:#x} attempt {tent+1}: {e}", flush=True)
            drain()
    else:
        open(out + ".partial", "wb").write(data)
        sys.exit(f"failed at block {off:#x}")
    if (off // BLOCK) % 16 == 15:
        print(f"{(off+BLOCK)*100//size}% in {time.time()-t0:.0f} s", flush=True)
open(out, "wb").write(data)
print("ok sha256", hashlib.sha256(data).hexdigest())
