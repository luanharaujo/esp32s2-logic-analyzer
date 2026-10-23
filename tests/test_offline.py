# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.2,<2"]
# ///
"""Testes sem hardware: um ESP falso (HTTP local) responde como o firmware; confere CLI, análise e OTA.
Uso: uv run tests/test_offline.py"""
import hashlib, json, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
import analyzer  # noqa: E402

HZ = 240_000_000
TOKEN = analyzer.TOKEN_FILE.read_text().strip()
state = {"boot": 1, "fw": "0.2.0", "t0": time.time(), "gen": None}


PATTERN = [3, 5, 12, 8, 40, 25, 20000, 4, 6, 15, 10, 60]


def fake_combined(q: dict, ms: int) -> str:
    """Captura combinada: IO10 digital (cai em 0, sobe em 300 µs, cai de vez em 600 µs) e o mesmo nó no
    ADC (IO1, 20 kHz) desde 1 ms antes do trigger, com as amostras atrasadas até 1 período."""
    lines = [f"# gpio_edges v1 mode=s2dedic cpu_hz={HZ} ms={ms} pull=none trigger=IO10 edge=fall tmode=poll pins=IO10",
             "# initial IO10=1", "cycles,pin,level", "0,IO10,0", f"{300 * 240},IO10,1", f"{600 * 240},IO10,0",
             "# end edges=3 overflow=0 max_gap_cycles=22 status=ok loops=1 max_edges=1 buf=psram wait_ms=10 err="]
    rate = int(q["adc_rate"][0]); per = 96 * (2_500_000 // rate)
    lines.append(f"# adc_samples v1 pin={q['adc_pin'][0]} gpio=1 header_pin=10 unit=1 ch=0 atten_range_mv=2500 rate={rate} "
                 f"rate_real={2_500_000 / (2_500_000 // rate):.1f} bits=12 cal=nominal t0=digital chain=3070")
    lines.append("cycles,raw,mv")
    n = 0
    c = -1000 * 240 + 77
    while c <= ms * 1000 * 240:
        us = c / 240
        lv = 0 if (0 <= us < 300 or us >= 600) else 1
        raw = 4095 if lv else 30
        lines.append(f"{c},{raw},{raw * 2500 // 4095}")
        c += per; n += 1
    lines.append(f"# adc_end samples={n} wanted={n} chain=3070 invalid=0 period_cycles={per} first_cycles={-1000 * 240 + 77} slice_ms=50")
    return "\n".join(lines) + "\n"


def fake_csv(q: dict) -> str:
    ms = int(q.get("ms", ["100"])[0])
    if q.get("adc_pin"):
        return fake_combined(q, ms)
    if state.get("bounce") and q.get("pins", [""])[0] == "IO10":  # rajada do gerador, borda a borda
        state["bounce"] = False
        lines = [f"# gpio_edges v1 mode=s2dedic cpu_hz={HZ} ms={ms} pull=none trigger=IO10 edge=fall pins=IO10",
                 "# initial IO10=1", "cycles,pin,level"]
        t, lv = 0, 0
        for d in PATTERN:
            lines.append(f"{t},IO10,{lv}")
            t += d * HZ // 1_000_000
            lv ^= 1
        lines.append(f"# end edges={len(PATTERN)} overflow=0 max_gap_cycles=22 status=ok loops=1 max_edges=1 wait_ms=800 err=")
        return "\n".join(lines) + "\n"
    if state.get("sq") and q.get("pins", [""])[0] == "IO11":  # 10 kHz, 30 %
        lines = [f"# gpio_edges v1 mode=s2dedic cpu_hz={HZ} ms={ms} pull=none trigger=none edge=any pins=IO11",
                 "# initial IO11=0", "cycles,pin,level"]
        per = HZ // 10000
        for k in range(ms * 10):
            lines.append(f"{k * per},IO11,1"); lines.append(f"{k * per + per * 3 // 10},IO11,0")
        lines.append("# end edges=1 overflow=0 max_gap_cycles=22 status=ok loops=1 max_edges=1 err=")
        return "\n".join(lines) + "\n"
    trig = q.get("trigger", ["none"])[0]
    lines = [f"# gpio_edges v1 mode=s2dedic cpu_hz={HZ} ms={ms} pull=up trigger={trig} edge=fall pins=IO10,IO11",
             "# initial IO10=1 IO11=0", "cycles,pin,level"]
    t, lv = 0, 0  # bounce no IO10: 6 transições em ~300 µs, depois estável
    for w_us in [0, 2.5, 10, 40, 120, 130]:
        t += int(w_us * HZ / 1e6)
        lines.append(f"{t},IO10,{lv}")
        lv ^= 1
    if state["gen"]:  # onda de 1 kHz, 50% no IO11
        for k in range(2 * ms):
            lines.append(f"{k * HZ // 2000 + 7},IO11,{(k + 1) % 2}")
    n = len(lines) - 3
    lines.append(f"# end edges={n} overflow=0 max_gap_cycles=24 status=ok loops={ms * 10000} max_edges=20000 wait_ms=812 err=")
    return "\n".join(lines) + "\n"


def fake_adc(q: dict):
    """Botão no IO10 (pull-up 10 kΩ a 3,3 V, satura em 4095) com ruído de 60 Hz de 30 mV e um aperto com
    bounce lento: cai em 2 ms, volta em 2,3 ms, cai de vez em 2,6 ms."""
    import math
    pin = q.get("pin", ["IO10"])[0]
    if pin in ("IO11", "IO12", "IO13", "IO17", "IO18"):
        return None
    rate, ms = int(q.get("rate", ["83333"])[0]), int(q.get("ms", ["100"])[0])
    n = ms * rate // 1000
    lines = [f"# adc_samples v1 pin={pin} gpio=10 header_pin=5 unit=1 ch=9 atten=11 range_mv=2500 rate={rate} bits=12 "
             "cal=nominal trig_mv=-1 edge=none pre=0", "us,raw,mv"]
    for k in range(n):
        t = k / rate
        low = 2e-3 <= t < 2.3e-3 or t >= 2.6e-3
        mv = (40 if low else 2600) + 30 * math.sin(2 * math.pi * 60 * t)
        raw = max(0, min(4095, round(mv * 4095 / 2500)))
        lines.append(f"{k * 1e6 / rate:.1f},{raw},{raw * 2500 // 4095}")
    lines.append(f"# end samples={n} sps_measured={rate - 3} invalid=0 overflow=0 trig_index=-1 status=ok wait_ms={ms} err=")
    return "\n".join(lines) + "\n"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/status":
            self.reply(200, json.dumps({"ok": True, "fw": state["fw"], "boot": state["boot"], "partition": "ota_1",
                                        "uptime_s": int(time.time() - state["t0"]), "reset_detail": "",
                                        "ota_pending_verify": False}))
        elif u.path == "/capture":
            self.reply(200, fake_csv(q), "text/csv")
        elif u.path == "/adc":
            body = fake_adc(q)
            if body is None:
                self.reply(400, "pino do ADC2 (conflita com o Wi-Fi); use IO10, IO1 ou IO2 (ADC1)", "text/plain")
            else:
                self.reply(200, body, "text/csv")
        elif u.path == "/levels":
            self.reply(200, json.dumps({"ok": True, "raw": 1, "ch": {c: int(i == 0) for i, c in enumerate(analyzer.CHANNELS)}}))
        elif u.path == "/channels":
            self.reply(200, json.dumps({"ok": True, "channels": [{"name": c} for c in analyzer.CHANNELS]}))
        else:
            self.reply(404, "{}")

    def do_POST(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if self.headers.get("X-Token") != TOKEN:
            return self.reply(403, '{"ok":false,"err":"token"}')
        n = int(self.headers.get("Content-Length", 0)); d = self.rfile.read(n)
        if u.path == "/gen":
            if q.get("mode", ["square"])[0] == "bounce":
                state["bounce"] = True
                return self.reply(200, json.dumps({"ok": True, "gen": q["pin"][0], "mode": "bounce", "pattern_us": PATTERN}))
            state["gen"] = int(q["hz"][0]) > 0
            state["sq"] = q["pin"][0] == "IO11" and int(q["hz"][0]) == 10000
            self.reply(200, json.dumps({"ok": True, "gen": q["pin"][0]}))
        elif u.path == "/ota":
            if hashlib.sha256(d).hexdigest() != self.headers.get("X-SHA256"):
                return self.reply(400, "sha")
            self.reply(200, '{"ok":true}')
            state.update(boot=state["boot"] + 1, fw="0.2.1", t0=time.time())


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
host = f"127.0.0.1:{srv.server_address[1]}"
an = analyzer.Analyzer(host)
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("ok   " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""))
    fails += not cond


st = an.status(); check("status", st["fw"] == "0.2.0")
check("levels", an.levels("up")["ch"]["IO10"] == 1)
check("gen", an.gen("IO11", 1000)["ok"])
res = an.capture(ms=100, trigger="IO10", edge="fall", pull="up", tag="teste")
io10 = res["pins"]["IO10"]
check("bounce: 1 evento", len(io10["events"]) == 1, io10)
ev = io10["events"][0]
check("bounce: 6 transições", ev["transitions"] == 6, ev)
check("bounce: duração 302,5 µs", abs(ev["bounce_us"] - 302.5) < 0.01, ev)
check("bounce: menor pulso 2,5 µs", abs(ev["min_pulse_us"] - 2.5) < 0.01, ev)
io11 = res["pins"]["IO11"]
check("gerador: 1 kHz", abs(io11.get("freq_hz", 0) - 1000) < 1, io11)
check("gerador: duty 50%", abs(io11.get("duty_pct", 0) - 50) < 1, io11)
check("período médio de amostra", res.get("mean_sample_period_us") == 0.1, res.get("mean_sample_period_us"))
csv_path = Path(res["csv_local"])
check("CSV salvo", csv_path.exists())
off = json.loads(subprocess.run(["uv", "run", "-q", str(ROOT / "agent/analyzer.py"), "analyze", str(csv_path)],
                                capture_output=True, text=True).stdout)
check("analyze offline igual", off["pins"]["IO10"]["events"][0]["transitions"] == 6)
csv_path.unlink()
ad = an.adc(pin="IO10", ms=50, rate=20000, tag="teste_adc")
check("adc: 1000 amostras", ad["samples"] == 1000, ad)
check("adc: taxa medida", ad["sps_measured"] == 19997, ad)
check("adc: satura no alto", ad["saturated_pct"] > 0 and ad["max_mv"] == 2500, ad)
check("adc: 3 cruzamentos (bounce lento)", ad["crossings"] == 3, ad)
check("adc: bounce dura 600 µs", abs(ad.get("cross_span_us", 0) - 600) < 60, ad)
check("adc: ruído de 60 Hz", 15 < ad.get("tone_60hz_mv", 0) < 45, ad)
adc_path = Path(ad["csv_local"])
off = json.loads(subprocess.run(["uv", "run", "-q", str(ROOT / "agent/analyzer.py"), "analyze-adc", str(adc_path)],
                                capture_output=True, text=True).stdout)
check("analyze-adc offline igual", off["crossings"] == 3, off)
adc_path.unlink()
try:
    an.adc(pin="IO11"); check("adc: ADC2 recusado", False)
except analyzer.AnalyzerError as e:
    check("adc: ADC2 recusado", "ADC2" in str(e), e)
cb = an.capture(ms=20, trigger="IO10", edge="fall", adc_pin="IO1", adc_rate=20000, tag="teste_comb")
check("combinada: digital intacto", cb["pins"]["IO10"]["events"][0]["transitions"] == 3, cb["pins"]["IO10"])
cmp_ = cb.get("compare", {})
check("combinada: 3 cruzamentos no ADC", cmp_.get("adc_crossings") == 3, cmp_)
check("combinada: atraso < 1 amostra", 0 <= cmp_.get("first_lag_us", -1) <= 50, cmp_)
check("combinada: pré-trigger negativo", cmp_.get("adc_from_us", 0) < -900, cmp_)
check("combinada: duração igual", abs(cmp_.get("adc_span_us", 0) - cmp_.get("digital_span_us", 0)) <= 50, cmp_)
check("combinada: taxa real", cb["adc"]["rate_sps"] == 20000.0, cb["adc"])
comb_path = Path(cb["csv_local"])
off = json.loads(subprocess.run(["uv", "run", "-q", str(ROOT / "agent/analyzer.py"), "analyze", str(comb_path)],
                                capture_output=True, text=True).stdout)
check("analyze offline combinada", off["compare"]["adc_crossings"] == 3, off.get("compare"))
comb_path.unlink()
st = an.selftest()
check("selftest bounce", st["bounce"]["ok"], st["bounce"])
check("selftest square", st["square"]["ok"], st["square"])
binp = ROOT / "firmware/build/s2la.bin"
if binp.exists():
    r = an.ota(str(binp), expect="0.2.1")
    check("ota", r["ok"] and r["after_fw"] == "0.2.1", r)
# MCP: lista de ferramentas
p = subprocess.Popen(["uv", "run", "-q", str(ROOT / "agent/analyzer.py"), "mcp"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, text=True)
msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {},
         "clientInfo": {"name": "t", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
for m in msgs:
    p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush()
p.stdout.readline()
tools = [t["name"] for t in json.loads(p.stdout.readline())["result"]["tools"]]
p.kill()
check("MCP tools", set(tools) >= {"status", "capture", "levels", "channels", "test_generator", "device_log", "adc"}, tools)
print("FALHAS:", fails)
sys.exit(1 if fails else 0)
