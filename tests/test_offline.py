# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.2,<2", "matplotlib>=3.8"]
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


def fake_record_csv() -> str:
    """Gravação contínua: 3 apertos (bounce de 3 bordas + soltura) em 0,5 s, 1,2 s e 2,0 s; depois do
    buffer cheio, 1 rajada só em resumo; janela analógica do 1o evento."""
    C = 240
    lines = ["# gpio_edges v1 mode=s2record cpu_hz=240000000 ms=3000 pull=none trigger=none edge=any tmode=record pins=IO10",
             "# initial IO10=1", "cycles,pin,level"]
    for t_s in (0.5, 1.2, 2.0):
        t0 = int(t_s * 1e6) * C
        for k, (dt, lv) in enumerate([(0, 0), (4, 1), (9, 0), (150000, 1)]):
            lines.append(f"{t0 + dt * C},IO10,{lv}")
    lines.append("# end edges=12 overflow=1 max_gap_cycles=24000 status=buffer_full loops=1 max_edges=12 buf=psram total_edges=20 "
                 "events=4 gaps_over_2us=100 gaps_over_10us=10 gaps_over_100us=3 gaps_over_1ms=0 max_gap_at_ms=1.0 "
                 "bursts_after_full=1 settle_ticks=75000 err=")
    lines.append(f"# burst {int(2.6e6) * C} {int(2.6e6 + 50) * C} 8 0")
    lines.append("# adc_samples v1 pin=IO1 atten_range_mv=2500 rate=10000 rate_real=10000.0 bits=12 t0=digital mode=events "
                 "pre_ms=20 post_ms=80 align=esp_timer")
    lines.append("cycles,raw,mv")
    for k in range(-200, 800):
        c = int(0.5e6 * C) + k * 24000
        lv = 30 if 0 <= k < 1500 else 4095
        lines.append(f"{c},{lv},{lv * 2500 // 4095}")
    lines.append("# adc_end samples=1000 wanted=1000 windows=1 lost_events=0 invalid=0 period_cycles=24000")
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
            if state.get("reboot_on_status"):  # simula panic + rollback durante a série
                state["reboot_on_status"] -= 1
                if state["reboot_on_status"] == 0:
                    state.update(boot=state["boot"] + 1, fw="0.2.3")
            self.reply(200, json.dumps({"ok": True, "fw": state["fw"], "boot": state["boot"], "reset_reason": "panic",
                                        "panic": "assert failed", "partition": "ota_1",
                                        "uptime_s": int(time.time() - state["t0"]), "reset_detail": "",
                                        "ota_pending_verify": False}))
        elif u.path == "/capture":
            state["last_capture_q"] = q
            self.reply(200, fake_csv(q), "text/csv")
        elif u.path == "/adc":
            body = fake_adc(q)
            if body is None:
                self.reply(400, "pino do ADC2 (conflita com o Wi-Fi); use IO10, IO1 ou IO2 (ADC1)", "text/plain")
            else:
                self.reply(200, body, "text/csv")
        elif u.path == "/record/status":
            self.reply(200, json.dumps({"ok": True, "state": "recording", "events": 2, "edges": 8, "last_events_s": [0.5, 1.2]}))
        elif u.path == "/record/data":
            self.reply(200, fake_record_csv(), "text/csv")
        elif u.path == "/levels":
            self.reply(200, json.dumps({"ok": True, "raw": 1, "ch": {c: int(i == 0) for i, c in enumerate(analyzer.CHANNELS)}}))
        elif u.path == "/channels":
            self.reply(200, json.dumps({"ok": True, "channels": [{"name": c} for c in analyzer.CHANNELS]}))
        else:
            self.reply(404, "{}")

    def do_POST(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if self.headers.get("X-Token") != TOKEN and not u.path.startswith("/record"):  # /record não exige token
            return self.reply(403, '{"ok":false,"err":"token"}')
        n = int(self.headers.get("Content-Length", 0)); d = self.rfile.read(n)
        if u.path == "/record":
            state["record_q"] = q
            return self.reply(200, json.dumps({"ok": True, "s": int(q["s"][0]), "max_edges": 250000}))
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
check("combinada: atenuação e status", cb["adc"]["atten_db"] == "11" and cb["adc"]["status"] == "ok", cb["adc"])
old = analyzer.parse_combined_adc("# adc_samples v1 pin=IO1 t0=digital\ncycles,raw,mv\n100,4095,2500\n"
                                  "# adc_end samples=1 wanted=1 chain=1280 invalid=0 period_cycles=24000 first_cycles=100 slice_ms=64\n")
check("combinada: cabeçalho do 0.3.1 (taxa pelo período)", abs(float(old["meta"]["rate"]) - 10000) < 1e-6, old["meta"])
comb_path = Path(cb["csv_local"])
off = json.loads(subprocess.run(["uv", "run", "-q", str(ROOT / "agent/analyzer.py"), "analyze", str(comb_path)],
                                capture_output=True, text=True).stdout)
check("analyze offline combinada", off["compare"]["adc_crossings"] == 3, off.get("compare"))
# plot: painéis manuais (combinada, com zoom em µs) e automático; PNG quadrado 990x990
import matplotlib.pyplot as plt  # noqa: E402
png = analyzer.plot_png([analyzer.parse_panel(f"{comb_path}|-1|20|combinada"),
                         analyzer.parse_panel(f"{comb_path}|-0.05|0.7|zoom")], ROOT / "captures/_teste_plot.png", "teste")
check("plot: PNG 990x990", plt.imread(png).shape[:2] == (990, 990), plt.imread(png).shape)
png.unlink()
auto = analyzer.auto_panels(comb_path)
check("plot --auto: 2 painéis, zoom no 1º evento", len(auto) == 2 and auto[1][1] < 0 < auto[1][2] < 1, auto)
cli = subprocess.run(["uv", "run", "-q", str(ROOT / "agent/analyzer.py"), "plot", "--auto", str(comb_path), "-o",
                      str(ROOT / "captures/_teste_cli.png")], capture_output=True, text=True)
check("plot CLI", cli.returncode == 0 and (ROOT / "captures/_teste_cli.png").exists(), cli.stderr[-300:])
(ROOT / "captures/_teste_cli.png").unlink(missing_ok=True)
comb_path.unlink()
# series: começa no 0.3.4 com ADC; o ESP "reinicia" no 0.2.3 antes da 2a captura -> avisa e adapta
state.update(fw="0.3.4", reboot_on_status=2)
lines = []
sr = analyzer.run_series(an, 2, ms=100, trigger="IO10", timeout_ms=300000, gap_s=0, tag="teste_serie_rb",
                         adc_pin="IO1", out=lines.append)
check("series: detecta reinício", any("reiniciou" in x for x in lines), lines)
check("series: adapta ao fw do rollback", sr["timeout_ms"] == 60000 and sr["adc_pin"] is None
      and state["last_capture_q"]["timeout_ms"] == ["60000"], (sr["timeout_ms"], state["last_capture_q"]))
for c in sr["captures"]:
    Path(c["csv"]).unlink()
for x in sr["png"]:
    Path(x).unlink()
# record (fw >= 0.4.0): 3 eventos completos + 1 só em resumo, PNG, recusa em fw antigo
state.update(fw="0.4.3", reboot_on_status=0)
lines = []
rr = analyzer.run_record(an, s=1, pins="IO10", adc_pin="IO1", tag="teste_rec", live=True, out=lines.append)
check("record: parâmetros", state["record_q"]["s"] == ["1"] and state["record_q"]["adc_pin"] == ["IO1"], state.get("record_q"))
check("record: 7 eventos, 4 apertos (1 em resumo)", len(rr["events"]) == 7 and rr["presses"] == 4
      and rr["events"][6].get("only_summary") and rr["events"][1]["kind"] == "soltura", rr["events"])
check("record: 1º evento 3 bordas em 9 µs", rr["events"][0]["transitions"] == 3 and abs(rr["events"][0]["bounce_us"] - 9) < 0.01,
      rr["events"][0])
check("record: hora de parede", all(len(e["wall"]) == 12 for e in rr["events"]), [e["wall"] for e in rr["events"]])
check("record: eventos ao vivo", sum("evento" in x and "às" in x for x in lines) == 2, lines)
check("record: PNG", rr["png"] and Path(rr["png"]).exists() and plt.imread(rr["png"]).shape[:2] == (990, 990), rr["png"])
ra = analyzer.analyze_any(Path(rr["csv_local"]).read_text())
check("record: ADC por evento sem tom", "tone_60hz_mv" not in ra["adc"] and ra["adc"]["samples"] == 1000, ra["adc"])
check("record: 4 apertos reais", len(rr["real_presses"]) == 4, rr["real_presses"])
gr = analyzer.find_presses(Path(rr["csv_local"]).read_text())
pr = [g for g in gr if g["kind"] == "aperto"]
check("presses: última descida (regra do STM32)", abs(pr[0]["last_fall_us"] - 500009) < 0.01, pr[0])
ml = analyzer.match_laps(gr, [700.0 * 1.0015, 600.0 * 1.0015, 5000.0])
check("presses: voltas e razão de relógio", ml[0]["lap_ms"] == 700.0 and abs(ml[1]["lap_ms"] - 600.05) < 0.01
      and abs(ml[0]["clock_ppm"] - 1500) < 100 and ml[2]["lap_ms"] is None, ml)
png2 = analyzer.plot_presses_png(Path(rr["csv_local"]), gr, ROOT / "captures/_teste_apertos.png")
check("presses: PNG", plt.imread(png2).shape[:2] == (990, 990))
png2.unlink()
Path(rr["csv_local"]).unlink(); Path(rr["png"]).unlink()
state["fw"] = "0.3.4"
try:
    analyzer.run_record(an, s=1, out=lines.append); check("record: recusa fw < 0.4.0", False)
except analyzer.AnalyzerError as e:
    check("record: recusa fw < 0.4.0", "0.4.0" in str(e), e)
state["fw"] = "0.2.0"
# series: firmware 0.2.0 -> timeout limitado a 60 s e sem ADC; 2 grupos de 1
lines = []
state["bounce"] = False
sr = analyzer.run_series(an, 2, ms=100, trigger="IO10", timeout_ms=300000, gap_s=0, tag="teste_serie",
                         groups="caneta:1,dedo:1", adc_pin="IO1", out=lines.append)
check("series: timeout limitado no fw antigo", sr["timeout_ms"] == 60000 and state["last_capture_q"]["timeout_ms"] == ["60000"], sr)
check("series: sem ADC no fw antigo", "adc_pin" not in state["last_capture_q"], state["last_capture_q"])
check("series: 2 capturas com evento", [c["events"] for c in sr["captures"]] == [1, 1], sr["captures"])
check("series: 1 PNG por grupo", len(sr["png"]) == 2 and all(Path(x).exists() for x in sr["png"]), sr["png"])
check("series: linha por captura", sum("bordas" in x for x in lines) == 2, lines)
for c in sr["captures"]:
    Path(c["csv"]).unlink()
for x in sr["png"]:
    Path(x).unlink()
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
