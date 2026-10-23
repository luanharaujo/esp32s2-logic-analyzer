# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "mcp>=1.2,<2",
# ]
# ///
"""Analisador lógico pela rede (Wi-Fi Devboard ESP32-S2, firmware em firmware/), para agentes.

O ESP se anuncia por mDNS como logic-s2.local (nunca IP fixo). Uso:
    uv run agent/analyzer.py find                 # resolve o endereço (IPv4) pelo mDNS
    uv run agent/analyzer.py status | log [--prev] | scan
    uv run agent/analyzer.py ota firmware/build/s2la.bin [--expect VERSAO]
    uv run agent/analyzer.py reboot
    uv run agent/analyzer.py channels | levels [--pull up]
    uv run agent/analyzer.py capture [--ms 100] [--trigger IO10 --edge fall --timeout-ms 10000] [--pull up]
                                     [--pins IO10,IO11] [--settle-us 5000]   # salva CSV em captures/ e resume
                                     [--adc-pin IO1 --adc-rate 20000 --adc-atten 11]  # + analógico junto
    uv run agent/analyzer.py analyze captures/x.csv [--settle-us 5000]       # offline
    uv run agent/analyzer.py gen IO10 --hz 1000 [--duty 50] | gen IO10 --hz 0  # gerador de teste no canal
    uv run agent/analyzer.py gen IO10 --mode bounce [--delay-ms 500]          # rajada de bounce de teste
    uv run agent/analyzer.py selftest                                          # autoteste sem nada ligado
    uv run agent/analyzer.py adc [--pin IO10] [--ms 100] [--rate 83333] [--atten 11]
                                 [--trig-mv 1650 --edge fall --timeout-ms 10000 --pre 100]  # analógico (ADC1)
    uv run agent/analyzer.py analyze-adc captures/x_adc.csv                    # offline
    uv run agent/analyzer.py mcp                  # servidor MCP (stdio)
Host: --host, ou S2LA_HOST, ou logic-s2.local. Token (rotas que alteram o ESP): ~/.config/s2la/token.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import select
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

HOSTNAME = "logic-s2.local"
TOKEN_FILE = Path.home() / ".config" / "s2la" / "token"
CAPTURE_DIR = Path(__file__).resolve().parent.parent / "captures"
CHANNELS = ["IO10", "IO11", "IO12", "IO13", "IO1", "IO2", "IO18", "IO17"]


class AnalyzerError(RuntimeError):
    pass


def resolve(name: str = HOSTNAME, timeout: float = 5.0) -> str:
    """Endereço IPv4 de um nome .local. No macOS usa dns-sd (o getaddrinfo pode travar no IPv6)."""
    if re.fullmatch(r"[\d.]+(:\d+)?", name):  # IP (com porta opcional, para testes)
        return name
    if sys.platform == "darwin" and name.endswith(".local"):
        try:
            p = subprocess.Popen(["dns-sd", "-G", "v4", name], stdout=subprocess.PIPE)
            t0 = time.time()
            buf = ""
            try:
                while time.time() - t0 < timeout:
                    ready, _, _ = select.select([p.stdout], [], [], 0.2)
                    if ready:
                        buf += os.read(p.stdout.fileno(), 4096).decode(errors="replace")
                        m = re.search(r"\s(\d+\.\d+\.\d+\.\d+)\s", buf)
                        if m and not m.group(1).startswith("0."):
                            return m.group(1)
            finally:
                p.kill()
        except FileNotFoundError:
            pass
    try:
        infos = socket.getaddrinfo(name, 80, socket.AF_INET, socket.SOCK_STREAM)
        return infos[0][4][0]
    except socket.gaierror as e:
        raise AnalyzerError(f"não achei {name} pelo mDNS ({e}). O ESP está ligado e na rede principal?") from e


class Analyzer:
    def __init__(self, host: str | None = None):
        self.name = host or os.environ.get("S2LA_HOST") or HOSTNAME
        self._ip: str | None = None

    @property
    def ip(self) -> str:
        if not self._ip:
            self._ip = resolve(self.name)
        return self._ip

    def _token(self) -> str:
        try:
            return TOKEN_FILE.read_text().strip()
        except FileNotFoundError:
            raise AnalyzerError(f"sem token em {TOKEN_FILE}")

    def request(self, path: str, method: str = "GET", data: bytes | None = None, headers: dict | None = None,
                timeout: float = 10.0, auth: bool = False) -> bytes:
        h = dict(headers or {})
        if auth:
            h["X-Token"] = self._token()
        req = urllib.request.Request(f"http://{self.ip}{path}", data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            raise AnalyzerError(f"HTTP {e.code} em {path}: {e.read().decode(errors='replace').strip()}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise AnalyzerError(f"sem resposta de {self.name} ({self.ip}) em {path}: {e}") from e

    def status(self) -> dict:
        return json.loads(self.request("/status"))

    def log(self, prev: bool = False) -> str:
        return self.request("/log?prev=1" if prev else "/log").decode(errors="replace")

    def scan(self) -> dict:
        return json.loads(self.request("/scan", timeout=15))

    def reboot(self) -> dict:
        return json.loads(self.request("/reboot", method="POST", auth=True))

    def channels(self) -> dict:
        return json.loads(self.request("/channels"))

    def levels(self, pull: str | None = None) -> dict:
        return json.loads(self.request("/levels" + (f"?pull={pull}" if pull else "")))

    def gen(self, pin: str, hz: int = 0, duty: int = 50, mode: str = "square", delay_ms: int = 500) -> dict:
        """Gerador de teste no próprio canal: mode="square" (LEDC, hz=0 desliga) ou "bounce" (rajada de
        botão com bounce, por RMT com 1 µs exato, disparada delay_ms depois)."""
        q = urllib.parse.urlencode({"pin": pin, "hz": hz, "duty": duty, "mode": mode, "delay_ms": delay_ms})
        return json.loads(self.request(f"/gen?{q}", method="POST", data=b"", auth=True))

    def selftest(self) -> dict:
        """Autoteste sem nada ligado aos canais: (1) rajada de bounce conhecida no IO10, capturada com
        trigger na borda de descida; (2) onda de 10 kHz no IO11. Compara com o esperado."""
        out = {"ok": True}
        g = self.gen("IO10", mode="bounce", delay_ms=800)
        expected = g["pattern_us"]
        res = analyze(parse_edges_csv(self.capture_csv(ms=60, trigger="IO10", edge="fall", timeout_ms=3000,
                                                       pins="IO10")), settle_us=5000)
        evs = res["pins"]["IO10"]["events"]
        got = [w for e in evs for w in e["pulses_us"]]
        # larguras esperadas entre bordas: todas menos a última (repouso final); o trecho longo (20 ms)
        # separa os dois eventos (pressão e soltura) e não aparece em pulses_us
        want = [d for d in expected[:-1] if d < 5000]
        err = max((abs(a - b) for a, b in zip(got, want)), default=None)
        b_ok = len(got) == len(want) and err is not None and err < 0.5
        out["bounce"] = {"ok": b_ok, "status": res["status"], "events": len(evs), "pulses_us": got, "expected_us": want,
                         "max_err_us": err, "max_sample_gap_us": res.get("max_sample_gap_us"),
                         "mean_sample_period_us": res.get("mean_sample_period_us")}
        # mesma rajada com trigger por interrupção (informativo: mostra o que a latência da ISR perde)
        self.gen("IO10", mode="bounce", delay_ms=800)
        res = analyze(parse_edges_csv(self.capture_csv(ms=60, trigger="IO10", edge="fall", timeout_ms=3000,
                                                       pins="IO10", tmode="isr")), settle_us=5000)
        out["bounce_isr_info"] = {"status": res["status"],
                                  "pulses_us": [w for e in res["pins"]["IO10"]["events"] for w in e["pulses_us"]]}
        self.gen("IO11", hz=10000, duty=30)
        res = analyze(parse_edges_csv(self.capture_csv(ms=20, pins="IO11")))
        p = res["pins"]["IO11"]
        sq_ok = abs(p.get("freq_hz", 0) - 10000) < 50 and abs(p.get("duty_pct", 0) - 30) < 3
        out["square"] = {"ok": sq_ok, "freq_hz": p.get("freq_hz"), "duty_pct": p.get("duty_pct"), "edges": p["edges"]}
        self.gen("IO11", hz=0)
        out["ok"] = b_ok and sq_ok
        return out

    def capture_csv(self, ms: int = 100, trigger: str | None = None, edge: str = "any", timeout_ms: int = 10000,
                    pull: str = "none", pins: str | None = None, tmode: str = "poll", adc_pin: str | None = None,
                    adc_rate: int = 20000, adc_atten: str = "11") -> str:
        """Captura bordas nos canais (CSV gpio_edges v1, ciclos de 240 MHz). Com trigger, espera a borda até
        timeout_ms (até 300000) e captura ms a partir dela. adc_pin (IO1, IO2 ou IO10): amostra também esse
        pino no ADC1, na mesma base de tempo (seção adc_samples depois do # end)."""
        q = {"ms": ms, "edge": edge, "timeout_ms": timeout_ms, "pull": pull, "tmode": tmode}
        if adc_pin:
            q.update(adc_pin=adc_pin, adc_rate=adc_rate, adc_atten=adc_atten)
        if trigger:
            q["trigger"] = trigger
        if pins:
            q["pins"] = pins
        wait = (timeout_ms if trigger else 0) / 1000 + ms / 1000 + 15
        return self.request("/capture?" + urllib.parse.urlencode(q), timeout=wait).decode()

    def adc_csv(self, pin: str = "IO10", ms: int = 100, rate: int = 83333, atten: str = "11",
                trig_mv: int | None = None, edge: str = "fall", timeout_ms: int = 10000, pre: int = 100) -> str:
        """Captura analógica no ADC1 (IO10, IO1 ou IO2), CSV adc_samples v1 (us,raw,mv). Sem pull no pino.
        rate: 611 a 83333 amostras/s; atten 11 dB = 0 a ~2,5 V (acima disso satura). trig_mv: espera
        cruzar esse nível (edge fall/rise) até timeout_ms, guardando até pre amostras antes."""
        q = {"pin": pin, "ms": ms, "rate": rate, "atten": atten}
        if trig_mv is not None:
            q.update(trig_mv=trig_mv, edge=edge, timeout_ms=timeout_ms, pre=pre)
        wait = (timeout_ms if trig_mv is not None else 0) / 1000 + ms / 1000 + 30
        return self.request("/adc?" + urllib.parse.urlencode(q), timeout=wait).decode()

    def adc(self, tag: str = "adc", **kw) -> dict:
        text = self.adc_csv(**kw)
        path = save_capture(text, tag)
        res = analyze_adc(parse_adc_csv(text))
        res["csv_local"] = str(path)
        return res

    def capture(self, settle_us: float = 5000.0, tag: str = "capture", **kw) -> dict:
        text = self.capture_csv(**kw)
        path = save_capture(text, tag)
        res = analyze_any(text, settle_us)
        res["csv_local"] = str(path)
        return res

    def ota(self, bin_path: str, expect: str | None = None, timeout: float = 120.0) -> dict:
        """Envia o .bin por HTTP POST (o Mac empurra; o ESP não precisa alcançar o Mac), espera o
        ESP voltar e confere a versão."""
        data = Path(bin_path).read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        before = self.status()
        t0 = time.time()
        r = json.loads(self.request("/ota", method="POST", data=data, auth=True, timeout=180,
                                    headers={"Content-Type": "application/octet-stream", "X-SHA256": sha}))
        sent_s = round(time.time() - t0, 1)
        time.sleep(4)
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                self._ip = None  # o IP pode mudar depois do reboot
                st = self.status()
                if st.get("boot") != before.get("boot") or st.get("uptime_s", 1e9) < time.time() - t0:
                    ok = expect is None or st.get("fw") == expect
                    return {"ok": ok, "sent": r, "upload_s": sent_s, "bytes": len(data), "sha256": sha,
                            "before_fw": before.get("fw"), "after_fw": st.get("fw"),
                            "partition": st.get("partition"), "reset_detail": st.get("reset_detail"),
                            "ota_pending_verify": st.get("ota_pending_verify"),
                            **({} if ok else {"err": f"versão {st.get('fw')} != esperada {expect}"})}
            except AnalyzerError as e:
                last_err = str(e)
            time.sleep(2)
        raise AnalyzerError(f"ESP não voltou em {timeout:.0f} s depois da OTA ({last_err})")


# --- CSV de bordas (mesmo formato do FAP gpio_edges do projeto do Flipper) e análise ---
# Copiado de ~/repositories/projeto do Flipper/agent/flipper.py (parse_edges_csv, analyze) para o
# projeto não depender de outro repo.

def parse_edges_csv(text: str) -> dict:
    meta, initial, end, rows = {}, {}, {}, []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("# gpio_edges"):
            meta = dict(kv.split("=", 1) for kv in line.split()[3:] if "=" in kv)
            meta["version"] = line.split()[2]
        elif line.startswith("# initial"):
            initial = {k: int(v) for k, v in (kv.split("=", 1) for kv in line.split()[2:])}
        elif line.startswith("# end"):
            end = dict(kv.split("=", 1) for kv in line.split()[2:] if "=" in kv)
        elif line.startswith("cycles") or line.startswith("#"):
            continue
        else:
            c, pin, lv = line.split(",")
            rows.append((int(c), pin, int(lv)))
    return {"meta": meta, "initial": initial, "end": end, "rows": rows}


def analyze(parsed: dict, settle_us: float = 5000.0) -> dict:
    """Resumo por pino: bordas, rajadas (bounce) separadas por silêncio > settle_us."""
    hz = float(parsed["meta"].get("cpu_hz", 240_000_000))
    pins = parsed["meta"].get("pins", "").split(",") if parsed["meta"].get("pins") else []
    out = {"cpu_hz": hz, "tick_us": round(1e6 / hz, 4), "status": parsed["end"].get("status"),
           "trigger": parsed["meta"].get("trigger"), "window_ms": parsed["meta"].get("ms"),
           "overflow": int(parsed["end"].get("overflow", 0) or 0), "buf": parsed["end"].get("buf"), "pins": {}}
    gap = parsed["end"].get("max_gap_cycles")
    if gap and gap != "0":
        out["max_sample_gap_us"] = round(int(gap) / hz * 1e6, 3)
    loops, ms = parsed["end"].get("loops"), parsed["meta"].get("ms")
    if loops and ms and parsed["end"].get("status") != "timeout":
        out["mean_sample_period_us"] = round(float(ms) * 1000 / max(1, int(loops)), 4)
    for pin in pins or sorted({r[1] for r in parsed["rows"]}):
        rs = [(c / hz * 1e6, lv) for c, p, lv in parsed["rows"] if p == pin]
        groups, cur = [], []
        for t, lv in rs:
            if cur and t - cur[-1][0] > settle_us:
                groups.append(cur)
                cur = []
            cur.append((t, lv))
        if cur:
            groups.append(cur)
        gsum = []
        for g in groups[:50]:
            widths = [round(b[0] - a[0], 3) for a, b in zip(g, g[1:])]
            gsum.append({
                "start_us": round(g[0][0], 3), "bounce_us": round(g[-1][0] - g[0][0], 3),
                "transitions": len(g), "final_level": g[-1][1],
                "min_pulse_us": min(widths) if widths else None,
                "pulses_us": widths[:40],
            })
        info = {"initial": parsed["initial"].get(pin), "edges": len(rs), "events": gsum}
        if len(groups) > 50:
            info["events_truncated"] = len(groups)
        if len(rs) >= 10:  # sinal periódico: frequência e duty médios (só com bordas suficientes)
            per = [b[0] - a[0] for a, b in zip(rs, rs[1:])]
            hi = [b[0] - a[0] for a, b in zip(rs, rs[1:]) if a[1] == 1]
            span = rs[-1][0] - rs[0][0]
            cycles = (len(rs) - 1) / 2
            if span > 0:
                info["freq_hz"] = round(cycles / span * 1e6, 3)
                info["duty_pct"] = round(100 * sum(hi) / (sum(per) or 1), 2)
                info["min_interval_us"] = round(min(per), 3)
                info["max_interval_us"] = round(max(per), 3)
        out["pins"][pin] = info
    return out


def parse_adc_csv(text: str) -> dict:
    """CSV adc_samples v1 -> {"meta": {...}, "end": {...}, "us": [...], "raw": [...], "mv": [...]}."""
    out = {"meta": {}, "end": {}, "us": [], "raw": [], "mv": []}
    for line in text.splitlines():
        if line.startswith("# adc_samples"):
            out["meta"] = dict(kv.split("=", 1) for kv in line.split()[3:] if "=" in kv)
        elif line.startswith("# end"):
            out["end"] = dict(kv.split("=", 1) for kv in line.split()[2:] if "=" in kv)
        elif line and line[0] in "-0123456789":
            us, raw, mv = line.split(",")
            out["us"].append(float(us)); out["raw"].append(int(raw)); out["mv"].append(int(mv))
    if not out["meta"]:
        raise AnalyzerError("CSV sem cabeçalho adc_samples v1")
    return out


def _tone_mv(mv: list, rate: float, hz: float) -> float:
    """Amplitude (mV de pico) da componente de hz Hz, por DFT num número inteiro de ciclos."""
    import math
    n = int(len(mv) // (rate / hz) * (rate / hz))
    if n < rate / hz:
        return 0.0
    m = sum(mv[:n]) / n
    w = 2 * math.pi * hz / rate
    re_ = sum((mv[k] - m) * math.cos(w * k) for k in range(n))
    im = sum((mv[k] - m) * math.sin(w * k) for k in range(n))
    return 2 * math.hypot(re_, im) / n


def analyze_adc(parsed: dict, hyst_mv: float = 200.0) -> dict:
    """Resumo de uma captura analógica: estatística em mV, saturação, cruzamentos do meio da faixa (com
    histerese, para ver bounce lento), ruído de 50/60 Hz se a janela tiver ao menos um ciclo."""
    import statistics
    mv, raw, meta, end = parsed["mv"], parsed["raw"], parsed["meta"], parsed["end"]
    rate = float(meta.get("rate", 0)) or 1.0
    out = {"pin": meta.get("pin"), "atten_db": meta.get("atten"), "range_mv": int(meta.get("range_mv", 0)),
           "cal": meta.get("cal"), "rate_sps": rate, "sps_measured": float(end.get("sps_measured", 0)),
           "status": end.get("status"), "invalid": int(end.get("invalid", 0)), "samples": len(mv)}
    if not mv:
        return out
    out["window_ms"] = round(len(mv) / rate * 1000, 3)
    out["sample_period_us"] = round(1e6 / rate, 2)
    out.update(min_mv=min(mv), max_mv=max(mv), mean_mv=round(statistics.fmean(mv), 1),
               std_mv=round(statistics.pstdev(mv), 1), saturated_pct=round(100 * sum(r >= 4095 for r in raw) / len(raw), 2))
    mid = (min(mv) + max(mv)) / 2
    cross = []
    if max(mv) - min(mv) > 2 * hyst_mv:
        hi = mv[0] > mid
        for k, v in enumerate(mv):
            if hi and v < mid - hyst_mv / 2:
                hi = False; cross.append(parsed["us"][k])
            elif not hi and v > mid + hyst_mv / 2:
                hi = True; cross.append(parsed["us"][k])
    out["mid_mv"] = round(mid)
    out["crossings"] = len(cross)
    if cross:
        out["first_cross_us"], out["last_cross_us"] = cross[0], cross[-1]
        out["cross_span_us"] = round(cross[-1] - cross[0], 1)
    # Ruído de rede: no trecho estável mais longo (longe dos cruzamentos), para o degrau não contaminar
    us = parsed["us"]
    cuts = [0] + [k for k in range(1, len(mv)) if any(abs(us[k] - c) < 0.5 for c in cross)] + [len(mv)]
    margin = int(rate * 200e-6) + 1
    seg = max(((a + margin * (a > 0), b - margin * (b < len(mv))) for a, b in zip(cuts, cuts[1:])),
              key=lambda ab: ab[1] - ab[0])
    out["stable_ms"] = round(max(0, seg[1] - seg[0]) / rate * 1000, 2)
    for hz in (50, 60):
        if seg[1] - seg[0] >= rate / hz:
            out[f"tone_{hz}hz_mv"] = round(_tone_mv(mv[seg[0]:seg[1]], rate, hz), 1)
    return out


def split_combined(text: str) -> tuple[str, str | None]:
    """CSV da captura combinada -> (parte gpio_edges, parte adc_samples ou None)."""
    k = text.find("# adc_samples v1")
    return (text, None) if k < 0 else (text[:k], text[k:])


def parse_combined_adc(text: str) -> dict:
    """Seção adc_samples da captura combinada (cycles,raw,mv desde o t0 digital) -> formato de parse_adc_csv."""
    out = {"meta": {}, "end": {}, "us": [], "raw": [], "mv": [], "cycles": []}
    for line in text.splitlines():
        if line.startswith("# adc_samples"):
            out["meta"] = dict(kv.split("=", 1) for kv in line.split()[3:] if "=" in kv)
        elif line.startswith("# adc_end"):
            out["end"] = dict(kv.split("=", 1) for kv in line.split()[2:] if "=" in kv)
        elif line and line[0] in "-0123456789":
            c, raw, mv = line.split(",")
            out["cycles"].append(int(c)); out["raw"].append(int(raw)); out["mv"].append(int(mv))
    out["us"] = [c / 240.0 for c in out["cycles"]]
    m = out["meta"]
    m["rate"] = m.get("rate_real", m.get("rate", "0"))
    m.setdefault("range_mv", m.get("atten_range_mv", "0"))
    return out


def compare_dig_adc(dig: dict, adc_parsed: dict, pin: str, hyst_mv: float = 200.0) -> dict:
    """Mesmo nó nas duas garras: bordas digitais do pino vs cruzamentos do meio da faixa no analógico."""
    edges = [c / 240.0 for c, p, _ in dig["rows"] if p == pin]
    mv, us = adc_parsed["mv"], adc_parsed["us"]
    out = {"pin": pin, "digital_edges": len(edges)}
    if not mv:
        return out
    out["adc_from_us"], out["adc_to_us"] = round(us[0], 2), round(us[-1], 2)
    inside = [e for e in edges if us[0] <= e <= us[-1]]
    out["digital_edges_in_adc_window"] = len(inside)
    mid = (min(mv) + max(mv)) / 2
    cross, hi = [], mv[0] > mid
    if max(mv) - min(mv) > 2 * hyst_mv:
        for k, v in enumerate(mv):
            if hi and v < mid - hyst_mv / 2:
                hi = False; cross.append(us[k])
            elif not hi and v > mid + hyst_mv / 2:
                hi = True; cross.append(us[k])
    out["adc_crossings"] = len(cross)
    if inside and cross:
        out["first_digital_us"], out["first_adc_cross_us"] = round(inside[0], 2), round(cross[0], 2)
        out["first_lag_us"] = round(cross[0] - inside[0], 2)
        out["digital_span_us"] = round(inside[-1] - inside[0], 2)
        out["adc_span_us"] = round(cross[-1] - cross[0], 2)
    return out


def analyze_any(text: str, settle_us: float = 5000.0, compare_pin: str | None = None) -> dict:
    """analyze() da parte digital; se houver seção analógica, junta analyze_adc e a comparação."""
    dig_txt, adc_txt = split_combined(text)
    dig = parse_edges_csv(dig_txt)
    res = analyze(dig, settle_us)
    if adc_txt:
        ap = parse_combined_adc(adc_txt)
        a = analyze_adc(ap)
        a["end"] = ap["end"]
        res["adc"] = a
        pin = compare_pin or (dig["meta"].get("trigger") if dig["meta"].get("trigger") not in (None, "none") else "IO10")
        res["compare"] = compare_dig_adc(dig, ap, pin)
    return res


def save_capture(text: str, tag: str = "capture") -> Path:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    path = CAPTURE_DIR / f"{datetime.now():%Y%m%d_%H%M%S}_{tag}.csv"
    path.write_text(text)
    return path


def run_mcp():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("logic", instructions=(
        "Analisador lógico de 8 canais pela rede (ESP32-S2 em logic-s2.local, 3,3 V, nunca 5 V). "
        "Canais IO10, IO11, IO12, IO13, IO1, IO2, IO18, IO17; GND comum com o alvo. Use capture com "
        "trigger para medir bounce de botão; o resultado já vem analisado. adc: captura analógica lenta (até "
        "83 kamostras/s, 12 bits, 0 a ~2,5 V) em IO10, IO1 ou IO2."))
    an = Analyzer()

    @mcp.tool()
    def status() -> str:
        """Estado do analisador: firmware, Wi-Fi (ssid, bssid, rssi, ip), uptime, motivo do último reset."""
        return json.dumps(an.status(), ensure_ascii=False)

    @mcp.tool()
    def device_log(previous_boot: bool = False) -> str:
        """Últimas linhas de log do ESP (do boot atual, ou do anterior se previous_boot)."""
        return an.log(previous_boot)

    @mcp.tool()
    def channels() -> str:
        """Mapa dos 8 canais: nome (IO10...), GPIO e pino do header da devboard."""
        return json.dumps(an.channels(), ensure_ascii=False)

    @mcp.tool()
    def levels(pull: str = "") -> str:
        """Nível lógico atual de cada canal. pull: "up", "down", "none" ou vazio (não muda)."""
        return json.dumps(an.levels(pull or None), ensure_ascii=False)

    @mcp.tool()
    def capture(ms: int = 100, trigger: str = "", edge: str = "any", timeout_ms: int = 10000,
                pull: str = "none", pins: str = "", settle_us: float = 5000.0, tmode: str = "poll",
                adc_pin: str = "", adc_rate: int = 20000, adc_atten: str = "11") -> str:
        """Captura bordas nos canais do analisador (resolução ~0,1 µs, janela de até 2000 ms).
        trigger: canal (ex. "IO10") cuja borda (edge: rise, fall, any) dispara a captura; vazio = agora.
        timeout_ms: quanto esperar pelo trigger. pull: up/down/none em todos os canais.
        pins: lista "IO10,IO11" (vazio = os 8). settle_us: silêncio que separa eventos (bounce).
        tmode: "poll" (padrão, latência ~0,1 µs; Wi-Fi pausa durante a espera) ou "isr" (~1-2 µs).
        timeout_ms até 300000 (5 min).
        adc_pin ("IO1", "IO2" ou "IO10"): grava também o analógico desse pino (ADC1 por DMA, adc_rate 611 a
        83333/s, 12 bits, adc_atten "11" = 0 a ~2,5 V) na MESMA base de tempo das bordas, para comparar
        as duas garras no mesmo nó. Cobre no máximo a cadeia de DMA (chain amostras, ~150 ms a 20 kHz).
        Devolve, por pino, os eventos (duração do bounce, transições, larguras de pulso), frequência
        e duty de sinais periódicos, o resumo analógico e a comparação (se adc_pin), e o caminho do CSV."""
        return json.dumps(an.capture(settle_us=settle_us, ms=ms, trigger=trigger or None, edge=edge,
                                     timeout_ms=timeout_ms, pull=pull, pins=pins or None, tmode=tmode,
                                     adc_pin=adc_pin or None, adc_rate=adc_rate, adc_atten=adc_atten),
                          ensure_ascii=False)

    @mcp.tool()
    def test_generator(pin: str = "IO10", hz: int = 1000, duty: int = 50, mode: str = "square",
                       delay_ms: int = 500) -> str:
        """Gerador de teste no próprio canal: mode="square" (onda quadrada, hz=0 desliga) ou "bounce"
        (rajada que imita bounce de botão, disparada delay_ms depois). Só usar com NADA externo nesse pino."""
        return json.dumps(an.gen(pin, hz, duty, mode, delay_ms), ensure_ascii=False)

    @mcp.tool()
    def adc(pin: str = "IO10", ms: int = 100, rate: int = 83333, atten: str = "11", trig_mv: int = -1,
            edge: str = "fall", timeout_ms: int = 10000, pre: int = 100) -> str:
        """Captura ANALÓGICA lenta no ADC1 (pinos IO10, IO1 ou IO2; os outros canais são ADC2, que o Wi-Fi
        usa). rate: 611 a 83333 amostras/s (12 µs por amostra no máximo), 12 bits. atten "11" = 0 a ~2,5 V
        (3,3 V satura). Não liga pull no pino. trig_mv >= 0: espera o sinal cruzar esse nível (edge fall
        ou rise) até timeout_ms e guarda pre amostras antes. Devolve min/max/média/desvio em mV, saturação,
        cruzamentos do meio da faixa, ruído de 50/60 Hz e o caminho do CSV (us,raw,mv) salvo no Mac."""
        return json.dumps(an.adc(pin=pin, ms=ms, rate=rate, atten=atten, trig_mv=trig_mv if trig_mv >= 0 else None,
                                 edge=edge, timeout_ms=timeout_ms, pre=pre), ensure_ascii=False)

    @mcp.tool()
    def selftest() -> str:
        """Autoteste do analisador sem nada ligado: mede uma rajada de bounce conhecida e uma onda de 10 kHz
        geradas pelo próprio ESP e compara com o esperado."""
        return json.dumps(an.selftest(), ensure_ascii=False)

    mcp.run()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", help="nome .local ou IP (padrão: S2LA_HOST ou logic-s2.local)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("find")
    sub.add_parser("status")
    p = sub.add_parser("log"); p.add_argument("--prev", action="store_true")
    sub.add_parser("scan")
    sub.add_parser("reboot")
    p = sub.add_parser("ota"); p.add_argument("bin"); p.add_argument("--expect")
    sub.add_parser("channels")
    p = sub.add_parser("levels"); p.add_argument("--pull")
    p = sub.add_parser("capture")
    p.add_argument("--ms", type=int, default=100); p.add_argument("--trigger"); p.add_argument("--edge", default="any")
    p.add_argument("--timeout-ms", type=int, default=10000); p.add_argument("--pull", default="none")
    p.add_argument("--pins"); p.add_argument("--settle-us", type=float, default=5000); p.add_argument("--tag", default="capture")
    p.add_argument("--tmode", default="poll", choices=["poll", "isr"])
    p.add_argument("--adc-pin", help="IO1, IO2 ou IO10: analógico junto, mesma base de tempo")
    p.add_argument("--adc-rate", type=int, default=20000); p.add_argument("--adc-atten", default="11", choices=["0", "2.5", "6", "11"])
    p = sub.add_parser("analyze"); p.add_argument("csv"); p.add_argument("--settle-us", type=float, default=5000)
    p = sub.add_parser("gen"); p.add_argument("pin"); p.add_argument("--hz", type=int, default=1000); p.add_argument("--duty", type=int, default=50)
    p.add_argument("--mode", default="square", choices=["square", "bounce"]); p.add_argument("--delay-ms", type=int, default=500)
    sub.add_parser("selftest")
    p = sub.add_parser("adc"); p.add_argument("--pin", default="IO10"); p.add_argument("--ms", type=int, default=100)
    p.add_argument("--rate", type=int, default=83333); p.add_argument("--atten", default="11", choices=["0", "2.5", "6", "11"])
    p.add_argument("--trig-mv", type=int); p.add_argument("--edge", default="fall", choices=["fall", "rise"])
    p.add_argument("--timeout-ms", type=int, default=10000); p.add_argument("--pre", type=int, default=100)
    p.add_argument("--tag", default="adc")
    p = sub.add_parser("analyze-adc"); p.add_argument("csv")
    sub.add_parser("mcp")
    a = ap.parse_args()
    if a.cmd == "mcp":
        return run_mcp()
    if a.cmd == "analyze":
        print(json.dumps(analyze_any(Path(a.csv).read_text(), a.settle_us), indent=1))
        return
    if a.cmd == "analyze-adc":
        print(json.dumps(analyze_adc(parse_adc_csv(Path(a.csv).read_text())), indent=1))
        return
    an = Analyzer(a.host)
    try:
        if a.cmd == "find":
            print(json.dumps({"name": an.name, "ip": an.ip}))
        elif a.cmd == "status":
            print(json.dumps(an.status(), indent=1, ensure_ascii=False))
        elif a.cmd == "log":
            print(an.log(a.prev), end="")
        elif a.cmd == "scan":
            print(json.dumps(an.scan(), indent=1, ensure_ascii=False))
        elif a.cmd == "reboot":
            print(json.dumps(an.reboot()))
        elif a.cmd == "channels":
            print(json.dumps(an.channels(), indent=1))
        elif a.cmd == "levels":
            print(json.dumps(an.levels(a.pull), indent=1))
        elif a.cmd == "gen":
            print(json.dumps(an.gen(a.pin, a.hz, a.duty, a.mode, a.delay_ms)))
        elif a.cmd == "selftest":
            r = an.selftest()
            print(json.dumps(r, indent=1))
            sys.exit(0 if r["ok"] else 1)
        elif a.cmd == "capture":
            print(json.dumps(an.capture(settle_us=a.settle_us, tag=a.tag, ms=a.ms, trigger=a.trigger, edge=a.edge,
                                        timeout_ms=a.timeout_ms, pull=a.pull, pins=a.pins, tmode=a.tmode,
                                        adc_pin=a.adc_pin, adc_rate=a.adc_rate, adc_atten=a.adc_atten),
                             indent=1, ensure_ascii=False))
        elif a.cmd == "adc":
            print(json.dumps(an.adc(tag=a.tag, pin=a.pin, ms=a.ms, rate=a.rate, atten=a.atten, trig_mv=a.trig_mv,
                                    edge=a.edge, timeout_ms=a.timeout_ms, pre=a.pre), indent=1, ensure_ascii=False))
        elif a.cmd == "ota":
            res = an.ota(a.bin, a.expect)
            print(json.dumps(res, indent=1, ensure_ascii=False))
            sys.exit(0 if res["ok"] else 1)
    except AnalyzerError as e:
        print(f"erro: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
