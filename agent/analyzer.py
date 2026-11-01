# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "mcp>=1.2,<2",
#   "matplotlib>=3.8",
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
    uv run agent/analyzer.py live [--pin IO1] [--rate 5000] [--window-s 30]   # tensão ao vivo numa janela + painel 8765
    uv run agent/analyzer.py analyze-adc captures/x_adc.csv                    # offline
    uv run agent/analyzer.py plot "arq.csv|t0_ms|t1_ms|título" [...] [-o x.png] [--title T] [--show]  # PNG 9x9
    uv run agent/analyzer.py plot --auto arq.csv [--show]                     # janela inteira + zoom no 1º evento
    uv run agent/analyzer.py series --n 9 --ms 1500 --trigger IO10 --edge fall --timeout-ms 300000 --gap-s 2
                                    --tag t2 [--groups caneta:3,chassi:3,dedo:3] [--adc-pin IO1] [--show]
    uv run agent/analyzer.py record --s 120 --pins IO10 [--adc-pin IO1 --adc-rate 10000] [--live] [--show]
                                    # gravação contínua (fw >= 0.4.0): lista de eventos com hora + PNG
    uv run agent/analyzer.py presses captures/x.csv [--silence-ms 20] [--ref 1387.438,1544.998] [--png] [--zoom N] [--show]
                                    # apertos reais (regra do STM32) e voltas comparadas com uma referência
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


def analyze(parsed: dict, settle_us: float = 5000.0, max_events: int = 50) -> dict:
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
        for g in groups[:max_events]:
            widths = [round(b[0] - a[0], 3) for a, b in zip(g, g[1:])]
            gsum.append({
                "start_us": round(g[0][0], 3), "bounce_us": round(g[-1][0] - g[0][0], 3),
                "transitions": len(g), "final_level": g[-1][1],
                "min_pulse_us": min(widths) if widths else None,
                "pulses_us": widths[:40],
            })
        info = {"initial": parsed["initial"].get(pin), "edges": len(rs), "events": gsum}
        if len(groups) > max_events:
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
    m, e = out["meta"], out["end"]
    m["rate"] = m.get("rate_real", m.get("rate", "0"))
    if m["rate"] in ("0", "") and e.get("period_cycles"):  # cabeçalho incompleto (fw 0.3.1): taxa pelo período
        m["rate"] = str(240e6 / int(e["period_cycles"]))
    m.setdefault("range_mv", m.get("atten_range_mv", "0"))
    m.setdefault("atten", {"750": "0", "1050": "2.5", "1300": "6", "2500": "11"}.get(m["range_mv"]))
    if e:
        e.setdefault("status", "ok" if e.get("samples") == e.get("wanted") else "incompleto")
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
        if ap["meta"].get("mode") == "events":  # janelas soltas por evento: ruído de rede não faz sentido
            for kk in ("tone_50hz_mv", "tone_60hz_mv", "stable_ms"):
                a.pop(kk, None)
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


# ---------------------------------------------------------------------------------------------------
# Gráficos (PNG quadrado) e séries de capturas de bancada

PLOT_DIGITAL_COLOR = "#1f5fa8"
PLOT_ADC_COLOR = "#d9822b"
PREVIEW_BOUNDS = "{0, 30, 1040, 1070}"  # canto superior esquerdo da tela principal (2080x1170 pontos)


def _br(x: float, nd: int = 1) -> str:
    """Número com vírgula decimal."""
    return f"{x:.{nd}f}".replace(".", ",")


def resolve_csv(name: str) -> Path:
    """Caminho do CSV: como veio, ou dentro de captures/."""
    p = Path(name).expanduser()
    if p.exists():
        return p
    q = CAPTURE_DIR / name
    if q.exists():
        return q
    raise AnalyzerError(f"CSV não encontrado: {name}")


def load_plot_data(path: Path) -> dict:
    """Lê um CSV gpio_edges (com ou sem a seção analógica) ou adc_samples. Tempos em ms desde o t0."""
    text = Path(path).read_text()
    out = {"path": Path(path), "dig": None, "adc": None, "ms": None}
    if text.lstrip().startswith("# adc_samples"):
        out["adc"] = parse_adc_csv(text)
    else:
        dig_txt, adc_txt = split_combined(text)
        out["dig"] = parse_edges_csv(dig_txt)
        out["ms"] = float(out["dig"]["meta"].get("ms", 0) or 0)
        out["bursts"] = parse_bursts(dig_txt)  # gravação: rajadas depois do buffer cheio (só resumo)
        if adc_txt:
            out["adc"] = parse_combined_adc(adc_txt)
    return out


def _data_range_ms(d: dict) -> tuple[float, float]:
    lo, hi = 0.0, d["ms"] or 0.0
    if d["dig"] and d["dig"]["rows"]:
        hz = float(d["dig"]["meta"].get("cpu_hz", 240_000_000))
        hi = max(hi, d["dig"]["rows"][-1][0] / hz * 1e3)
    if d["adc"] and d["adc"]["us"]:
        lo, hi = min(lo, d["adc"]["us"][0] / 1e3), max(hi, d["adc"]["us"][-1] / 1e3)
    return lo, (hi if hi > lo else lo + 1.0)


def plot_panel(ax, d: dict, t0: float | None, t1: float | None, title: str = "", origin_ms: float | None = None):
    """Um painel: degraus do digital (um por pino, empilhados) e o analógico em mV no eixo da direita."""
    import numpy as np
    lo, hi = _data_range_ms(d)
    t0 = lo if t0 is None else t0
    t1 = hi if t1 is None else t1
    k = 1000.0 if t1 - t0 < 1.0 else 1.0  # janela < 1 ms: eixo em µs
    o = origin_ms or 0.0  # origem do eixo (ex.: início do evento)
    n_edges = 0
    if d["dig"]:
        dig = d["dig"]
        hz = float(dig["meta"].get("cpu_hz", 240_000_000))
        pins = dig["meta"].get("pins", "").split(",") if dig["meta"].get("pins") else sorted({r[1] for r in dig["rows"]})
        pins = [p for p in pins if p]
        for i, pin in enumerate(pins):
            rows = [(c / hz * 1e3, lv) for c, p, lv in dig["rows"] if p == pin]
            bursts = d.get("bursts") or []
            if bursts and i == 0:  # resumo das rajadas: faixa cinza e o nível final no fim de cada uma
                for b in bursts:
                    b0, b1 = b["start_us"] / 1e3, (b["start_us"] + b["bounce_us"]) / 1e3
                    if b1 >= t0 and b0 <= t1:
                        ax.axvspan((b0 - o) * k, (max(b1, b0 + (t1 - t0) * 0.002) - o) * k, color="#999", alpha=0.35, lw=0)
                    rows.append((b1, b["final_level"]))
                rows.sort()
            t = np.array([r[0] for r in rows]); v = np.array([r[1] for r in rows])
            init = dig["initial"].get(pin, v[0] ^ 1 if len(v) else 0)
            m = (t >= t0) & (t <= t1) if len(t) else np.array([], bool)
            before = v[t < t0] if len(t) else []
            vi = before[-1] if len(before) else init
            n_edges += int(m.sum())
            tt = np.concatenate([[t0], t[m], [t1]])
            vv = np.concatenate([[vi], v[m], [v[m][-1] if m.any() else vi]])
            off = 1.5 * (len(pins) - 1 - i)
            ax.step((tt - o) * k, vv + off, where="post", lw=0.8, color=PLOT_DIGITAL_COLOR)
        if len(pins) == 1:
            ax.set_ylim(-0.2, 1.2); ax.set_yticks([0, 1]); ax.set_ylabel(f"{pins[0]} (nível)")
        else:
            ax.set_ylim(-0.3, 1.5 * len(pins) - 0.3)
            ax.set_yticks([1.5 * (len(pins) - 1 - i) + 0.5 for i in range(len(pins))]); ax.set_yticklabels(pins)
    if d["adc"] and d["adc"]["us"]:
        a = d["adc"]
        t = np.array(a["us"]) / 1e3; mv = np.array(a["mv"])
        m = (t >= t0) & (t <= t1)
        ax2 = ax.twinx() if d["dig"] else ax
        tt, yy = (t[m] - o) * k, mv[m].astype(float)
        if len(tt) > 2:  # quebra a linha onde faltam amostras (janelas por evento na gravação contínua)
            per = float(np.median(np.diff(tt)))
            br = np.where(np.diff(tt) > 3 * per)[0] + 1
            tt, yy = np.insert(tt, br, np.nan), np.insert(yy, br, np.nan)
        ax2.plot(tt, yy, lw=0.8, color=PLOT_ADC_COLOR, marker="." if m.sum() < 120 else None, ms=3)
        rng = float(a["meta"].get("range_mv", 0) or 0) or (mv.max() if len(mv) else 2500)
        ax2.set_ylim(-0.08 * rng, 1.08 * rng)
        ax2.set_ylabel(f"{a['meta'].get('pin', 'ADC')} (mV)", color=PLOT_ADC_COLOR)
        ax2.tick_params(axis="y", colors=PLOT_ADC_COLOR)
        if not d["dig"]:
            n_edges = None
    ax.set_xlim((t0 - o) * k, (t1 - o) * k)
    ax.ticklabel_format(axis="x", useOffset=False, style="plain")
    unit = "µs" if k > 1 else "ms"
    ax.set_xlabel(f"tempo desde o evento ({unit})" if origin_ms is not None else f"tempo ({unit})")
    ax.set_title(title or d["path"].name, fontsize=11, loc="left")
    ax.grid(alpha=0.3)
    if n_edges is not None:
        ax.text(0.99, 0.97, f"{n_edges} borda{'' if n_edges == 1 else 's'}", transform=ax.transAxes, fontsize=9, color="#a33",
                ha="right", va="top", bbox=dict(facecolor="white", edgecolor="none", alpha=0.8, pad=1))


def parse_panel(spec: str) -> tuple[Path, float | None, float | None, str]:
    """"arquivo|t0_ms|t1_ms|título" (t0, t1 e título opcionais; vazio = janela inteira)."""
    parts = spec.split("|") + ["", "", ""]
    f, t0, t1, title = parts[0], parts[1].strip(), parts[2].strip(), "|".join(parts[3:]).strip("|").strip()
    return resolve_csv(f), (float(t0) if t0 else None), (float(t1) if t1 else None), title


def auto_panels(path: Path) -> list[tuple[Path, float | None, float | None, str]]:
    """Janela geral + zoom no primeiro evento (rajada) do pino do trigger (ou do 1o pino com bordas)."""
    d = load_plot_data(path)
    panels = [(path, None, None, f"{path.stem}: janela inteira")]
    if not d["dig"]:
        return panels
    res = analyze(d["dig"])
    trig = res.get("trigger")
    pins = [trig] if trig in res["pins"] else []
    pins += [p for p in res["pins"] if p not in pins]
    for pin in pins:
        evs = res["pins"][pin]["events"]
        if evs:
            ev = evs[0]
            s, b = ev["start_us"], ev["bounce_us"]
            margin = max(20.0, 0.2 * b)
            panels.append((path, (s - margin) / 1e3, (s + b + margin) / 1e3,
                           f"{pin}: 1º evento, {ev['transitions']} bordas em {_br(b)} µs"))
            break
    return panels


def plot_png(panels: list, out: Path, title: str = "") -> Path:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axs = plt.subplots(len(panels), 1, figsize=(9, 9), dpi=110, squeeze=False)
    for ax, (f, t0, t1, ttl) in zip(axs[:, 0], panels):
        plot_panel(ax, load_plot_data(f), t0, t1, ttl)
    if title:
        fig.suptitle(title, fontsize=12)
    fig.tight_layout()
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out)
    plt.close(fig)
    return out


def show_png(paths: list[Path]):
    """Fecha as janelas anteriores do Preview e abre os PNGs nele, no canto superior esquerdo."""
    subprocess.run(["osascript", "-e", 'tell application "Preview" to close every window'], capture_output=True)
    subprocess.run(["open", "-a", "Preview", *[str(p) for p in paths]], check=False)
    time.sleep(1.0)
    subprocess.run(["osascript", "-e", f'tell application "Preview" to set bounds of front window to {PREVIEW_BOUNDS}'],
                   capture_output=True)


PAINEL_URL = "http://127.0.0.1:8765/recursos/analisador/leitura"  # painel do Mac (Arquiteto); nunca localhost
LIVE_PIDFILE = CAPTURE_DIR / ".live.pid"
LIVE_GEOMETRY = "1040x640+0+30"  # canto superior esquerdo da tela principal


def post_painel(pino: str, tipo: str, unidade: str, valores: list, resumo: str, agente: str | None = None):
    """Manda uma leitura ao painel 8765 (cartão do recurso analisador). Nunca levanta erro nem trava (1 s)."""
    body = {"pino": pino, "tipo": tipo, "unidade": unidade, "valores": [round(v, 1) for v in valores[-120:]],
            "resumo": resumo[:80]}
    if agente:
        body["agente"] = agente
    try:
        req = urllib.request.Request(PAINEL_URL, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=1.0).read()
    except Exception:
        pass


def _close_previous_live():
    try:
        old = int(LIVE_PIDFILE.read_text().strip())
        if old != os.getpid():
            os.kill(old, 15)
            time.sleep(0.5)
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        pass


def run_live(an: "Analyzer", pin: str = "IO1", ms: int = 100, rate: int = 5000, atten: str = "11",
             window_s: float = 30.0, block_ms: float = 10.0, sat_mv: float = 2500.0, duration_s: float = 0,
             agente: str | None = None, painel: bool = True, out=print):
    """Tensão ao vivo numa janela (Tk, canto superior esquerdo): pede trechos de `ms` ao /adc em sequência,
    reduz a médias de `block_ms` e mostra os últimos `window_s`. Fecha a janela 'live' anterior.
    Manda as leituras ao painel 8765 a cada ~1 s. Ao fechar salva o histórico em captures/*_live.csv."""
    import matplotlib
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt

    _close_previous_live()
    CAPTURE_DIR.mkdir(exist_ok=True)
    LIVE_PIDFILE.write_text(str(os.getpid()))
    an.status()  # falha cedo se o ESP não está na rede
    fig, ax = plt.subplots(figsize=(10.4, 6.4), dpi=100)
    try:
        fig.canvas.manager.window.wm_geometry(LIVE_GEOMETRY)
        fig.canvas.manager.set_window_title(f"Analisador ao vivo: {pin}")
    except Exception:
        pass
    line, = ax.plot([], [], lw=1.6, color="#1f77b4")
    ax.axhspan(sat_mv, 3400, color="#d62728", alpha=0.08)
    ax.axhline(sat_mv, color="#d62728", lw=0.8, ls="--")
    ax.text(0.01, sat_mv + 40, f"acima de ~{sat_mv/1000:.1f} V o ADC satura (11 dB)", color="#d62728",
            fontsize=9, transform=ax.get_yaxis_transform())
    ax.set_ylim(-50, 3400); ax.set_xlim(-window_s, 0)
    ax.set_xlabel("tempo (s, 0 = agora)"); ax.set_ylabel("tensão (mV)")
    ax.grid(alpha=0.3)
    txt = ax.text(0.99, 0.95, "", transform=ax.transAxes, ha="right", va="top", fontsize=22, family="monospace")
    sub = ax.text(0.99, 0.86, "", transform=ax.transAxes, ha="right", va="top", fontsize=10, color="#555")
    plt.show(block=False)

    hist_t, hist_mv = [], []
    t_start = time.monotonic(); last_post = 0.0; errors = 0; n_req = 0
    try:
        while plt.fignum_exists(fig.number):
            if duration_s and time.monotonic() - t_start > duration_s:
                break
            try:
                d = parse_adc_csv(an.adc_csv(pin=pin, ms=ms, rate=rate, atten=atten))
                errors = 0; n_req += 1
            except Exception as e:
                errors += 1
                sub.set_text(f"erro: {str(e)[:60]}")
                fig.canvas.draw_idle(); plt.pause(0.5)
                if errors >= 20:
                    out("erro: 20 falhas seguidas, parei"); break
                continue
            now = time.monotonic() - t_start
            us, mv = d["us"], d["mv"]
            if not us:
                plt.pause(0.05); continue
            span = (us[-1] - us[0]) / 1e6 or ms / 1000
            nb = max(1, int(round(span * 1000 / block_ms)))
            per = max(1, len(mv) // nb)
            for i in range(0, len(mv) - per + 1, per):
                hist_mv.append(sum(mv[i:i + per]) / per)
                hist_t.append(now - span + (us[i] - us[0]) / 1e6)
            cut = now - max(window_s, 60)
            while hist_t and hist_t[0] < cut:
                hist_t.pop(0); hist_mv.pop(0)
            line.set_data([t - now for t in hist_t], hist_mv)
            cur = sum(mv) / len(mv)
            vis = [v for t, v in zip(hist_t, hist_mv) if t >= now - window_s]
            txt.set_text(f"{cur/1000:.2f} V")
            sub.set_text(f"{pin}  faixa {min(vis):.0f} a {max(vis):.0f} mV  ({len(mv)} amostras a {rate}/s, "
                         f"ruído ±{(max(mv)-min(mv))/2:.0f} mV)" + ("  SATURADO" if cur >= sat_mv - 30 else ""))
            fig.canvas.draw_idle(); plt.pause(0.01)
            if painel and now - last_post >= 1.0:
                last_post = now
                vals = hist_mv[-120:]
                post_painel(pin, "adc", "mV", vals, f"{pin} {cur:.0f} mV (faixa {min(vals):.0f}-{max(vals):.0f})",
                            agente)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if LIVE_PIDFILE.read_text().strip() == str(os.getpid()):
                LIVE_PIDFILE.unlink()
        except FileNotFoundError:
            pass
        plt.close("all")
    path = None
    if hist_t:
        path = CAPTURE_DIR / f"{datetime.now():%Y%m%d_%H%M%S}_{pin}_live.csv"
        path.write_text("# live_adc v1 t_s,mv (médias de %g ms)\n" % block_ms +
                        "".join(f"{t:.3f},{v:.1f}\n" for t, v in zip(hist_t, hist_mv)))
    out(json.dumps({"requests": n_req, "secs": round(time.monotonic() - t_start, 1),
                    "csv_local": str(path) if path else None}, ensure_ascii=False))


def _fw_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "0")[:3])


def run_series(an: "Analyzer", n: int, ms: int = 1500, trigger: str = "IO10", edge: str = "fall",
               timeout_ms: int = 300000, gap_s: float = 2.0, tag: str = "serie", groups: str | None = None,
               settle_us: float = 5000.0, pull: str = "none", pins: str | None = None, adc_pin: str | None = None,
               adc_rate: int = 20000, adc_atten: str = "11", show: bool = False, out=print) -> dict:
    """N capturas com trigger em sequência (teste de bancada). Uma linha por captura e, no fim, um PNG
    comparativo por grupo (zoom comum no 1o evento)."""
    want_timeout, want_adc = timeout_ms, adc_pin
    st = an.status()
    fw, boot = st.get("fw", ""), st.get("boot")

    def adapt(fw: str):
        """Limites do firmware que está rodando AGORA (pode ter mudado por rollback de OTA)."""
        t, a = want_timeout, want_adc
        if _fw_tuple(fw) < (0, 3, 1):
            if t > 60000:
                out(f"firmware {fw}: timeout limitado a 60000 ms (5 min só a partir do 0.3.1)")
            t = min(t, 60000)
            if a:
                out(f"firmware {fw}: sem captura analógica junto (precisa do 0.3.1); seguindo só com o digital")
                a = None
        return t, a

    timeout_ms, adc_pin = adapt(fw)
    labels = []
    if groups:
        for g in groups.split(","):
            name, _, k = g.partition(":")
            labels += [name.strip()] * int(k or 1)
    labels = (labels + [labels[-1] if labels else ""] * n)[:n]
    caps = []
    for i in range(n):
        lab = labels[i]
        if i:
            # confere se o ESP reiniciou (panic, rollback de OTA) antes de armar de novo; espera ele voltar
            st = None
            for _ in range(30):
                try:
                    st = an.status()
                    break
                except AnalyzerError:
                    time.sleep(2)
            if st is None:
                out("  ESP não respondeu em 60 s; série interrompida")
                break
            if st.get("boot") != boot:
                out(f"  ATENÇÃO: o ESP reiniciou (reset={st.get('reset_reason')}, detalhe={st.get('reset_detail')!r}, "
                    f"panic={st.get('panic', '')!r}, fw={st.get('fw')})")
                boot = st.get("boot")
                if st.get("fw") != fw:
                    fw = st.get("fw", "")
                    timeout_ms, adc_pin = adapt(fw)
        name = f"{tag}_{lab}_{i + 1}" if lab else f"{tag}_{i + 1}"
        out(f"[{i + 1}/{n}] {('grupo ' + lab + ': ') if lab else ''}armado, esperando borda {edge} em {trigger} "
            f"(até {timeout_ms // 1000} s)")
        try:
            r = an.capture(settle_us=settle_us, tag=name, ms=ms, trigger=trigger, edge=edge, timeout_ms=timeout_ms,
                           pull=pull, pins=pins, adc_pin=adc_pin, adc_rate=adc_rate, adc_atten=adc_atten)
        except AnalyzerError as e:
            out(f"  {datetime.now():%H:%M:%S} erro: {e}")
            caps.append({"i": i + 1, "group": lab, "error": str(e)})
            time.sleep(gap_s)
            continue
        p = r["pins"].get(trigger) or next(iter(r["pins"].values()), {})
        evs = p.get("events", [])
        line = (f"  {datetime.now():%H:%M:%S} {r.get('status')}: {p.get('edges', 0)} bordas, {len(evs)} eventos")
        if evs:
            line += f", 1º evento {evs[0]['transitions']} bordas em {_br(evs[0]['bounce_us'])} µs"
        if len(evs) >= 2:
            starts = [e["start_us"] for e in evs]
            per = (starts[-1] - starts[0]) / (len(starts) - 1)
            line += f", rajadas a cada {_br(per / 1000, 2)} ms"
        line += f"  ({Path(r['csv_local']).name})"
        out(line)
        caps.append({"i": i + 1, "group": lab, "csv": r["csv_local"], "status": r.get("status"),
                     "edges": p.get("edges", 0), "events": len(evs),
                     "first_event_us": evs[0]["bounce_us"] if evs else None,
                     "first_start_us": evs[0]["start_us"] if evs else None})
        if i < n - 1:
            time.sleep(gap_s)
    pngs = series_pngs(caps, tag)
    for png in pngs:
        out(f"gráfico: {png}")
    if show and pngs:
        show_png(pngs)
    return {"fw": fw, "timeout_ms": timeout_ms, "adc_pin": adc_pin, "captures": caps, "png": [str(p) for p in pngs]}


def series_pngs(caps: list, tag: str) -> list[Path]:
    """Um PNG por grupo (até 6 painéis por PNG), todos com o mesmo zoom: do início do 1o evento até o
    maior evento da série, com margem."""
    ok = [c for c in caps if c.get("csv")]
    if not ok:
        return []
    spans = [c["first_event_us"] or 0 for c in ok if c.get("first_start_us") is not None]
    span = max(spans) if spans else 0
    margin = max(20.0, 0.2 * span)
    order = []
    for c in ok:
        if c["group"] not in order:
            order.append(c["group"])
    pngs = []
    stamp = f"{datetime.now():%Y%m%d_%H%M%S}"
    for g in order:
        mine = [c for c in ok if c["group"] == g]
        for k in range(0, len(mine), 6):
            part = mine[k:k + 6]
            panels = []
            for c in part:
                s = c["first_start_us"] or 0.0
                ttl = f"#{c['i']}{(' ' + g) if g else ''}: {c['events']} eventos, 1º com {_br(c['first_event_us'] or 0)} µs"
                panels.append((Path(c["csv"]), (s - margin) / 1e3, (s + span + margin) / 1e3, ttl))
            suffix = (f"_{g}" if g else "") + (f"_{k // 6 + 1}" if len(mine) > 6 else "")
            pngs.append(plot_png(panels, CAPTURE_DIR / f"{stamp}_{tag}{suffix}.png",
                                 f"Série {tag}{(': ' + g) if g else ''} (zoom no 1º evento)"))
    return pngs


# ---------------------------------------------------------------------------------------------------
# Gravação contínua (firmware >= 0.4.0): uma janela longa, sem rearmar, com a lista de eventos

def plot_record_png(path: Path, events: list, out: Path, title: str = "", max_events: int = 12) -> Path:
    """PNG 9x9: visão geral da gravação em cima (largura toda) e um zoom por evento embaixo (2 colunas)."""
    import math
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    d = load_plot_data(path)
    evs = events[:max_events]
    rows = 1 + math.ceil(len(evs) / 2)
    fig = plt.figure(figsize=(9, 9), dpi=110)
    gs = fig.add_gridspec(rows, 2, height_ratios=[1.4] + [1] * (rows - 1))
    ax = fig.add_subplot(gs[0, :])
    lo, hi = _data_range_ms(d)
    plot_panel(ax, d, lo, hi, f"gravação inteira: {len(events)} eventos")
    for e in events:
        ax.axvline(e["start_us"] / 1e3, color="#a33", lw=0.5, alpha=0.5)
    for i, e in enumerate(evs):
        a = fig.add_subplot(gs[1 + i // 2, i % 2])
        s, b = e["start_us"], e["bounce_us"]
        margin = max(50.0, 0.2 * b)
        nb = e["transitions"]
        plot_panel(a, d, (s - margin) / 1e3, (s + b + margin) / 1e3,
                   f"#{i + 1} {e.get('kind', '')} {e.get('wall', '')}: {nb} borda{'' if nb == 1 else 's'}, {_br(b)} µs",
                   origin_ms=s / 1e3)
        a.title.set_fontsize(9)
        a.xaxis.label.set_fontsize(8); a.tick_params(labelsize=7)
    if title:
        fig.suptitle(title, fontsize=12)
    fig.tight_layout()
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out)
    plt.close(fig)
    return out


def parse_bursts(text: str) -> list[dict]:
    """Linhas "# burst t0 t1 n final" (rajadas depois do buffer cheio) -> lista em µs."""
    out = []
    for line in text.splitlines():
        if line.startswith("# burst "):
            _, _, t0, t1, n, fin = line.split()
            out.append({"start_us": int(t0) / 240.0, "bounce_us": (int(t1) - int(t0)) / 240.0, "transitions": int(n),
                        "final_level": int(fin), "only_summary": True})
    return out


def run_record(an: "Analyzer", s: int = 120, pins: str = "IO10", pull: str = "none", settle_ms: float = 5.0,
               adc_pin: str | None = None, adc_rate: int = 10000, adc_pre_ms: int = 20, adc_post_ms: int = 80,
               tag: str = "rec", live: bool = False, show: bool = False, out=print) -> dict:
    """Gravação contínua de s segundos no ESP. Sem --live, o Mac não fala com o ESP durante a gravação
    (cada consulta de progresso pausa a varredura por alguns ms). No fim baixa o CSV, lista os eventos
    com a hora e gera o PNG (visão geral + zoom por evento)."""
    fw = an.status().get("fw", "")
    if _fw_tuple(fw) < (0, 4, 0):
        raise AnalyzerError(f"gravação contínua precisa do firmware 0.4.0 ou mais novo (placa: {fw})")
    q = {"s": s, "pins": pins, "pull": pull, "settle_ms": max(1, round(settle_ms))}
    if adc_pin:
        q.update(adc_pin=adc_pin, adc_rate=adc_rate, adc_pre_ms=adc_pre_ms, adc_post_ms=adc_post_ms)
    r = json.loads(an.request("/record?" + urllib.parse.urlencode(q), method="POST", data=b""))
    t_start = time.time()
    out(f"{datetime.fromtimestamp(t_start):%H:%M:%S} gravando {s} s em {pins}"
        f"{' + ADC ' + adc_pin if adc_pin else ''} (até {r.get('max_edges')} bordas). Pode apertar.")
    shown = 0
    try:
        while time.time() - t_start < s:
            time.sleep(min(5.0, max(0.2, s - (time.time() - t_start))))
            if live:
                st = json.loads(an.request("/record/status"))
                n, last = st.get("events", 0), st.get("last_events_s", [])
                first_idx = n - len(last)
                for k in range(max(shown, first_idx), n):
                    ts = t_start + last[k - first_idx]
                    out(f"  evento {k + 1} às {datetime.fromtimestamp(ts):%H:%M:%S}  ({st.get('edges')} bordas até agora)")
                shown = n
            else:
                left = s - (time.time() - t_start)
                if left > 1:
                    out(f"  ... faltam {left:.0f} s")
    except KeyboardInterrupt:
        out("interrompido: encerrando a gravação e baixando o que já foi gravado")
        an.request("/record/stop", method="POST", data=b"")
    text = an.request("/record/data", timeout=s + 120).decode()
    path = save_capture(text, tag)
    dig_txt, _ = split_combined(text)
    parsed = parse_edges_csv(dig_txt)
    res = analyze(parsed, settle_ms * 1000, max_events=5000)
    end = parsed["end"]
    pins_l = [p for p in pins.split(",") if p]
    main_pin = pins_l[0] if pins_l else "IO10"
    events = list(res["pins"].get(main_pin, {}).get("events", []))
    events += parse_bursts(dig_txt)
    idle = parsed["initial"].get(main_pin, 1)
    for e in events:
        e["wall"] = f"{datetime.fromtimestamp(t_start + e['start_us'] / 1e6):%H:%M:%S.%f}"[:-3]
        e["kind"] = "aperto" if e["final_level"] != idle else "soltura"  # repouso = nível inicial
    gaps = {k: int(end.get(k, 0) or 0) for k in ("gaps_over_2us", "gaps_over_10us", "gaps_over_100us", "gaps_over_1ms")}
    n_press = sum(e["kind"] == "aperto" for e in events)
    out(f"{len(events)} eventos em {main_pin}: {n_press} apertos, {len(events) - n_press} solturas ({end.get('total_edges', end.get('edges'))} bordas, status {end.get('status')}); "
        f"pausas da varredura: {gaps['gaps_over_100us']} > 100 µs, {gaps['gaps_over_1ms']} > 1 ms, "
        f"máx {_br(int(end.get('max_gap_cycles', 0) or 0) / 240.0, 1)} µs")
    # apertos reais: pino fica em 0 por >= 20 ms; instante = última descida antes do silêncio (regra do STM32)
    groups = find_presses(text, main_pin, 20.0)
    presses = [g for g in groups if g["kind"] == "aperto"]
    n_noise = sum(g["kind"] == "ruído" for g in groups)
    out(f"apertos reais (0 estável por >= 20 ms): {len(presses)}; grupos de ruído (voltam a 1 sem aperto): {n_noise}")
    for i, g in enumerate(presses):
        g["wall"] = f"{datetime.fromtimestamp(t_start + g['last_fall_us'] / 1e6):%H:%M:%S.%f}"[:-3]
        prev = presses[i - 1]["last_fall_us"] if i else None
        dt = f", {_br((g['last_fall_us'] - prev) / 1000, 3)} ms depois do anterior" if prev else ""
        out(f"  aperto {i + 1}: {g['wall']}  ({g['edges']} bordas no grupo, {_br(g['dur_ms'], 1)} ms de bounce/ruído{dt})")
    png = None
    if presses:
        png = plot_presses_png(path, groups, CAPTURE_DIR / f"{path.stem}.png",
                               title=f"Gravação {tag}: {main_pin}, {datetime.fromtimestamp(t_start):%H:%M:%S}")
    elif events or parsed["rows"]:
        png = plot_record_png(path, [e for e in events if not e.get("only_summary")],
                              CAPTURE_DIR / f"{path.stem}.png",
                              f"Gravação {tag}: {main_pin}, {datetime.fromtimestamp(t_start):%H:%M:%S}")
        out(f"CSV: {path}\ngráfico: {png}")
        if show:
            show_png([png])
    return {"fw": fw, "csv_local": str(path), "png": str(png) if png else None, "events": events, "presses": n_press,
            "real_presses": [{k: g[k] for k in ("wall", "last_fall_us", "edges", "dur_ms")} for g in presses], "end": end,
            "start": datetime.fromtimestamp(t_start).isoformat(timespec="seconds")}


# ---------------------------------------------------------------------------------------------------
# Apertos reais e voltas (mesma regra do cronômetro do STM32: instante = última borda de descida antes
# de silence_ms sem bordas)

def find_presses(text: str, pin: str = "IO10", silence_ms: float = 20.0) -> list[dict]:
    """Agrupa as bordas (e as rajadas resumidas depois do buffer cheio) em grupos separados por silence_ms
    sem bordas. Cada grupo: instante da última descida (regra do STM32), nível em que fica depois e tipo:
    "aperto" (fica em 0, estável por >= silence_ms), "soltura" (volta a 1 logo depois de um aperto) ou
    "ruído" (rajadas que voltam a 1 sem aperto, ex.: 120 Hz do dedo encostado)."""
    dig_txt, _ = split_combined(text)
    parsed = parse_edges_csv(dig_txt)
    hz = float(parsed["meta"].get("cpu_hz", 240_000_000))
    items = [(c / hz * 1e6, c / hz * 1e6, lv, 1, False) for c, p, lv in parsed["rows"] if p == pin]
    for b in parse_bursts(dig_txt):  # (início, fim, nível final, bordas, resumida)
        items.append((b["start_us"], b["start_us"] + b["bounce_us"], b["final_level"], b["transitions"], True))
    items.sort(key=lambda x: x[0])
    groups = []
    for t0, t1, lv, n, summ in items:
        # última descida: exata para borda guardada; numa rajada resumida, o fim dela (se termina em 0) ou
        # aproximada pelo fim (termina em 1 com >= 2 bordas: a última descida está logo antes)
        lf = t1 if lv == 0 else (t1 if summ and n >= 2 else None)
        approx = summ and lv == 1
        if groups and t0 - groups[-1]["end_us"] < silence_ms * 1000:
            g = groups[-1]
            g["end_us"] = max(g["end_us"], t1); g["edges"] += n; g["final_level"] = lv; g["summary"] |= summ
            if lf is not None:
                g["last_fall_us"], g["approx"] = lf, approx
        else:
            groups.append({"start_us": t0, "end_us": t1, "edges": n, "final_level": lv, "summary": summ,
                           "last_fall_us": lf, "approx": approx})
    prev_press = False
    for g in groups:
        if g["final_level"] == 0:
            g["kind"] = "aperto"
        else:
            g["kind"] = "soltura" if prev_press else "ruído"
        prev_press = g["kind"] == "aperto"
        g["dur_ms"] = round((g["end_us"] - g["start_us"]) / 1000, 3)
    return groups


def match_laps(groups: list[dict], ref_ms: list[float], tol: float = 0.02) -> list[dict]:
    """Casa cada volta de referência (ex.: as do STM32, em ordem) com o par de eventos (com descida)
    consecutivos cuja diferença mais se aproxima, avançando no tempo. tol: erro relativo máximo."""
    ev = [g for g in groups if g.get("last_fall_us") is not None]
    out, j = [], 0
    for r in ref_ms:
        best = None
        for a in range(j, len(ev) - 1):
            for b in range(a + 1, min(a + 4, len(ev))):
                lap = (ev[b]["last_fall_us"] - ev[a]["last_fall_us"]) / 1000
                err = abs(lap - r) / r
                # prefere aperto -> aperto: cada ponta que não é aperto custa 0,2% (os relógios diferem ~0,1%)
                score = err + 0.002 * ((ev[a]["kind"] != "aperto") + (ev[b]["kind"] != "aperto"))
                if err <= tol and (best is None or score < best[0]):
                    best = (score, a, b, lap)
        if best:
            _, a, b, lap = best
            out.append({"ref_ms": r, "lap_ms": round(lap, 3), "diff_us": round((lap - r) * 1000, 1),
                        "start": ev[a], "stop": ev[b], "approx": ev[a]["approx"] or ev[b]["approx"]})
            j = b
        else:
            out.append({"ref_ms": r, "lap_ms": None, "diff_us": None, "start": None, "stop": None, "approx": False})
    ok = [m for m in out if m["lap_ms"] and not m["approx"]]
    if len(ok) >= 2:  # razão de relógio (ref/analisador) por mínimos quadrados, e o resíduo
        k = sum(m["ref_ms"] * m["lap_ms"] for m in ok) / sum(m["lap_ms"] ** 2 for m in ok)
        for m in out:
            if m["lap_ms"]:
                m["resid_us"] = round((m["lap_ms"] * k - m["ref_ms"]) * 1000, 1)
        out_k = {"clock_ratio": k, "clock_ppm": round((k - 1) * 1e6)}
        for m in out:
            m.update(out_k)
    return out


def plot_presses_png(path: Path, groups: list[dict], out: Path, zoom: int | None = None, title: str = "") -> Path:
    """PNG 9x9: linha do tempo dos apertos (numerados) + zoom num aperto com o analógico (janela do ADC)
    + zoom do bounce em µs."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    d = load_plot_data(path)
    presses = [g for g in groups if g["kind"] == "aperto"]
    fig, axs = plt.subplots(3, 1, figsize=(9, 9), dpi=110, height_ratios=[1.2, 1, 1])
    if presses:
        lo = presses[0]["start_us"] / 1e3 - 1000
        hi = max(g["end_us"] for g in groups) / 1e3 + 1000
        plot_panel(axs[0], d, lo, hi, f"{len(presses)} apertos (0 estável por >= 20 ms, linhas vermelhas); faixas cheias/cinza = rajadas de ruído")
        axs[0].ticklabel_format(axis="x", useOffset=False, style="plain")
        for i, g in enumerate(presses):
            x = g["last_fall_us"] / 1e3
            axs[0].axvline(x, color="#a33", lw=0.6)
            axs[0].text(x, 1.1, f"{i + 1}", color="#a33", fontsize=7, ha="center")
    # zoom: o aperto pedido, ou o 1o com janela analógica
    adc_t = []
    if d["adc"] and d["adc"]["us"]:
        adc_t = d["adc"]["us"]
    def has_adc(g):
        return any(abs(t - g["last_fall_us"]) < 5000 for t in adc_t[:: max(1, len(adc_t) // 20000)]) if adc_t else False
    pick = None
    if presses:
        if zoom and 1 <= zoom <= len(presses):
            pick = zoom - 1
        else:
            pick = next((i for i, g in enumerate(presses) if has_adc(g)), 0)
        g = presses[pick]
        x = g["last_fall_us"] / 1e3
        plot_panel(axs[1], d, x - 20, x + 80, f"aperto {pick + 1}: 20 ms antes, 80 ms depois", origin_ms=x)
        s0 = g["start_us"] / 1e3
        span = max(0.05, (g["last_fall_us"] - g["start_us"]) / 1e3)
        plot_panel(axs[2], d, s0 - 0.2 * span - 0.01, x + 0.2 * span + 0.01,
                   f"aperto {pick + 1}: bounce ({g['edges']} borda{'' if g['edges'] == 1 else 's'}, última descida em {_br((g['last_fall_us'] - g['start_us']))} µs)",
                   origin_ms=s0)
    if title:
        fig.suptitle(title, fontsize=12)
    fig.tight_layout()
    out = Path(out)
    fig.savefig(out)
    plt.close(fig)
    return out


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
    def plot(panels: list[str] | None = None, auto_csv: str = "", title: str = "", show: bool = False) -> str:
        """PNG quadrado (9x9 pol) de capturas salvas: degraus do digital e mV do analógico no mesmo eixo de
        tempo, contagem de bordas por painel. panels: "arquivo|t0_ms|t1_ms|título" (arquivo em captures/
        ou caminho; t0/t1 vazios = janela inteira). auto_csv: janela inteira + zoom no 1º evento.
        show: abre no Preview (canto superior esquerdo). Devolve o caminho do PNG."""
        pl = [parse_panel(x) for x in (panels or [])]
        if auto_csv:
            pl += auto_panels(resolve_csv(auto_csv))
        if not pl:
            raise AnalyzerError("passe panels ou auto_csv")
        out = plot_png(pl, CAPTURE_DIR / f"{datetime.now():%Y%m%d_%H%M%S}_{pl[0][0].stem}_plot.png", title)
        if show:
            show_png([out])
        return str(out)

    @mcp.tool()
    def record(s: int = 60, pins: str = "IO10", settle_ms: float = 5.0, adc_pin: str = "", adc_rate: int = 10000,
               show: bool = False) -> str:
        """Gravação contínua (firmware >= 0.4.0) de s segundos (até 280) sem rearmar: para testes de bancada com
        vários apertos. Varredura com interrupções ligadas (~1% cego em pausas curtas). Devolve a lista de
        eventos (hora, bordas, duração do bounce), pausas da varredura, CSV e PNG (visão geral + zoom por
        evento). adc_pin: janela analógica por evento (alinhamento aproximado). Bloqueia por s segundos."""
        r = run_record(an, s=s, pins=pins, settle_ms=settle_ms, adc_pin=adc_pin or None, adc_rate=adc_rate,
                       show=show, out=lambda x: None)
        return json.dumps(r, ensure_ascii=False)

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
    p = sub.add_parser("live"); p.add_argument("--pin", default="IO1"); p.add_argument("--ms", type=int, default=100)
    p.add_argument("--rate", type=int, default=5000); p.add_argument("--atten", default="11", choices=["0", "2.5", "6", "11"])
    p.add_argument("--window-s", type=float, default=30); p.add_argument("--duration-s", type=float, default=0)
    p.add_argument("--agente"); p.add_argument("--no-painel", action="store_true")
    p = sub.add_parser("analyze-adc"); p.add_argument("csv")
    p = sub.add_parser("presses"); p.add_argument("csv"); p.add_argument("--pin", default="IO10")
    p.add_argument("--silence-ms", type=float, default=20.0); p.add_argument("--ref", help="voltas de referência em ms, separadas por vírgula")
    p.add_argument("--png", action="store_true"); p.add_argument("--zoom", type=int); p.add_argument("--show", action="store_true")
    p = sub.add_parser("record"); p.add_argument("--s", type=int, default=120); p.add_argument("--pins", default="IO10")
    p.add_argument("--pull", default="none"); p.add_argument("--settle-ms", type=float, default=5.0)
    p.add_argument("--adc-pin"); p.add_argument("--adc-rate", type=int, default=10000)
    p.add_argument("--adc-pre-ms", type=int, default=20); p.add_argument("--adc-post-ms", type=int, default=80)
    p.add_argument("--tag", default="rec"); p.add_argument("--live", action="store_true", help="mostra os eventos ao vivo (cada consulta pausa a varredura ~2 a 9 ms)")
    p.add_argument("--show", action="store_true")
    p = sub.add_parser("plot"); p.add_argument("panels", nargs="*", help='"arquivo|t0_ms|t1_ms|título"')
    p.add_argument("--auto", help="CSV: janela inteira + zoom no 1º evento"); p.add_argument("-o", "--out")
    p.add_argument("--title", default=""); p.add_argument("--show", action="store_true")
    p = sub.add_parser("series"); p.add_argument("--n", type=int, required=True); p.add_argument("--ms", type=int, default=1500)
    p.add_argument("--trigger", default="IO10"); p.add_argument("--edge", default="fall", choices=["fall", "rise", "any"])
    p.add_argument("--timeout-ms", type=int, default=300000); p.add_argument("--gap-s", type=float, default=2.0)
    p.add_argument("--tag", default="serie"); p.add_argument("--groups", help="nome:qtd,nome:qtd (ex. caneta:3,dedo:3)")
    p.add_argument("--pull", default="none"); p.add_argument("--pins"); p.add_argument("--settle-us", type=float, default=5000)
    p.add_argument("--adc-pin"); p.add_argument("--adc-rate", type=int, default=20000)
    p.add_argument("--adc-atten", default="11", choices=["0", "2.5", "6", "11"]); p.add_argument("--show", action="store_true")
    sub.add_parser("mcp")
    a = ap.parse_args()
    if a.cmd == "mcp":
        return run_mcp()
    if a.cmd == "analyze":
        print(json.dumps(analyze_any(Path(a.csv).read_text(), a.settle_us), indent=1))
        return
    if a.cmd == "plot":
        try:
            pl = [parse_panel(x) for x in a.panels]
            if a.auto:
                pl += auto_panels(resolve_csv(a.auto))
            if not pl:
                raise AnalyzerError('passe painéis "arquivo|t0_ms|t1_ms|título" ou --auto arquivo.csv')
            out = Path(a.out) if a.out else CAPTURE_DIR / f"{datetime.now():%Y%m%d_%H%M%S}_{pl[0][0].stem}_plot.png"
            out = plot_png(pl, out, a.title)
        except AnalyzerError as e:
            print(f"erro: {e}", file=sys.stderr)
            sys.exit(2)
        print(out)
        if a.show:
            show_png([out])
        return
    if a.cmd == "presses":
        path = resolve_csv(a.csv)
        groups = find_presses(path.read_text(), a.pin, a.silence_ms)
        pr = [g for g in groups if g["kind"] == "aperto"]
        cnt = {k: sum(g["kind"] == k for g in groups) for k in ("aperto", "soltura", "ruído")}
        print(f"{len(groups)} grupos separados por {_br(a.silence_ms, 0)} ms de silêncio: {cnt['aperto']} apertos, "
              f"{cnt['soltura']} solturas, {cnt['ruído']} de ruído")
        for i, g in enumerate(pr):
            print(f"  aperto {i + 1:2d}: {_br(g['last_fall_us'] / 1e6, 6)} s  ({g['edges']} bordas no grupo, "
                  f"{_br(g['dur_ms'], 1)} ms{', resumido' if g['summary'] else ''})")
        if a.ref:
            ref = [float(x) for x in a.ref.split(",") if x.strip()]
            ms = match_laps(groups, ref)
            print("volta | referência (ms) | analisador (ms) | diferença (µs) | resíduo após razão de relógio (µs) | eventos")
            for i, m in enumerate(ms):
                if m["lap_ms"] is None:
                    print(f"{i + 1} | {_br(m['ref_ms'], 3)} | não achada | | |")
                    continue
                kinds = f"{m['start']['kind']}->{m['stop']['kind']}" + (" (aprox.)" if m["approx"] else "")
                print(f"{i + 1} | {_br(m['ref_ms'], 3)} | {_br(m['lap_ms'], 3)} | {_br(m['diff_us'], 1)} | "
                      f"{_br(m.get('resid_us', 0), 1)} | {kinds}")
            if ms and "clock_ppm" in ms[0]:
                print(f"razão de relógio referência/analisador: {ms[0]['clock_ratio']:.6f} ({ms[0]['clock_ppm']:+d} ppm)")
        if a.png:
            png = plot_presses_png(path, groups, CAPTURE_DIR / f"{path.stem}_apertos.png", a.zoom,
                                   f"{path.stem}: apertos em {a.pin}")
            print(f"gráfico: {png}")
            if a.show:
                show_png([png])
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
        elif a.cmd == "record":
            run_record(an, s=a.s, pins=a.pins, pull=a.pull, settle_ms=a.settle_ms, adc_pin=a.adc_pin, adc_rate=a.adc_rate,
                       adc_pre_ms=a.adc_pre_ms, adc_post_ms=a.adc_post_ms, tag=a.tag, live=a.live, show=a.show,
                       out=lambda x: print(x, flush=True))
        elif a.cmd == "series":
            r = run_series(an, a.n, ms=a.ms, trigger=a.trigger, edge=a.edge, timeout_ms=a.timeout_ms, gap_s=a.gap_s,
                           tag=a.tag, groups=a.groups, settle_us=a.settle_us, pull=a.pull, pins=a.pins,
                           adc_pin=a.adc_pin, adc_rate=a.adc_rate, adc_atten=a.adc_atten, show=a.show,
                           out=lambda x: print(x, flush=True))
            sys.exit(0 if all(c.get("csv") for c in r["captures"]) else 1)
        elif a.cmd == "live":
            run_live(an, pin=a.pin, ms=a.ms, rate=a.rate, atten=a.atten, window_s=a.window_s,
                     duration_s=a.duration_s, agente=a.agente, painel=not a.no_painel)
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
