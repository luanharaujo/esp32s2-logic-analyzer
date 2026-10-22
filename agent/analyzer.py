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
    uv run agent/analyzer.py analyze captures/x.csv [--settle-us 5000]       # offline
    uv run agent/analyzer.py gen IO10 --hz 1000 [--duty 50] | gen IO10 --hz 0  # gerador de teste no canal
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

    def gen(self, pin: str, hz: int, duty: int = 50) -> dict:
        q = urllib.parse.urlencode({"pin": pin, "hz": hz, "duty": duty})
        return json.loads(self.request(f"/gen?{q}", method="POST", data=b"", auth=True))

    def capture_csv(self, ms: int = 100, trigger: str | None = None, edge: str = "any", timeout_ms: int = 10000,
                    pull: str = "none", pins: str | None = None) -> str:
        """Captura bordas nos canais (CSV gpio_edges v1, ciclos de 240 MHz). Com trigger, espera a borda até
        timeout_ms e captura ms a partir dela."""
        q = {"ms": ms, "edge": edge, "timeout_ms": timeout_ms, "pull": pull}
        if trigger:
            q["trigger"] = trigger
        if pins:
            q["pins"] = pins
        wait = (timeout_ms if trigger else 0) / 1000 + ms / 1000 + 15
        return self.request("/capture?" + urllib.parse.urlencode(q), timeout=wait).decode()

    def capture(self, settle_us: float = 5000.0, tag: str = "capture", **kw) -> dict:
        text = self.capture_csv(**kw)
        path = save_capture(text, tag)
        res = analyze(parse_edges_csv(text), settle_us)
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
           "overflow": int(parsed["end"].get("overflow", 0) or 0), "pins": {}}
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
        "trigger para medir bounce de botão; o resultado já vem analisado."))
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
                pull: str = "none", pins: str = "", settle_us: float = 5000.0) -> str:
        """Captura bordas nos canais do analisador (resolução ~0,1 µs, janela de até 2000 ms).
        trigger: canal (ex. "IO10") cuja borda (edge: rise, fall, any) dispara a captura; vazio = agora.
        timeout_ms: quanto esperar pelo trigger. pull: up/down/none em todos os canais.
        pins: lista "IO10,IO11" (vazio = os 8). settle_us: silêncio que separa eventos (bounce).
        Devolve, por pino, os eventos (duração do bounce, transições, larguras de pulso), frequência
        e duty de sinais periódicos, e o caminho do CSV salvo no Mac."""
        return json.dumps(an.capture(settle_us=settle_us, ms=ms, trigger=trigger or None, edge=edge,
                                     timeout_ms=timeout_ms, pull=pull, pins=pins or None), ensure_ascii=False)

    @mcp.tool()
    def test_generator(pin: str = "IO10", hz: int = 1000, duty: int = 50) -> str:
        """Liga um gerador de onda quadrada (LEDC) no próprio canal para autoteste (hz=0 desliga).
        Só usar com NADA externo ligado nesse pino."""
        return json.dumps(an.gen(pin, hz, duty), ensure_ascii=False)

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
    p = sub.add_parser("analyze"); p.add_argument("csv"); p.add_argument("--settle-us", type=float, default=5000)
    p = sub.add_parser("gen"); p.add_argument("pin"); p.add_argument("--hz", type=int, default=1000); p.add_argument("--duty", type=int, default=50)
    sub.add_parser("mcp")
    a = ap.parse_args()
    if a.cmd == "mcp":
        return run_mcp()
    if a.cmd == "analyze":
        print(json.dumps(analyze(parse_edges_csv(Path(a.csv).read_text()), a.settle_us), indent=1))
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
            print(json.dumps(an.gen(a.pin, a.hz, a.duty)))
        elif a.cmd == "capture":
            print(json.dumps(an.capture(settle_us=a.settle_us, tag=a.tag, ms=a.ms, trigger=a.trigger, edge=a.edge,
                                        timeout_ms=a.timeout_ms, pull=a.pull, pins=a.pins), indent=1, ensure_ascii=False))
        elif a.cmd == "ota":
            res = an.ota(a.bin, a.expect)
            print(json.dumps(res, indent=1, ensure_ascii=False))
            sys.exit(0 if res["ok"] else 1)
    except AnalyzerError as e:
        print(f"erro: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
