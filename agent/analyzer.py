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
import urllib.request
from pathlib import Path

HOSTNAME = "logic-s2.local"
TOKEN_FILE = Path.home() / ".config" / "s2la" / "token"


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


def run_mcp():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("logic", instructions=(
        "Analisador lógico pela rede (ESP32-S2 em logic-s2.local). Por enquanto: estado e log do "
        "firmware. A captura de bordas entra numa versão futura."))
    an = Analyzer()

    @mcp.tool()
    def status() -> str:
        """Estado do analisador: firmware, Wi-Fi (ssid, bssid, rssi, ip), uptime, motivo do último reset."""
        return json.dumps(an.status(), ensure_ascii=False)

    @mcp.tool()
    def device_log(previous_boot: bool = False) -> str:
        """Últimas linhas de log do ESP (do boot atual, ou do anterior se previous_boot)."""
        return an.log(previous_boot)

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
    sub.add_parser("mcp")
    a = ap.parse_args()
    if a.cmd == "mcp":
        return run_mcp()
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
        elif a.cmd == "ota":
            res = an.ota(a.bin, a.expect)
            print(json.dumps(res, indent=1, ensure_ascii=False))
            sys.exit(0 if res["ok"] else 1)
    except AnalyzerError as e:
        print(f"erro: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
