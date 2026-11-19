#!/usr/bin/env python3
"""
alpn_check.py - Comprueba si un host acepta HTTP/2 (ALPN h2) desde Internet.

Equivalente a:
  openssl s_client -connect {HOST}:443 -servername {HOST} -alpn h2 </dev/null 2>&1 \
    | grep -E 'ALPN protocol:|No ALPN negotiated|Connection refused|connect:errno|handshake failure'

Clasificacion:
  H2         -> ALPN protocol: h2        (acepta HTTP/2)
  NO_ALPN    -> No ALPN negotiated       (no acepta HTTP/2)
  FAILED     -> refused / errno / handshake failure / DNS / timeout
  UNKNOWN    -> cualquier otra salida

Uso:
  ./alpn_check.py dominios.txt
  ./alpn_check.py dominios.txt --workers 30 --timeout 8 --csv out.csv
  cat dominios.txt | ./alpn_check.py -
  ./alpn_check.py dominio1.com dominio2.com:8443
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


class C:
    """Codigos ANSI para colorear la salida."""
    GREEN = "\033[32m"
    RED = "\033[31m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    enabled = True

    @classmethod
    def paint(cls, text, color):
        if not cls.enabled or not color:
            return text
        return f"{color}{text}{cls.RESET}"


def status_color(status: str):
    """Verde si hay ALPN (H2), rojo si no hay ALPN o fallo."""
    if status == "H2":
        return C.GREEN
    return C.RED


def vulnerability(status: str) -> str:
    """Clasificacion de exposicion a nginx2shell / nginx2root.

    Las CVE-2026-123007 y CVE-2026-123633 (RCE no autenticado en NGINX)
    requieren HTTP/2 habilitado sobre TLS. Si el host negocia ALPN h2 es
    candidato; si no lo negocia no esta expuesto por esta via.
      H2                -> YES      (HTTP/2 activo: potencialmente vulnerable)
      NO_ALPN           -> NO       (no negocia h2)
      FAILED / UNKNOWN  -> UNKNOWN  (no se pudo verificar)
    """
    if status == "H2":
        return "YES"
    if status == "NO_ALPN":
        return "NO"
    return "UNKNOWN"

OPENSSL = shutil.which("openssl") or "/usr/bin/openssl"
TIMEOUT_BIN = shutil.which("timeout")

ALPN_RE = re.compile(r"ALPN protocol:\s*(\S+)")
TLS_RE = re.compile(r"^\s*(?:New|Protocol)\s*:\s*(\S+)", re.MULTILINE)
NO_ALPN_RE = re.compile(r"No ALPN negotiated", re.IGNORECASE)
FAIL_RE = re.compile(
    r"Connection refused|connect:errno|Connection timed out|Network is unreachable|"
    r"handshake failure|no peer certificate available|"
    r"Name or service not known|getaddrinfo|no such host|"
    r"unable to connect|socket error|Connection reset by peer",
    re.IGNORECASE,
)


def normalize(raw: str):
    """Devuelve (host, port) o None. Acepta URLs, host:puerto, comentarios."""
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    # quitar esquema y ruta
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    s = s.strip().lower()
    if not s:
        return None
    port = None
    if s.startswith("["):  # IPv6 [::1]:443
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", s)
        if m:
            return m.group(1), int(m.group(2) or 443)
        return None
    if s.count(":") == 1:
        host, _, p = s.partition(":")
        if p.isdigit():
            port = int(p)
            s = host
    elif s.count(":") > 1:
        return s, 443  # IPv6 sin puerto
    return s, port or 443


def check(host: str, port: int, timeout: int):
    cmd = [OPENSSL, "s_client", "-connect", f"{host}:{port}",
           "-servername", host, "-alpn", "h2"]
    if TIMEOUT_BIN:
        cmd = [TIMEOUT_BIN, f"{timeout}s"] + cmd

    try:
        p = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout + 5,
        )
        out = p.stdout.decode("utf-8", "replace")
        rc = p.returncode
    except subprocess.TimeoutExpired:
        return {"host": host, "port": port, "status": "FAILED",
                "alpn": "-", "tls": "-", "detail": "timeout (proceso colgado)"}
    except FileNotFoundError:
        sys.exit(f"[!] No se encontro el binario openssl ({OPENSSL})")
    except Exception as e:  # noqa: BLE001
        return {"host": host, "port": port, "status": "FAILED",
                "alpn": "-", "tls": "-", "detail": f"error local: {e}"}

    tls_m = TLS_RE.search(out)
    tls = tls_m.group(1) if tls_m else "-"

    # timeout(1) mata openssl con rc=124 cuando el host no responde
    if rc == 124 or (rc != 0 and not out.strip()):
        return {"host": host, "port": port, "status": "FAILED",
                "alpn": "-", "tls": "-",
                "detail": f"sin respuesta en {timeout}s (timeout/filtrado)"}

    alpn_m = ALPN_RE.search(out)
    if alpn_m:
        proto = alpn_m.group(1).strip()
        if proto.lower() == "h2":
            return {"host": host, "port": port, "status": "H2",
                    "alpn": proto, "tls": tls, "detail": "ALPN protocol: h2"}
        return {"host": host, "port": port, "status": "NO_ALPN",
                "alpn": proto, "tls": tls,
                "detail": f"ALPN negociado distinto de h2: {proto}"}

    if NO_ALPN_RE.search(out):
        return {"host": host, "port": port, "status": "NO_ALPN",
                "alpn": "-", "tls": tls, "detail": "No ALPN negotiated"}

    if FAIL_RE.search(out):
        line = next((l.strip() for l in out.splitlines() if FAIL_RE.search(l)), "")
        return {"host": host, "port": port, "status": "FAILED",
                "alpn": "-", "tls": tls, "detail": line[:200]}

    if rc != 0:
        return {"host": host, "port": port, "status": "FAILED",
                "alpn": "-", "tls": tls,
                "detail": f"openssl rc={rc}, salida inesperada: {out.strip()[:150]}"}

    snippet = " ".join(out.split())[:200] or "sin salida"
    return {"host": host, "port": port, "status": "UNKNOWN",
            "alpn": "-", "tls": tls, "detail": snippet}


def load_targets(args):
    targets, seen = [], set()
    for item in args.inputs:
        if item == "-":
            lines = sys.stdin.read().splitlines()
        elif os.path.isfile(item):
            with open(item, "r", errors="replace") as fh:
                lines = fh.read().splitlines()
        else:
            lines = [item]
        for raw in lines:
            t = normalize(raw)
            if not t:
                continue
            host, port = t
            if args.port:
                port = args.port
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            targets.append(key)
    return targets


def main():
    ap = argparse.ArgumentParser(
        description="Comprueba ALPN h2 (HTTP/2) por TLS en una lista de dominios.")
    ap.add_argument("inputs", nargs="+",
                    help="ficheros con dominios, o '-' para stdin, o hosts sueltos")
    ap.add_argument("-p", "--port", type=int, default=0,
                    help="forzar puerto para todos los hosts (por defecto 443 o el indicado con host:puerto)")
    ap.add_argument("-w", "--workers", type=int, default=20,
                    help="hilos en paralelo (por defecto 20)")
    ap.add_argument("-t", "--timeout", type=int, default=10,
                    help="timeout por host en segundos (por defecto 10)")
    ap.add_argument("-o", "--csv", default="alpn_results.csv",
                    help="fichero CSV de salida (por defecto alpn_results.csv)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="no imprimir resultado por host (solo resumen)")
    ap.add_argument("--no-color", action="store_true",
                    help="desactivar colores ANSI en la salida")
    ap.add_argument("--color", action="store_true",
                    help="forzar colores aunque la salida no sea una terminal")
    args = ap.parse_args()

    # por defecto colores solo si la salida es una terminal
    C.enabled = args.color or (
        not args.no_color
        and not os.environ.get("NO_COLOR")
        and sys.stdout.isatty()
    )

    if not shutil.which("openssl") and not os.path.exists(OPENSSL):
        sys.exit("[!] openssl no esta instalado.")

    targets = load_targets(args)
    if not targets:
        sys.exit("[!] No hay hosts validos que comprobar.")

    print(f"[*] {len(targets)} hosts | workers={args.workers} | timeout={args.timeout}s",
          file=sys.stderr)

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(check, h, p, args.timeout): (h, p) for h, p in targets}
        for i, fut in enumerate(as_completed(futs), 1):
            r = fut.result()
            results.append(r)
            if not args.quiet:
                color = status_color(r["status"])
                print(C.paint(
                    f"[{i}/{len(targets)}] {r['status']:<8} "
                    f"{r['host']}:{r['port']}  tls={r['tls']}  {r['detail']}",
                    color), flush=True)

    for r in results:
        r["potentially_vulnerable"] = vulnerability(r["status"])

    order = {"H2": 0, "NO_ALPN": 1, "UNKNOWN": 2, "FAILED": 3}
    results.sort(key=lambda r: (order.get(r["status"], 9), r["host"]))

    with open(args.csv, "w", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["host", "port", "status", "alpn", "tls",
                        "potentially_vulnerable", "detail"],
        )
        w.writeheader()
        w.writerows(results)

    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    print("\n=== RESUMEN ===", file=sys.stderr)
    for k in ("H2", "NO_ALPN", "UNKNOWN", "FAILED"):
        if k in counts:
            print(C.paint(f"  {k:<8} {counts[k]}", status_color(k)),
                  file=sys.stderr)
    vuln = sum(1 for r in results if r["potentially_vulnerable"] == "YES")
    print(C.paint(f"\n  Potencialmente vulnerables (nginx2shell): {vuln}",
                  C.GREEN if vuln else C.RED), file=sys.stderr)
    h2 = [r["host"] for r in results if r["status"] == "H2"]
    if h2:
        print(C.paint("\n  Hosts con HTTP/2 (h2):", C.GREEN), file=sys.stderr)
        for h in h2:
            print(C.paint(f"    - {h}", C.GREEN), file=sys.stderr)
    no_alpn = [f"{r['host']}:{r['port']}" for r in results if r["status"] != "H2"]
    if no_alpn:
        print(C.paint("\n  Hosts sin ALPN h2:", C.RED), file=sys.stderr)
        for h in no_alpn:
            print(C.paint(f"    - {h}", C.RED), file=sys.stderr)
    print(f"\n[+] CSV: {os.path.abspath(args.csv)}", file=sys.stderr)


if __name__ == "__main__":
    main()
