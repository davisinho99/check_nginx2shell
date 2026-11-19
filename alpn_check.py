#!/usr/bin/env python3
"""
alpn_check.py - Comprueba si un host acepta HTTP/2 (ALPN h2) y detecta la
version de NGINX para estimar si esta en el rango afectado por
CVE-2026-123007 / CVE-2026-123633 (nginx2shell / nginx2root).

Equivalente ALPN a:
  openssl s_client -connect {HOST}:443 -servername {HOST} -alpn h2 </dev/null 2>&1 \
    | grep -E 'ALPN protocol:|No ALPN negotiated|Connection refused|connect:errno|handshake failure'

Ademas hace una peticion HTTP (HEAD, con fallback a GET) por TLS para leer el
header `Server:` y extraer la version de NGINX.

Clasificacion ALPN:
  H2         -> ALPN protocol: h2        (acepta HTTP/2)
  NO_ALPN    -> No ALPN negotiated       (no acepta HTTP/2)
  FAILED     -> refused / errno / handshake failure / DNS / timeout
  UNKNOWN    -> cualquier otra salida

Clasificacion de version (columnas server / nginx_version / version_vulnerable):
  YES      -> version dentro de los rangos afectados (se listan las CVE)
  NO       -> version >= 1.30.7 (rama stable) o >= 1.31.9 (mainline)
  UNKNOWN  -> sin header Server, version oculta o servidor no-NGINX (CDN, etc.)

Clasificacion de familia (columna server_family):
  nginx      -> Server anuncia nginx/openresty (con o sin version)
  non-nginx  -> Server anuncia otro producto (Apache, IIS, cloudflare, etc.)
  unknown    -> sin header Server o producto no reconocido

potentially_vulnerable solo es YES con H2 y un servidor nginx (o no identificado)
cuya version sea afectada o desconocida. Un servidor claramente no-NGINX nunca
marca YES: las CVE de nginx2shell/nginx2root no le aplican.

Veredicto por host (columna que abre cada linea y el resumen):
  AFECTADO    -> HTTP/2 + nginx afectado o sin version (candidato real, verificar)
  REVISAR     -> HTTP/2 pero sin version, o ALPN indeterminado
  ERROR       -> sin conexion TLS, no verificable (re-escanear)
  NO AFECTADO -> nginx con version ya corregida
  NO EXPUESTO -> no negocia HTTP/2
  NO APLICA   -> servidor no-NGINX (las CVE de nginx no aplican)

Uso:
  ./alpn_check.py dominios.txt
  ./alpn_check.py dominios.txt --workers 30 --timeout 8 --csv out.csv
  cat dominios.txt | ./alpn_check.py -
  ./alpn_check.py dominio1.com dominio2.com:8443
  ./alpn_check.py dominios.txt --no-version   # solo ALPN, sin pedir version
"""

import argparse
import csv
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


class C:
    """Codigos ANSI para colorear la salida."""
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    ORANGE = "\033[38;5;208m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    enabled = True

    @classmethod
    def paint(cls, text, color):
        if not cls.enabled or not color:
            return text
        return f"{color}{text}{cls.RESET}"


# Colores por veredicto: rojo = exposicion confirmada, naranja = no verificable,
# amarillo = a revisar, verde = sin exposicion.
VERDICT_COLORS = {
    "AFECTADO": C.RED,
    "REVISAR": C.YELLOW,
    "ERROR": C.ORANGE,
    "NO AFECTADO": C.GREEN,
    "NO EXPUESTO": C.GREEN,
    "NO APLICA": C.GREEN,
}


def verdict_of(r: dict):
    """Devuelve (etiqueta, motivo) para un resultado.

    AFECTADO    -> HTTP/2 + nginx (o servidor no identificado) con version afectada
                   o desconocida: candidato real, verificar a mano.
    REVISAR     -> HTTP/2 pero sin version, o ALPN indeterminado.
    ERROR       -> no se pudo conectar (no verificable).
    NO AFECTADO -> nginx con version ya corregida.
    NO EXPUESTO -> no negocia HTTP/2.
    NO APLICA   -> servidor no-NGINX: las CVE de nginx no le afectan.
    """
    if r["status"] == "FAILED":
        return "ERROR", "sin conexion TLS"
    if r["potentially_vulnerable"] == "YES":
        return "AFECTADO", "HTTP/2 + nginx afectado o sin version"
    if r["server_family"] == "non-nginx":
        return "NO APLICA", "servidor no-NGINX"
    if r["version_vulnerable"] == "NO":
        return "NO AFECTADO", "nginx ya corregido"
    if r["status"] == "NO_ALPN":
        return "NO EXPUESTO", "no negocia ALPN h2"
    return "REVISAR", "version o ALPN sin determinar"


FAIL_REASON = (
    (r"Name or service not known|getaddrinfo|no such host", "DNS no resuelve"),
    (r"Connection refused", "conexion rechazada"),
    (r"timed out|timeout|sin respuesta", "timeout/filtrado"),
    (r"handshake failure", "handshake TLS fallido"),
    (r"no peer certificate available", "sin certificado TLS"),
    (r"Connection reset by peer", "conexion reseteada"),
    (r"Network is unreachable", "red inalcanzable"),
)


def short_detail(r: dict):
    """Quita el detalle redundante que ya se ve en las columnas status/version."""
    d = r["detail"]
    if r["status"] == "FAILED":
        for pattern, reason in FAIL_REASON:
            if re.search(pattern, d, re.IGNORECASE):
                return reason
    for noise in ("ALPN protocol: h2", "No ALPN negotiated"):
        d = d.replace(noise, "")
    d = " | ".join(p.strip() for p in d.split("|") if p.strip())
    return d or "-"


def version_text(r: dict):
    """Columna corta con la version de NGINX o el producto anunciado."""
    if r["server_family"] == "non-nginx":
        return r["server"]
    if r["nginx_version"] != "-":
        return f"nginx/{r['nginx_version']}"
    if r["server"] != "-":
        return r["server"]
    return "-"


# ---------------------------------------------------------------------------
# Rangos afectados (avisos de NGINX del 18-nov-2026)
#   CVE-2026-123007 (HTTP/2 flow control): 1.9.5 - 1.31.8
#   CVE-2026-123633 (HTTP/2 use-after-free): 1.19.7 - 1.31.8
#   Corregido en NGINX 1.30.7 (stable) y 1.31.9 (mainline).
# ---------------------------------------------------------------------------
VULN_007_MIN = (1, 9, 5)
VULN_633_MIN = (1, 19, 7)
VULN_MAX = (1, 31, 8)
FIXED_STABLE_MIN = (1, 30, 7)     # 1.30.7+ de la rama stable ya no es vulnerable
FIXED_MAINLINE_MIN = (1, 31, 9)   # 1.31.9+ de la rama mainline ya no es vulnerable

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
    """Negocia TLS pidiendo ALPN h2 y clasifica la respuesta."""
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


def parse_nginx_version(server: str):
    """Extrae la version de NGINX del header Server.

    Soporta 'nginx/1.31.8', 'openresty/1.25.3.1' (base nginx) y variantes con
    sufijos tipo 'nginx/1.31.8 (Ubuntu)'. Devuelve una tupla (x, y, z) o None.
    """
    if not server:
        return None
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", server, re.IGNORECASE)
    if not m:
        m = re.search(r"openresty/(\d+)\.(\d+)\.(\d+)", server, re.IGNORECASE)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


# Firmas de productos que no son NGINX: las CVE de nginx2shell/nginx2root no aplican.
NON_NGINX_RE = re.compile(
    r"\b(?:apache|httpd|litespeed|openlitespeed|iis|microsoft-iis|microsoft-httpapi|"
    r"cloudfront|cloudflare|gws|google\s+frontend|envoy|caddy|lighttpd|tomcat|jetty|"
    r"gunicorn|uvicorn|werkzeug|kestrel|varnish|haproxy|traefik|akamai|nginx-unit)\b",
    re.IGNORECASE,
)


def classify_server(server: str):
    """Clasifica el header Server como 'nginx', 'non-nginx' o 'unknown'.

    'nginx' incluye openresty (base NGINX) y nginx sin version anunciada.
    'non-nginx' es un producto conocido que no es NGINX (Apache, cloudflare, IIS...).
    'unknown' es un header ausente o un producto no reconocido.
    """
    if not server or server.strip() in ("", "-"):
        return "unknown"
    if re.search(r"\bnginx-unit\b", server, re.IGNORECASE):
        return "non-nginx"  # NGINX Unit no es el servidor HTTP de nginx
    if parse_nginx_version(server):
        return "nginx"
    if re.search(r"\b(?:nginx|openresty)\b", server, re.IGNORECASE):
        return "nginx"
    if NON_NGINX_RE.search(server):
        return "non-nginx"
    return "unknown"


def affected_cves(version):
    """Devuelve la lista de CVE que afectan a esa version de NGINX."""
    if version is None:
        return []
    if version >= FIXED_MAINLINE_MIN:
        return []
    if FIXED_STABLE_MIN <= version < (1, 31, 0):
        return []
    cves = []
    if VULN_007_MIN <= version <= VULN_MAX:
        cves.append("CVE-2026-123007")
    if VULN_633_MIN <= version <= VULN_MAX:
        cves.append("CVE-2026-123633")
    return cves


def fetch_server_info(host: str, port: int, timeout: int):
    """Hace una peticion HTTP/1.1 por TLS y devuelve (server, version, nota).

    Primero prueba HEAD y, si la respuesta no trae header Server, reintenta con
    GET. No verifica el certificado (es un escaneo, no una conexion de confianza).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    host_header = f"[{host}]" if ":" in host else host
    note = ""

    for method in ("HEAD", "GET"):
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    req = (
                        f"{method} / HTTP/1.1\r\n"
                        f"Host: {host_header}\r\n"
                        "User-Agent: Mozilla/5.0 (compatible; alpn_check)\r\n"
                        "Accept: */*\r\n"
                        "Connection: close\r\n\r\n"
                    )
                    ssock.sendall(req.encode())
                    data = b""
                    while b"\r\n\r\n" not in data and len(data) < 16384:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
        except (socket.timeout, TimeoutError):
            return None, None, f"timeout version ({timeout}s)"
        except ssl.SSLError as e:
            return None, None, f"TLS error version: {e}"
        except OSError as e:
            return None, None, f"error version: {e}"

        head = data.split(b"\r\n\r\n", 1)[0]
        server = None
        for line in head.decode("latin-1", "replace").split("\r\n")[1:]:
            name, sep, value = line.partition(":")
            if sep and name.strip().lower() == "server":
                server = value.strip()
                break
        if server:
            return server, parse_nginx_version(server), ""
        note = f"{method}: respuesta sin header Server"

    return None, None, note


def check_full(host: str, port: int, timeout: int, do_version: bool = True):
    """Ejecuta el chequeo ALPN y, si procede, la deteccion de version."""
    r = check(host, port, timeout)
    r.update({
        "server": "-",
        "server_family": "unknown",
        "nginx_version": "-",
        "version_vulnerable": "UNKNOWN",
        "cves": "",
    })

    if do_version and r["status"] != "FAILED":
        server, version, note = fetch_server_info(host, port, timeout)
        if server:
            r["server"] = server
            r["server_family"] = classify_server(server)
        if version:
            r["nginx_version"] = ".".join(str(x) for x in version)
            cves = affected_cves(version)
            r["version_vulnerable"] = "YES" if cves else "NO"
            r["cves"] = ",".join(cves)
        elif server:
            if r["server_family"] == "non-nginx":
                note = f"Servidor no-NGINX ({server}): CVEs de nginx no aplican"
            else:
                note = f"Server sin version de NGINX: {server}"
        if note:
            r["detail"] += f" | {note}"

    # Exposicion combinada: hace falta HTTP/2, un servidor nginx (o no identificado)
    # y una version afectada o desconocida.
    if r["status"] != "H2":
        r["potentially_vulnerable"] = "NO"
    elif r["server_family"] == "non-nginx":
        r["potentially_vulnerable"] = "NO"
    elif r["version_vulnerable"] == "NO":
        r["potentially_vulnerable"] = "NO"
    else:
        r["potentially_vulnerable"] = "YES"

    return r


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
        description="Comprueba ALPN h2 (HTTP/2) y version de NGINX por TLS.")
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
    ap.add_argument("--no-version", action="store_true",
                    help="no pedir el header Server (solo chequeo ALPN)")
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

    # anchos para alinear la linea por host
    counter_width = len(str(len(targets)))
    host_width = min(
        max((len(f"{h}:{p}") for h, p in targets), default=1), 40)

    print(f"[*] {len(targets)} hosts | workers={args.workers} | timeout={args.timeout}s "
          f"| version={'si' if not args.no_version else 'no'}",
          file=sys.stderr)

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {
            ex.submit(check_full, h, p, args.timeout, not args.no_version): (h, p)
            for h, p in targets
        }
        for i, fut in enumerate(as_completed(futs), 1):
            r = fut.result()
            results.append(r)
            if not args.quiet:
                label, _ = verdict_of(r)
                color = VERDICT_COLORS[label]
                hostport = f"{r['host']}:{r['port']}"
                if label == "AFECTADO":
                    note = r["cves"] or "version desconocida"
                elif label == "NO APLICA":
                    note = "CVEs de nginx no aplican"
                elif label == "NO AFECTADO":
                    note = "-"
                elif label == "NO EXPUESTO":
                    if r["version_vulnerable"] == "YES":
                        note = "version afectada, pero no negocia h2"
                    else:
                        note = short_detail(r)
                else:
                    note = short_detail(r)
                print(C.paint(
                    f"[{i:>{counter_width}}/{len(targets)}] {label:<11} "
                    f"{hostport:<{host_width}}  {version_text(r):<20}  {note}",
                    color), flush=True)

    order = {"H2": 0, "NO_ALPN": 1, "UNKNOWN": 2, "FAILED": 3}
    results.sort(key=lambda r: (order.get(r["status"], 9), r["host"]))

    # El veredicto va al CSV para que se pueda leer sin la salida de terminal.
    for r in results:
        r["verdict"], r["verdict_reason"] = verdict_of(r)

    with open(args.csv, "w", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["host", "port", "status", "alpn", "tls", "server",
                        "server_family", "nginx_version", "version_vulnerable",
                        "potentially_vulnerable", "cves", "detail",
                        "verdict", "verdict_reason"],
        )
        w.writeheader()
        w.writerows(results)

    groups = {}
    for r in results:
        groups.setdefault(verdict_of(r)[0], []).append(r)

    affected = groups.get("AFECTADO", [])
    review = groups.get("REVISAR", [])
    errors = groups.get("ERROR", [])
    safe = (groups.get("NO AFECTADO", [])
            + groups.get("NO EXPUESTO", [])
            + groups.get("NO APLICA", []))

    def section(title, items, color, note_fn):
        if not items:
            return
        print(C.paint(f"\n  {title} ({len(items)}):", color), file=sys.stderr)
        for r in items:
            hostport = f"{r['host']}:{r['port']}"
            print(C.paint(
                f"    - {hostport:<{host_width}}  {version_text(r):<20}  {note_fn(r)}",
                color), file=sys.stderr)

    print("\n=== RESUMEN ===", file=sys.stderr)
    print(f"  Analizados: {len(results)}  |  "
          + C.paint(f"AFECTADOS: {len(affected)}", C.RED)
          + "  |  " + C.paint(f"A REVISAR: {len(review)}", C.YELLOW)
          + "  |  " + C.paint(f"ERRORES: {len(errors)}", C.ORANGE)
          + "  |  " + C.paint(f"NO AFECTADOS: {len(safe)}", C.GREEN),
          file=sys.stderr)

    section("AFECTADOS (HTTP/2 + nginx afectado o sin version)",
            affected, C.RED, lambda r: r["cves"] or "version desconocida")
    section("A REVISAR (HTTP/2 sin version, o ALPN indeterminado)",
            review, C.YELLOW, short_detail)
    section("ERRORES (sin conexion, no verificables: re-escanear)",
            errors, C.ORANGE, short_detail)

    if safe:
        print(C.paint(f"\n  NO AFECTADOS ({len(safe)}):", C.GREEN),
              file=sys.stderr)
        for label, desc in (("NO EXPUESTO", "sin HTTP/2"),
                            ("NO AFECTADO", "nginx ya corregido"),
                            ("NO APLICA", "servidor no-NGINX")):
            items = groups.get(label, [])
            if items:
                print(C.paint(
                    f"      {label:<12} {len(items):>3}  ({desc})", C.GREEN),
                    file=sys.stderr)
        print("      verde = sin exposicion a estas CVE; no implica un host seguro",
              file=sys.stderr)

    print(f"\n[+] CSV: {os.path.abspath(args.csv)}", file=sys.stderr)


if __name__ == "__main__":
    main()
