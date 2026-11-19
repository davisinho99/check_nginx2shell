# check_nginx2shell

**`alpn_check.py`** — Comprobador masivo de **HTTP/2 vía ALPN (`h2`)** sobre TLS.

La herramienta se conecta a cada host de una lista, negocia TLS con `openssl s_client`
solicitando el protocolo ALPN `h2` y clasifica el resultado. Sirve como **chequeo de
superficie** para determinar qué servidores tienen HTTP/2 activo sobre TLS y, por tanto,
qué servidores son *candidatos* a verse afectados por vulnerabilidades que requieren
HTTP/2 (p. ej. la familia `nginx2shell` / `nginx2root`).

> ⚠️ **Aviso:** esta herramienta **no explota** nada. Solo verifica si el host negocia
> ALPN `h2`. Que un host tenga HTTP/2 activo **no** implica que sea vulnerable: hay que
> confirmar la versión del servidor y la CVE concreta.

---

## Tabla de contenidos

- [Cómo funciona](#cómo-funciona)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Uso](#uso)
- [Formato de entrada](#formato-de-entrada)
- [Estados y clasificación](#estados-y-clasificación)
- [Salida CSV](#salida-csv)
- [Ejemplos](#ejemplos)
- [Rendimiento y límites](#rendimiento-y-límites)
- [Solución de problemas](#solución-de-problemas)
- [Descargo de responsabilidad](#descargo-de-responsabilidad)
- [Licencia](#licencia)

---

## Cómo funciona

Por cada objetivo se ejecuta el equivalente a:

```bash
openssl s_client -connect HOST:443 -servername HOST -alpn h2 </dev/null 2>&1
```

y se parsea la salida buscando:

| Patrón en la salida                  | Estado     | Significado                          |
| ------------------------------------ | ---------- | ------------------------------------ |
| `ALPN protocol: h2`                  | `H2`       | HTTP/2 negociado                     |
| `ALPN protocol: <otro>`              | `NO_ALPN`  | Negocia ALPN, pero no `h2`           |
| `No ALPN negotiated`                 | `NO_ALPN`  | El servidor no negocia ALPN          |
| `Connection refused`, `connect:errno`, `handshake failure`, DNS, reset, etc. | `FAILED` | No se pudo completar la conexión TLS |
| Cualquier otra salida                | `UNKNOWN`  | Salida no reconocida                 |

Las comprobaciones se lanzan **en paralelo** con un `ThreadPoolExecutor`, y cada una
queda acotada por `timeout(1)` (si está disponible) además del timeout interno de Python,
para evitar que `openssl` se quede colgado.

---

## Requisitos

- **Python 3.8+** (solo biblioteca estándar, sin dependencias externas)
- **OpenSSL** en el `PATH` (`openssl s_client` con soporte ALPN — cualquier versión moderna)
- Opcional: `timeout` de coreutils (Linux/macOS) para el corte duro de procesos

```bash
python3 --version   # >= 3.8
openssl version
```

---

## Instalación

```bash
git clone https://github.com/davisinho99/check_nginx2shell.git
cd check_nginx2shell
chmod +x alpn_check.py
./alpn_check.py --help
```

No hace falta `pip install` ni entorno virtual.

---

## Uso

```
./alpn_check.py <inputs>... [opciones]
```

| Argumento | Descripción | Por defecto |
| --------- | ----------- | ----------- |
| `inputs`  | Ficheros de dominios, `-` para leer de **stdin**, o hosts sueltos | *(obligatorio)* |
| `-p, --port` | Forzar un puerto para **todos** los hosts | `443` o el de `host:puerto` |
| `-w, --workers` | Nº de hilos en paralelo | `20` |
| `-t, --timeout` | Timeout por host, en segundos | `10` |
| `-o, --csv` | Ruta del CSV de salida | `alpn_results.csv` |
| `-q, --quiet` | No imprimir resultado por host (solo el resumen) | desactivado |
| `--no-color` | Desactivar colores ANSI | auto |
| `--color` | Forzar colores aunque no sea TTY | auto |

Los colores se activan automáticamente solo si la salida es una terminal y no está
definida la variable `NO_COLOR`.

---

## Formato de entrada

Un objetivo por línea. El parser es tolerante y normaliza lo que le eches:

```text
# Comentarios y líneas vacías se ignoran
example.com
example.com:8443
https://example.com/ruta?x=1     # se queda con el host
HTTP://EXAMPLE.COM               # se normaliza a minúsculas
192.0.2.10
[2001:db8::1]:443                # IPv6 con puerto
2001:db8::1                      # IPv6 sin puerto -> 443
```

Los duplicados (`host`, `puerto`) se eliminan automáticamente.

---

## Estados y clasificación

Cada resultado incluye una columna derivada `potentially_vulnerable`:

| `status`   | `potentially_vulnerable` | Motivo |
| ---------- | ------------------------ | ------ |
| `H2`       | `YES`      | HTTP/2 activo: candidato a CVE que requieran h2 |
| `NO_ALPN`  | `NO`       | No negocia `h2`, no expuesto por esta vía |
| `FAILED`   | `UNKNOWN`  | No verificable (filtrado, caído, DNS) |
| `UNKNOWN`  | `UNKNOWN`  | Salida no interpretable |

`YES` significa **"hay que mirar más"**, no "vulnerable confirmado".

---

## Salida CSV

Se escribe siempre un CSV ordenado por severidad (`H2` → `NO_ALPN` → `UNKNOWN` → `FAILED`)
con las columnas:

```csv
host,port,status,alpn,tls,potentially_vulnerable,detail
example.com,443,H2,h2,TLSv1.3,YES,ALPN protocol: h2
otro.com,443,NO_ALPN,-,TLSv1.2,NO,No ALPN negotiated
```

El resumen final (conteos por estado y listado de hosts con/sin `h2`) se imprime por `stderr`,
de modo que la salida por host en `stdout` se puede redirigir/pipear limpiamente.

---

## Ejemplos

```bash
# Lista de dominios desde fichero
./alpn_check.py dominios.txt

# Más paralelismo y timeout más agresivo, CSV personalizado
./alpn_check.py dominios.txt -w 50 -t 5 -o resultados.csv

# Leer de stdin
cat dominios.txt | ./alpn_check.py -

# Hosts sueltos, forzando puerto
./alpn_check.py ejemplo.com ejemplo.org:8443 -p 443

# Solo el resumen (sin línea por host), sin colores
./alpn_check.py dominios.txt -q --no-color

# Guardar el detalle por host y ver solo el resumen
./alpn_check.py dominios.txt > detalle.log
```

---

## Rendimiento y límites

- **20 workers / 10 s** por defecto: buen equilibrio para listas de cientos de hosts.
- Cada host consume un proceso `openssl`; con `-w` muy alto puedes saturar CPU/FDs.
  Baja `-w` si ves `fork: Resource temporarily unavailable` o timeouts falsos.
- Hosts filtrados (sin respuesta) consumen el timeout completo. Si tu lista tiene mucho
  ruido, prueba `-t 5` y sube `-w` en consecuencia.
- El tool hace **una** conexión TLS por host: es ruidoso en logs del servidor y puede
  disparar rate-limits/WAF. Úsalo con cabeza.

---

## Solución de problemas

| Síntoma | Causa probable | Solución |
| ------- | -------------- | -------- |
| `[!] openssl no esta instalado.` | No hay `openssl` en `PATH` | Instálalo (`apt install openssl`) |
| Muchos `FAILED` con "sin respuesta" | Firewall/egress filtrado | Prueba desde otra red; sube `-t` |
| Todo `NO_ALPN` en hosts que sí tienen HTTP/2 | Servidor requiere SNI/ALPN distinto o CDN delante | Verifica manualmente con `openssl s_client` |
| Colores raros en pipes | TTY detectado incorrectamente | Usa `--no-color` o `NO_COLOR=1` |

Depuración manual de un host concreto:

```bash
openssl s_client -connect example.com:443 -servername example.com -alpn h2 </dev/null 2>&1 | grep -i alpn
```

---

## Descargo de responsabilidad

Esta herramienta está pensada para **auditorías autorizadas** y para verificar tu propia
infraestructura. Escanear sistemas de terceros sin permiso explícito puede ser ilegal en
tu jurisdicción. El autor no se hace responsable del mal uso.

Los identificadores de CVE citados en el código (`CVE-2026-123007`, `CVE-2026-123633`)
proceden de la fuente original del script y **deben verificarse** contra las bases oficiales
(NVD, MITRE, avisos del fabricante) antes de sacar conclusiones.

---

## Licencia

MIT — ver [LICENSE](LICENSE).
