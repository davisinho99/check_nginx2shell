# check_nginx2shell

**`alpn_check.py`** — Comprobador masivo de **HTTP/2 vía ALPN (`h2`)** sobre TLS y
**detección de la versión de NGINX** a partir del header `Server:`.

La herramienta se conecta a cada host de una lista, negocia TLS con `openssl s_client`
solicitando el protocolo ALPN `h2` y clasifica el resultado. Después hace una petición
HTTP (`HEAD`, con fallback a `GET`) para leer el header `Server:` y comparar la versión
de NGINX con los rangos afectados por **CVE-2026-123007** y **CVE-2026-123633**
(`nginx2shell` / `nginx2root`).

> ⚠️ **Aviso:** esta herramienta **no explota** nada. Solo verifica si el host negocia
> ALPN `h2` y qué versión de NGINX anuncia. Que un host tenga HTTP/2 activo **no**
> implica que sea vulnerable, y que la versión anunciada sea vulnerable **tampoco**
> confirma explotabilidad: hay que validar configuración (HTTP/2 activo, `proxy_pass`
> para CVE-2026-123633) y la CVE concreta.

---

## Tabla de contenidos

- [Cómo funciona](#cómo-funciona)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Uso](#uso)
- [Formato de entrada](#formato-de-entrada)
- [Rangos afectados](#rangos-afectados)
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

Después del chequeo ALPN (salvo que el host esté `FAILED` o se use `--no-version`), se
abre una segunda conexión TLS y se envía:

```http
HEAD / HTTP/1.1
Host: HOST
User-Agent: Mozilla/5.0 (compatible; alpn_check)
Accept: */*
Connection: close
```

Se lee únicamente la cabecera de la respuesta y se extrae el header `Server:`. Si `HEAD`
no devuelve `Server`, se reintenta una vez con `GET`. La versión se parsea con:

| Header `Server:` observado        | `nginx_version` |
| --------------------------------- | --------------- |
| `nginx/1.31.8`                    | `1.31.8`        |
| `nginx/1.30.6 (Ubuntu)`           | `1.30.6`        |
| `openresty/1.25.3.1`              | `1.25.3` (base NGINX) |
| `nginx` (sin versión, `server_tokens off`) | `-` (UNKNOWN) |
| `cloudflare`, `Apache/...`, etc.  | `-` (UNKNOWN)   |

La familia del servidor (`nginx` / `non-nginx` / `unknown`) se deduce del mismo header y
se guarda en la columna `server_family`.

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
| `--no-version` | No pedir el header `Server` (solo chequeo ALPN) | desactivado |
| `--no-color` | Desactivar colores ANSI | auto |
| `--color` | Forzar colores aunque no sea TTY | auto |

Los colores se activan automáticamente solo si la salida es una terminal y no está
definida la variable `NO_COLOR`. La salida por host y el resumen usan el mismo código
de color por veredicto: **rojo** = afectado, **naranja** = error/no verificable,
**amarillo** = a revisar, **verde** = sin exposición a estas CVE
(ver [¿Por qué sale en verde?](#por-qué-sale-en-verde)).

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

## Rangos afectados

Según los avisos de NGINX del **18 de noviembre de 2026** (corregido en **1.30.7** stable
y **1.31.9** mainline):

| CVE | Rango vulnerable | Corregido en |
| --- | ---------------- | ------------ |
| `CVE-2026-123007` (HTTP/2 flow control, integer underflow) | `1.9.5` – `1.31.8` | `1.30.7` / `1.31.9` |
| `CVE-2026-123633` (HTTP/2 use-after-free) | `1.19.7` – `1.31.8` | `1.30.7` / `1.31.9` |

El script compara la versión anunciada con esos rangos, teniendo en cuenta que las
ramas stable (`>= 1.30.7` y `< 1.31.0`) y mainline (`>= 1.31.9`) ya están corregidas.

> **Limitaciones:** el header `Server:` puede estar oculto (`server_tokens off` deja solo
> `nginx`), puede haber un CDN/proxy delante (`cloudflare`, `volt-adc`, etc.), o puede
> tratarse de **NGINX Plus** (no anuncia la versión de Plus en `Server:`). En esos casos
> la columna `version_vulnerable` será `UNKNOWN` y habrá que verificar la versión a mano.

---

## Estados y clasificación

Cada resultado incluye dos clasificaciones:

**ALPN (`status`):**

| `status`   | Significado |
| ---------- | ----------- |
| `H2`       | HTTP/2 negociado |
| `NO_ALPN`  | No negocia `h2` |
| `FAILED`   | No se pudo completar la conexión TLS |
| `UNKNOWN`  | Salida no reconocida |

**Versión (`version_vulnerable`):**

| Valor     | Motivo |
| --------- | ------ |
| `YES`     | Versión dentro de un rango afectado (las CVE se listan en la columna `cves`) |
| `NO`      | Versión corregida (`>= 1.30.7` stable o `>= 1.31.9` mainline) |
| `UNKNOWN` | Sin header `Server`, versión oculta o servidor no-NGINX |

**Exposición combinada (`potentially_vulnerable`):**

| Condición | `potentially_vulnerable` |
| --------- | ------------------------ |
| `H2` + versión `YES` o `UNKNOWN` + servidor nginx o desconocido | `YES` |
| `H2` + servidor claramente **no-NGINX** (Apache, IIS, CDN...) | `NO` |
| `H2` + versión `NO` (corregida) | `NO` |
| `NO_ALPN` / `FAILED` / `UNKNOWN` | `NO` |

`YES` significa **"hay que mirar más"**, no "vulnerable confirmado". Un `Server:` de
Apache/cloudflare/etc. descarta las CVE de nginx aunque haya HTTP/2 activo.

---

## Veredicto por host

Cada línea de salida empieza por un veredicto, y el resumen agrupa los hosts por ese
mismo veredicto. Es la respuesta rápida a "¿este host está afectado?":

| Veredicto     | Cuándo | Significado |
| ------------- | ------ | ----------- |
| `AFECTADO`    | `H2` + nginx afectado o versión desconocida | Candidato real: hay que verificar |
| `REVISAR`     | `H2` sin versión, o ALPN indeterminado | Falta información: comprobar a mano |
| `ERROR`       | `FAILED` | No verificable (DNS, timeout, firewall): re-escanear |
| `NO AFECTADO` | nginx con versión ya corregida | Fuera de rango |
| `NO EXPUESTO` | no negocia `h2` | Sin exposición a estas CVE |
| `NO APLICA`   | servidor no-NGINX | Las CVE de nginx no le afectan |

Ejemplo de línea por host:

```text
[ 7/42] AFECTADO    ejemplo.com:443      nginx/1.31.8          CVE-2026-123007,CVE-2026-123633
[ 8/42] REVISAR     oculto.com:443       nginx                Server sin version de NGINX: nginx
[ 9/42] NO AFECTADO fijo.com:443         nginx/1.31.9          -
[10/42] NO APLICA   apache.com:443       Apache                CVEs de nginx no aplican
[11/42] NO EXPUESTO viejo.com:443        nginx/1.30.6          version afectada, pero no negocia h2
[12/42] ERROR       caido.com:443        -                     DNS no resuelve
```

### ¿Por qué sale en verde?

Verde significa **"sin exposición a estas dos CVE según lo que se ha podido observar"**,
no "host seguro". Se pinta en verde cualquiera de los tres veredictos que no requieren
acción, y cada uno llega ahí por un motivo distinto:

- **`NO APLICA`** — el header `Server:` anuncia un producto que no es NGINX (Apache,
  IIS, cloudflare, LiteSpeed, Caddy, envoy, nginx-unit...). Las CVE viven en el parser
  HTTP/2 de nginx, así que otro servidor no las hereda aunque negocie `h2`.
- **`NO EXPUESTO`** — es nginx y la versión puede estar incluso en rango afectado, pero
  el servidor **no negocia `h2`** por ALPN. La explotación va por el framing HTTP/2:
  sin `h2` no hay superficie. Es el caso de `viejo.com:443` en el ejemplo.
- **`NO AFECTADO`** — es nginx, negocia `h2`, y la versión ya está corregida
  (≥ 1.31.9 en mainline o ≥ 1.30.7 en stable; el rango vulnerable llega hasta 1.31.8,
  y las CVE entran desde 1.9.5 y 1.19.7 respectivamente).

Dos matices importantes:

- `ERROR` se pinta en **naranja** a propósito: un host que no resuelve o no conecta
  **no está verificado**, y darlo por bueno sería un falso negativo. Verde es "hemos
  mirado y no aplica"; naranja en `ERROR` es "no hemos podido mirar". Rojo queda
  reservado a `AFECTADO` para que no se confundan a simple vista.
- El color es solo la pista rápida. La línea por host y el CSV te dicen **cuál** de los
  tres verdes es: un `NO EXPUESTO` con versión afectada sigue siendo un host a vigilar si
  algún día habilita HTTP/2, y un `NO APLICA` no dice nada sobre otras CVE de ese producto.

---

## Familia de servidor

La columna `server_family` resume qué anuncia el header `Server:`:

| Valor       | Significado |
| ----------- | ----------- |
| `nginx`     | `nginx`, `openresty` (base NGINX) o `nginx/<versión>` |
| `non-nginx` | Otro producto conocido: `Apache`, `IIS`, `cloudflare`, `LiteSpeed`, `Caddy`, `envoy`, `nginx-unit`, etc. |
| `unknown`   | Sin header `Server`, vacío o producto no reconocido |

Con `--no-version` la familia queda siempre en `unknown`.

---

## Salida CSV

Se escribe siempre un CSV ordenado por severidad (`H2` → `NO_ALPN` → `UNKNOWN` → `FAILED`)
con las columnas:

```csv
host,port,status,alpn,tls,server,server_family,nginx_version,version_vulnerable,potentially_vulnerable,cves,detail,verdict,verdict_reason
example.com,443,H2,h2,TLSv1.3,nginx/1.31.8,nginx,1.31.8,YES,YES,"CVE-2026-123007,CVE-2026-123633",ALPN protocol: h2,AFECTADO,HTTP/2 + nginx afectado o sin version
fijo.com,443,H2,h2,TLSv1.3,nginx/1.31.9,nginx,1.31.9,NO,NO,,ALPN protocol: h2,NO AFECTADO,nginx ya corregido
otro.com,443,NO_ALPN,-,TLSv1.2,nginx/1.30.6,nginx,1.30.6,YES,NO,"CVE-2026-123007,CVE-2026-123633",No ALPN negotiated,NO EXPUESTO,no negocia ALPN h2
cdn.com,443,H2,h2,TLSv1.3,cloudflare,non-nginx,-,UNKNOWN,NO,,ALPN protocol: h2 | Servidor no-NGINX (cloudflare): CVEs de nginx no aplican,NO APLICA,servidor no-NGINX
```

`verdict` y `verdict_reason` van **al final** a propósito: las doce columnas clásicas
conservan su posición, así que los `awk`/`cut` con índices fijos que ya tuvieras siguen
funcionando. Son el mismo par que imprime la línea por host (y el que decide el color),
para que el CSV se entienda solo sin depender de la terminal: `verdict_reason` es el
motivo corto del verde (o del rojo/amarillo) de cada host.

El resumen final se imprime por `stderr` y responde de un vistazo a "¿cuántos hosts
están afectados?". Muestra una cabecera con los totales (`AFECTADOS`, `A REVISAR`,
`ERRORES`, `NO AFECTADOS`) y debajo solo las listas accionables: los afectados, los que
hay que revisar y los errores. Los no afectados se resumen por motivo (`sin HTTP/2`,
`nginx ya corregido`, `servidor no-NGINX`) para no llenar la terminal con cientos de
líneas; el detalle de cada host sigue estando en el CSV.

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

# Solo ALPN, sin pedir el header Server (una conexión por host)
./alpn_check.py dominios.txt --no-version

# Filtrar en el CSV los hosts con versión afectada (columna 9: version_vulnerable)
./alpn_check.py dominios.txt -q && awk -F, 'NR>1 && $9=="YES"' alpn_results.csv

# Solo los que no son NGINX (descartables para estas CVE; columna 7: server_family)
./alpn_check.py dominios.txt -q && awk -F, 'NR>1 && $7=="non-nginx"' alpn_results.csv

# Ver el veredicto y su motivo (columnas 13 y 14, al final del CSV)
./alpn_check.py dominios.txt -q && awk -F, 'NR>1 {print $1, $13, $14}' alpn_results.csv
```

---

## Rendimiento y límites

- **20 workers / 10 s** por defecto: buen equilibrio para listas de cientos de hosts.
- Cada host consume un proceso `openssl`; con `-w` muy alto puedes saturar CPU/FDs.
  Baja `-w` si ves `fork: Resource temporarily unavailable` o timeouts falsos.
- Hosts filtrados (sin respuesta) consumen el timeout completo. Si tu lista tiene mucho
  ruido, prueba `-t 5` y sube `-w` en consecuencia.
- Sin `--no-version` el tool hace **dos** conexiones TLS por host (ALPN + petición
  HTTP): es ruidoso en logs del servidor y puede disparar rate-limits/WAF. Úsalo con
  cabeza.

---

## Solución de problemas

| Síntoma | Causa probable | Solución |
| ------- | -------------- | -------- |
| `[!] openssl no esta instalado.` | No hay `openssl` en `PATH` | Instálalo (`apt install openssl`) |
| Muchos `FAILED` con "sin respuesta" | Firewall/egress filtrado | Prueba desde otra red; sube `-t` |
| Todo `NO_ALPN` en hosts que sí tienen HTTP/2 | Servidor requiere SNI/ALPN distinto o CDN delante | Verifica manualmente con `openssl s_client` |
| `version_vulnerable=UNKNOWN` en todos | `server_tokens off`, CDN/proxy delante o NGINX Plus | Comprueba el binario/paquete o el header completo |
| Colores raros en pipes | TTY detectado incorrectamente | Usa `--no-color` o `NO_COLOR=1` |

Depuración manual de un host concreto:

```bash
# ALPN
openssl s_client -connect example.com:443 -servername example.com -alpn h2 </dev/null 2>&1 | grep -i alpn

# Versión anunciada
curl -sSI https://example.com | grep -i '^server:'
```

---

## Descargo de responsabilidad

Esta herramienta está pensada para **auditorías autorizadas** y para verificar tu propia
infraestructura. Escanear sistemas de terceros sin permiso explícito puede ser ilegal en
tu jurisdicción. El autor no se hace responsable del mal uso.

Los rangos de versiones afectadas se han contrastado con el aviso oficial de NGINX
(<https://nginx.org/en/security_advisories.html>) y el aviso de CERT-EU (2026-022).
Aun así, verifica siempre contra NVD/MITRE y el aviso del fabricante antes de sacar
conclusiones: el header `Server:` es una pista, no una prueba.

---

## Licencia

MIT — ver [LICENSE](LICENSE).
