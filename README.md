# PyRecon

Herramienta profesional de **reconocimiento de infraestructura de red** desarrollada en
Python puro, destinada a auditorías de seguridad **autorizadas**.

- **Lenguaje:** Python 3.11+ (probado con 3.15)
- **Sin dependencias de binarios externos:** no requiere `nmap`, `scapy` ni herramientas de sistema.
- **No destructiva:** solo abre y cierra conexiones TCP; no ejecuta explotaciones ni ataques.

> **Aviso legal.** Esta herramienta está pensada exclusivamente para auditorías con
> autorización expresa y por escrito. El uso contra sistemas ajenos es ilegal.

---

## Características

- Descubrimiento de hosts activos mediante sondeo TCP (sin requerir privilegios de root).
- Escaneo de puertos TCP con concurrencia acotada y tiempos de espera configurables.
- Identificación de servicios por puerto y por *banner*.
- Obtención de *banners* no invasiva (lectura inicial y sondeo HTTP `HEAD` en puertos web).
- Resolución DNS directa (A, AAAA, CNAME, MX, NS, TXT) e inversa (PTR).
- Definición de **alcance autorizado** con verificación previa, incluido el caso de
  redes CIDR (el objetivo puede ser un `/24` o `/23` y el alcance puede ser más amplio).
- Soporte de redes **/24 (254 hosts)** y **/23 (510 hosts)**; otros tamaños se rechazan.
- **Hallazgos con severidad y nivel de confirmación** (crítico, alto, medio, bajo,
  informativo; confirmado, probable, potencial).
- **Inventario persistente en SQLite** con detección de cambios entre barridos
  (hosts nuevos, puertos nuevos, puertos cerrados, hosts ausentes).
- Limitación de ritmo (*rate limit*) activa por defecto (50 pps) para no saturar el objetivo.
- Interrupción segura con `Ctrl+C`.
- Registro profesional con niveles configurables y volcado a fichero.
- Exportación de resultados a **JSON**, **CSV**, **HTML** y **PDF** (informe ejecutivo
  con las 11 secciones de la metodología y anexo técnico).
- Informes con **permisos 0600** para proteger el mapa de red generado.
- Interfaz de línea de comandos con `Typer` y salida enriquecida con `Rich`.
- Tipado estricto (`mypy`), linting (`ruff`) y pruebas unitarias e integración (`pytest`).

## Arquitectura

```text
pyrecon/
├── cli.py                 # interfaz Typer + Rich
├── config.py              # ScanConfig (Pydantic)
├── models.py              # modelos de datos (Pydantic)
├── exceptions.py          # jerarquía de excepciones
├── core/
│   ├── scanner.py         # orquestador del análisis
│   ├── discovery.py       # descubrimiento de hosts
│   ├── portscan.py        # escaneo TCP (connect scan)
│   ├── services.py        # identificación de servicios y banners
│   ├── severity.py        # reglas objetivas de severidad
│   ├── inventory.py       # inventario persistente y detección de cambios
│   ├── dns_resolver.py    # resolución DNS (dnspython)
│   └── ratelimit.py       # limitador de ritmo
├── export/
│   ├── json_export.py
│   ├── csv_export.py
│   ├── html_export.py     # informe HTML autónomo (Jinja2)
│   └── pdf_export.py      # informe PDF ejecutivo (ReportLab)
└── utils/
    ├── logger.py          # logging profesional
    ├── network.py         # IP/CIDR/dominio y alcance
    └── validators.py      # validación y autorización
```

Principios: separación de responsabilidades, modelos validados con Pydantic, manejo de
errores centralizado, sin estado global mutable y cada capa de exportación independiente.

## Tecnologías

| Componente | Librería |
|---|---|
| CLI | `typer`, `rich` |
| Validación y modelos | `pydantic` |
| DNS | `dnspython` |
| Red | `socket`, `asyncio`, `ipaddress` (estándar) |
| Informes HTML | `jinja2` |
| Informes PDF | `reportlab` |
| Inventario | `sqlite3` (estándar) |
| Tests | `pytest`, `pytest-asyncio`, `pytest-cov` |
| Calidad | `ruff`, `mypy` |

## Requisitos

- Python 3.11 o superior
- `pip` y `venv`
- Conexión a la red **autorizada** para los análisis

No se requieren permisos de administrador.

## Instalación

```bash
cd 01-PyRecon
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

Sin las dependencias de desarrollo:

```bash
pip install -r requirements.txt
```

## Configuración

Toda la configuración se realiza por línea de comandos. No se necesitan credenciales ni
ficheros de entorno. Opcionalmente puede definirse el alcance autorizado en un fichero JSON:

```json
{
  "name": "Laboratorio autorizado",
  "authorized_targets": ["127.0.0.1/8", "192.168.10.0/24", "dominio-autorizado.com"],
  "notes": "Alcance aprobado por escrito el 2026-01-15"
}
```

## Uso

### Ayuda

```bash
pyrecon --help
python -m pyrecon --help
```

### Análisis de un host

```bash
pyrecon scan 192.168.1.10 --confirm-authorized
```

### Análisis de una red principal /24 con alcance autorizado

```bash
pyrecon scan 192.168.10.0/24 --scope scope.json --concurrency 50 --timeout 1.5
```

### Análisis de una red /23

```bash
pyrecon scan 192.168.10.0/23 --scope scope.json --concurrency 200 --timeout 0.8
```

### Puertos concretos y exportación

```bash
pyrecon scan 192.168.1.10 --ports "22,80,443,8080-8090" \
    --confirm-authorized --format html --output informes/analisis
```

### Informe PDF ejecutivo

```bash
pyrecon scan 192.168.10.0/24 --scope scope.json \
    --confirm-authorized --format pdf --output informes/analisis
```

### Inventario con detección de cambios

```bash
# Cada ejecución se registra y se compara con la anterior
pyrecon scan 192.168.10.0/24 --scope scope.json \
    --confirm-authorized --inventory ~/.pyrecon/inventory.db

# Histórico de ejecuciones
pyrecon inventory --db ~/.pyrecon/inventory.db

# Cambios entre la última y la anterior ejecución
pyrecon diff --db ~/.pyrecon/inventory.db
```

### Con límite de ritmo y registro detallado

```bash
pyrecon scan 192.168.1.10 --confirm-authorized \
    --rate-limit 20 --verbose --log-file logs/pyrecon.log
```

### Consulta DNS

```bash
pyrecon resolve ejemplo.com
```

## Parámetros del comando `scan`

| Parámetro | Descripción | Por defecto |
|---|---|---|
| `target` | IP, rango CIDR `/24` o `/23`, o dominio (obligatorio) | — |
| `--ports`, `-p` | Puertos o rangos, p. ej. `80,443` o `1-1024` | 30 puertos comunes |
| `--timeout`, `-t` | Tiempo de espera por puerto (0,1–30 s) | `1.0` |
| `--concurrency`, `-c` | Conexiones simultáneas (1–500) | `50` |
| `--rate-limit` | Peticiones por segundo (1–1000) | `50` |
| `--scope` | Fichero JSON con el alcance autorizado | — |
| `--confirm-authorized` | Declara autorización expresa | `False` |
| `--output`, `-o` | Ruta del informe (sin extensión) | — |
| `--format`, `-f` | `json`, `csv`, `html` o `pdf` | `json` |
| `--inventory` | Ruta de la base de datos del inventario (SQLite) | — |
| `--log-file` | Volcar el registro a fichero | — |
| `--verbose`, `-v` | Registro detallado | `False` |
| `--no-banners` | No obtener *banners* | `False` |
| `--no-dns` | No resolver DNS | `False` |

## Tamaño de red admitido

Se admiten redes **/24** (254 hosts) y **/23** (510 hosts). Cualquier otro tamaño se
rechaza con error explícito antes de sondear:

```console
$ pyrecon scan 10.0.0.0/16 --confirm-authorized
Error de validación: el rango '10.0.0.0/16' tiene prefijo /16. Solo se admiten redes
/23 (510 hosts) y /24 (254 hosts). Reduce o amplía el objetivo según corresponda.
```

El alcance autorizado puede ser más amplio que el objetivo (por ejemplo, un scope
`/16` que autoriza un barrido `/24`), pero no puede ser más pequeño que `/24`.

## Ejemplo de resultado

Ejecución real en laboratorio local (servidor HTTP de prueba en el puerto 8000):

```console
$ pyrecon scan 127.0.0.1 --ports 8000,8001 --confirm-authorized
AVISO: esta herramienta está pensada exclusivamente para auditorías autorizadas...

PyRecon — objetivo: 127.0.0.1
Inicio: 2026-01-15 10:30:00 · Duración: 0.42s
Hosts activos
┏━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Host   ┃ IP         ┃ Puertos abiertos  ┃ Servicios ┃
┡━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ 127.0.0.1 │ 127.0.0.1 │ 8000              │ http      │
└────────┴────────────┴───────────────────┴───────────┘
Resumen: 1 host(s) activo(s), 1 puerto(s) abierto(s), 2 hallazgo(s).
Informe guardado en: informes/analisis.json
```

## Ejecución de pruebas

```bash
pytest -v                 # unitarias + integración
pytest --cov=pyrecon      # con cobertura
mypy src                  # tipado estricto
ruff check src tests      # linting
```

Las pruebas de integración utilizan servidores locales (HTTP y TCP) levantados en los
*fixtures* de `tests/conftest.py` y rangos de documentación (RFC 5737), por lo que son
seguras y no requieren red externa.

## Limitaciones conocidas

- El descubrimiento se basa en sondeo TCP: un host que solo responda a ICMP y tenga todos
  los puertos de sondeo filtrados podría no detectarse.
- La identificación de servicios se basa en puertos y *banners*; no es tan exhaustiva como
  un motor de detección de versiones completo.
- La precisión del escaneo depende de los timeouts y de la concurrencia configuradas.
- Solo se admiten redes /24 y /23. Otros tamaños se rechazan con error explícito.
- La detección de cambios del inventario depende de que los barridos compartan el mismo
  conjunto de puertos: si un barrido no incluye un puerto, no puede saberse si sigue abierto.

## Consideraciones de seguridad

- **Solo uso autorizado.** La herramienta exige declarar el alcance o confirmar la autorización.
- Sin explotación, sin fuerza bruta, sin ataques de denegación de servicio y sin modificaciones
  sobre el objetivo.
- Los *banners* obtenidos se incluyen en los informes: no los comparta si contienen información sensible.
- Los informes se escriben con permisos `0600` (solo lectura y escritura para el propietario).
- El límite de ritmo está activo por defecto (50 peticiones/segundo) y la concurrencia
  por defecto es conservadora (50).
- Revise la normativa local y obtenga autorización por escrito antes de usar la herramienta.

## Licencia

[MIT](./LICENSE)

---

© Juan Daniel Luevano Ruiz
