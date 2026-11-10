# Changelog

Todos los cambios notables de PyRecon se documentan en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y este proyecto se adhiere al [Versionado Semántico](https://semver.org/lang/es/).

## [1.1.0] — 2026-11-09

### Añadido

- Soporte de redes **/24** (254 hosts) y **/23** (510 hosts). Otros tamaños se rechazan
  con error explícito antes de sondear.
- Corrección del alcance con CIDR: un objetivo `/24` o `/23` ahora se puede comparar
  contra el alcance autorizado (red idéntica, subred contenida o superred que la contiene).
- Hallazgos con **severidad** (crítico, alto, medio, bajo, informativo) y **nivel de
  confirmación** (confirmado, probable, potencial).
- Exportador **PDF** con ReportLab: informe ejecutivo con las 11 secciones de la
  metodología y anexo técnico de detalle por host.
- **Inventario persistente en SQLite** (`--inventory`) con detección de cambios entre
  barridos: hosts nuevos, puertos nuevos, puertos cerrados y hosts ausentes.
- Comandos `inventory` (histórico de ejecuciones) y `diff` (cambios entre las dos
  últimas ejecuciones).
- Informe HTML ampliado a las 11 secciones de la metodología.
- Permisos `0600` en todos los informes generados (JSON, CSV, HTML y PDF).
- Constantes `MIN_NETWORK_PREFIX`, `MAX_NETWORK_PREFIX` y `MAX_NETWORK_ADDRESSES`.

### Cambiado

- Límite de ritmo por defecto: de sin límite a **50 peticiones/segundo**.
- Concurrencia por defecto: de 100 a **50**.
- `findings` pasa de `list[str]` a `list[Finding]`; el JSON usa `schema_version: 2`.
- `is_cidr` ahora exige prefijo explícito, de modo que una IP suelta no se confunde
  con un CIDR `/32`.
- El descubrimiento deja de truncar silenciosamente los hosts: si se supera
  `max_hosts`, se rechaza con error.

### Arreglado

- `is_target_in_scope` no aceptaba un CIDR como objetivo, lo que impedía escanear una
  red principal con `--scope`. Corregido.
- Las entradas del alcance se validan ahora al construir el modelo `Scope`.

### Seguridad

- Los *banners* dejan de registrarse en el log en nivel INFO.
- Los informes se escriben con permisos restrictivos para no exponer el mapa de red.

[1.1.0]: https://github.com/Danny-Developer2/PyRecon/compare/v1.0.0...v1.1.0
