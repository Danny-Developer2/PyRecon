"""Reglas objetivas de severidad para los hallazgos.

Las reglas se basan únicamente en el puerto y el servicio identificado. No se
infiere vulnerabilidad sin evidencia: un puerto abierto es una exposición
potencial, no una vulnerabilidad confirmada.
"""

from __future__ import annotations

from pyrecon.models import Severity

# Puertos que exponen servicios sensibles: administración remota, bases de datos
# o compartición de archivos. Su exposición justifica una severidad alta.
SENSITIVE_PORTS: frozenset[int] = frozenset(
    {
        21,  # ftp
        22,  # ssh
        23,  # telnet
        135,  # msrpc
        139,  # netbios-ssn
        445,  # microsoft-ds
        1433,  # ms-sql-s
        1521,  # oracle
        3306,  # mysql
        3389,  # ms-wbt-server (RDP)
        5432,  # postgresql
        5900,  # vnc
        5984,  # couchdb
        6379,  # redis
        9200,  # elasticsearch
        27017,  # mongodb
    }
)

# Puertos de servicios web.
WEB_PORTS: frozenset[int] = frozenset({80, 443, 8000, 8080, 8443})

# Puertos de correo.
MAIL_PORTS: frozenset[int] = frozenset({25, 110, 143, 465, 587, 993, 995})


def classify_port_severity(port: int, service: str | None) -> Severity:
    """Clasifica la severidad de un puerto abierto.

    Args:
        port: Número de puerto.
        service: Servicio identificado, si lo hubo.

    Returns:
        La severidad correspondiente según las reglas objetivas.
    """
    if port in SENSITIVE_PORTS:
        return Severity.ALTO
    if port in WEB_PORTS:
        return Severity.MEDIO
    if port in MAIL_PORTS:
        return Severity.MEDIO
    if service:
        return Severity.BAJO
    return Severity.INFORMATIVO
