"""Identificación de servicios y obtención de banners.

Solo se realizan sondeos no invasivos: lectura del banner inicial y, en puertos HTTP,
una petición HEAD mínima. No se envían cargas arbitrarias.
"""

from __future__ import annotations

import asyncio
import contextlib
import re

from pyrecon.utils.logger import get_logger

_logger = get_logger("core.services")

# Correlación básica de puertos habituales con servicios (sin depender de nmap).
SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Puertos que requieren TLS: no se les envía una petición HTTP en claro.
TLS_ONLY_PORTS: frozenset[int] = frozenset({443})

_PRINTABLE_RE = re.compile(r"[^\x20-\x7E\s]")


def identify_service(port: int, banner: str | None = None) -> str | None:
    """Devuelve el nombre del servicio a partir del puerto y, si hay, del banner."""
    if banner:
        lowered = banner.lower()
        for candidate in (
            "ssh",
            "ftp",
            "smtp",
            "http",
            "pop3",
            "imap",
            "mysql",
            "postgres",
            "redis",
            "mongodb",
            "telnet",
            "smtps",
        ):
            if candidate in lowered:
                return candidate
    return SERVICE_MAP.get(port)


def _sanitize(raw: bytes, max_bytes: int) -> str | None:
    """Convierte bytes en texto legible, descartando caracteres no imprimibles."""
    if not raw:
        return None
    text = raw[:max_bytes].decode("utf-8", errors="replace")
    text = _PRINTABLE_RE.sub("", text).strip()
    if not text:
        return None
    # Limita la longitud de la primera línea para no ensuciar el informe.
    first_line = text.splitlines()[0]
    return first_line[:256]


async def grab_banner(
    ip: str,
    port: int,
    timeout: float,
    max_bytes: int = 1024,
) -> str | None:
    """Intenta leer el banner de un servicio de forma no invasiva.

    Primero espera un banner enviado por el servidor (SSH, SMTP, FTP, ...). Si no
    llega nada, realiza un sondeo HTTP mínimo (excepto en puertos con TLS).

    Returns:
        El banner en texto o ``None`` si no se obtuvo.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (TimeoutError, OSError):
        return None

    try:
        data = b""
        # 1) El servidor habla primero (SSH, SMTP, FTP, POP3, IMAP...).
        try:
            data = await asyncio.wait_for(reader.read(max_bytes), timeout=min(timeout, 1.5))
        except TimeoutError:
            data = b""

        # 2) Si no hubo banner, se prueba un sondeo HTTP mínimo y no invasivo. Muchos
        #    servidores HTTP esperan a que el cliente hable y pueden estar en puertos
        #    no estándar. Se excluye 443 porque requiere TLS.
        if not data and port not in TLS_ONLY_PORTS:
            try:
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii"))
                await asyncio.wait_for(writer.drain(), timeout=timeout)
                candidate = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
            except (TimeoutError, OSError):
                candidate = b""
            if candidate[:12].upper().startswith(b"HTTP/"):
                data = candidate
    finally:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):  # pragma: no cover - defensivo
            await writer.wait_closed()

    banner = _sanitize(data, max_bytes)
    if banner:
        _logger.debug("banner en %s:%d -> %s", ip, port, banner)
    return banner
