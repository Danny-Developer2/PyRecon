"""Descubrimiento de hosts activos.

Se utiliza sondeo TCP (connect) sobre puertos habituales. No se emplea ICMP para no
requerir privilegios de root ni generar tráfico considerado intrusivo.
"""

from __future__ import annotations

import asyncio

from pyrecon.config import ScanConfig
from pyrecon.core.portscan import scan_port
from pyrecon.core.ratelimit import RateLimiter
from pyrecon.utils.logger import get_logger

_logger = get_logger("core.discovery")


async def is_host_up(
    ip: str,
    config: ScanConfig,
    rate_limiter: RateLimiter | None = None,
    probe_ports: list[int] | None = None,
) -> bool:
    """Determina si un host está activo comprobando los puertos de sondeo."""
    ports = probe_ports if probe_ports is not None else config.probe_ports
    semaphore = asyncio.Semaphore(config.concurrency)
    tasks = [scan_port(ip, port, config.timeout, semaphore, rate_limiter) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return any(result.state.value == "open" for result in results)


async def discover_hosts(
    targets: list[str],
    config: ScanConfig,
    rate_limiter: RateLimiter | None = None,
    probe_ports: list[int] | None = None,
) -> list[str]:
    """Descubre qué direcciones de la lista están activas.

    El número de direcciones se limita con ``config.max_hosts`` para evitar
    escaneos masivos accidentales.
    """
    if len(targets) > config.max_hosts:
        _logger.warning(
            "el objetivo se expande a %d direcciones; se limita a %d",
            len(targets),
            config.max_hosts,
        )
        targets = targets[: config.max_hosts]

    ports = probe_ports if probe_ports is not None else config.probe_ports
    semaphore = asyncio.Semaphore(config.concurrency)

    async def _probe(ip: str) -> str | None:
        async with semaphore:
            if rate_limiter is not None:
                await rate_limiter.acquire()
            up = await is_host_up(ip, config, rate_limiter=None, probe_ports=ports)
        return ip if up else None

    results = await asyncio.gather(*(_probe(ip) for ip in targets))
    active = [ip for ip in results if ip is not None]
    _logger.info("hosts activos detectados: %d de %d", len(active), len(targets))
    return active
