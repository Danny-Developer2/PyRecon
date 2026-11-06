"""Escaneo de puertos TCP mediante conexión completa (connect scan).

No requiere privilegios de root y es seguro: solo abre y cierra conexiones TCP.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import time

from pyrecon.config import ScanConfig
from pyrecon.core.ratelimit import RateLimiter
from pyrecon.models import PortResult, PortState
from pyrecon.utils.logger import get_logger

_logger = get_logger("core.portscan")


def _classify_error(exc: BaseException) -> PortState:
    """Clasifica un error de conexión como closed o filtered."""
    if isinstance(exc, asyncio.TimeoutError):
        return PortState.FILTERED
    if isinstance(exc, ConnectionRefusedError):
        return PortState.CLOSED
    if isinstance(exc, OSError):
        code = exc.errno
        if code in {
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
            errno.ENETDOWN,
            errno.EHOSTDOWN,
            errno.ETIMEDOUT,
            errno.EAGAIN,
            errno.EPIPE,
            errno.ECONNRESET,
        }:
            return PortState.FILTERED
        return PortState.CLOSED
    return PortState.FILTERED


async def scan_port(
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
    rate_limiter: RateLimiter | None = None,
) -> PortResult:
    """Comprueba el estado de un único puerto TCP.

    Args:
        ip: Dirección IP de destino.
        port: Puerto a comprobar.
        timeout: Tiempo máximo de espera en segundos.
        semaphore: Semáforo que limita la concurrencia.
        rate_limiter: Limitador de ritmo opcional.

    Returns:
        El resultado del puerto.
    """
    async with semaphore:
        if rate_limiter is not None:
            await rate_limiter.acquire()

        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (TimeoutError, OSError) as exc:
            state = _classify_error(exc)
            return PortResult(
                port=port,
                state=state,
                response_time_ms=round((time.perf_counter() - started) * 1000, 2),
            )

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):  # pragma: no cover - defensivo
            await writer.wait_closed()
        _logger.debug("puerto %s:%d abierto (%.2f ms)", ip, port, elapsed_ms)
        return PortResult(port=port, state=PortState.OPEN, response_time_ms=elapsed_ms)


async def scan_host(
    ip: str,
    ports: list[int],
    config: ScanConfig,
    rate_limiter: RateLimiter | None = None,
) -> list[PortResult]:
    """Escanea una lista de puertos sobre un host con concurrencia acotada."""
    if not ports:
        return []

    semaphore = asyncio.Semaphore(config.concurrency)
    tasks = [scan_port(ip, port, config.timeout, semaphore, rate_limiter) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return list(results)
