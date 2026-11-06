"""Control de ritmo (rate limiting) para no saturar el objetivo."""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Limita el número de operaciones por segundo.

    Implementación sencilla basada en intervalo mínimo entre operaciones. Si no se
    indica ritmo, las operaciones se ejecutan sin restricción.
    """

    def __init__(self, rate_per_second: float | None) -> None:
        self._interval = (1.0 / rate_per_second) if rate_per_second else 0.0
        self._lock = asyncio.Lock()
        self._last: float | None = None

    async def acquire(self) -> None:
        """Espera el tiempo necesario para respetar el ritmo configurado."""
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.perf_counter()
            if self._last is not None:
                wait = self._interval - (now - self._last)
                if wait > 0:
                    await asyncio.sleep(wait)
                    now = time.perf_counter()
            self._last = now
