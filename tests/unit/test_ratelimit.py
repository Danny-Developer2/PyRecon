"""Pruebas unitarias del limitador de ritmo."""

from __future__ import annotations

import asyncio

from pyrecon.core.ratelimit import RateLimiter


async def test_sin_limite_no_espera():
    limiter = RateLimiter(None)
    await limiter.acquire()
    await limiter.acquire()


async def test_con_limite_respeta_intervalo():
    limiter = RateLimiter(50.0)  # 20 ms entre operaciones
    start = asyncio.get_running_loop().time()
    for _ in range(3):
        await limiter.acquire()
    elapsed = asyncio.get_running_loop().time() - start
    assert elapsed >= 0.03
