"""Pruebas unitarias y de integración del resolutor DNS.

Se utilizan dominios reservados (``.invalid``, RFC 2606) para que las pruebas no
dependan de la red externa ni produzcan tráfico real.
"""

from __future__ import annotations

from pyrecon.core.dns_resolver import _stringify, resolve_dns, reverse_dns


async def test_resolve_dns_dominio_reservado_devuelve_vacio():
    # .invalid está reservado (RFC 2606): siempre NXDOMAIN.
    assert await resolve_dns("no-existe.invalid") == []


async def test_resolve_dns_tipo_desconocido_no_falla():
    records = await resolve_dns("no-existe.invalid", types=["SRV"])
    assert isinstance(records, list)


async def test_reverse_dns_no_lanza_excepcion():
    resultado = await reverse_dns("127.0.0.1")
    assert resultado is None or isinstance(resultado, str)


def test_stringify_entrada_vacia():
    assert _stringify("") is None


def test_stringify_nombre_con_punto_final():
    assert _stringify("ejemplo.com.") == "ejemplo.com"
