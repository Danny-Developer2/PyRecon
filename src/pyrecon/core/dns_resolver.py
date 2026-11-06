"""Resolución DNS asíncrona usando dnspython.

Solo realiza consultas estándar (A, AAAA, CNAME, MX, NS, TXT) y resolución inversa.
No se realizan transferencias de zona ni técnicas invasivas.
"""

from __future__ import annotations

from collections.abc import Iterable

import dns.asyncresolver
import dns.reversename
from dns.exception import DNSException
from dns.rdtypes.ANY.MX import MX

from pyrecon.models import DnsRecord
from pyrecon.utils.logger import get_logger

_logger = get_logger("core.dns")

RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


async def resolve_dns(
    host: str,
    types: Iterable[str] = RECORD_TYPES,
    lifetime: float = 5.0,
) -> list[DnsRecord]:
    """Resuelve los tipos de registro indicados para un nombre de host."""
    records: list[DnsRecord] = []
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = lifetime
    resolver.timeout = min(lifetime, 2.0)

    for record_type in types:
        try:
            answer = await resolver.resolve(host, record_type)
        except dns.resolver.NXDOMAIN:
            _logger.debug("%s no existe (NXDOMAIN)", host)
            break
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.NoNameservers, DNSException, OSError):
            _logger.warning("no se pudo resolver %s %s", record_type, host)
            continue

        for item in answer:
            try:
                value = _stringify(item)
            except Exception:  # defensivo: un registro mal formado no detiene la resolución
                _logger.debug("registro DNS no procesable: %r", item)
                continue
            if value:
                records.append(
                    DnsRecord(
                        name=str(answer.qname).rstrip("."),
                        type=record_type,
                        value=value,
                        ttl=int(answer.ttl) if answer.ttl is not None else None,
                    )
                )
    return records


def _stringify(item: object) -> str | None:
    """Convierte un registro DNS a texto legible."""
    if isinstance(item, MX):
        return f"{item.preference} {str(item.exchange).rstrip('.')}"
    text = str(item).strip()
    if text.endswith("."):
        text = text[:-1]
    return text or None


async def reverse_dns(ip: str, lifetime: float = 5.0) -> str | None:
    """Realiza una resolución inversa (PTR)."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = lifetime
    resolver.timeout = min(lifetime, 2.0)
    try:
        reversed_name = dns.reversename.from_address(ip)
        answer = await resolver.resolve(reversed_name, "PTR")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, DNSException, OSError):
        return None
    if not answer:
        return None
    return str(answer[0]).rstrip(".")
