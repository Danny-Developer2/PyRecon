"""Utilidades de red y de gestión del alcance autorizado."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from pathlib import Path
from typing import Any

from pyrecon.exceptions import ScopeError, ValidationError
from pyrecon.models import Scope

_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

MAX_EXPANDED_HOSTS = 4096


def is_ip_address(value: str) -> bool:
    """Indica si ``value`` es una dirección IPv4 o IPv6 válida."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_cidr(value: str) -> bool:
    """Indica si ``value`` es un rango CIDR válido."""
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def is_domain(value: str) -> bool:
    """Indica si ``value`` tiene forma de nombre de dominio."""
    candidate = value.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        return False
    if any(ch.isspace() for ch in candidate):
        return False
    return bool(_DOMAIN_RE.match(candidate))


def expand_target(target: str, limit: int = MAX_EXPANDED_HOSTS) -> list[str]:
    """Expande un objetivo a una lista de direcciones IP o nombres de host.

    Acepta una IP, un rango CIDR o un dominio. En el caso de CIDR se limita el número
    de direcciones para evitar escaneos masivos accidentales.

    Raises:
        ValidationError: Si el objetivo no es válido o supera el límite de hosts.
    """
    candidate = target.strip()
    if not candidate:
        raise ValidationError("el objetivo no puede estar vacío")

    if is_ip_address(candidate):
        return [candidate]

    if is_cidr(candidate):
        network = ipaddress.ip_network(candidate, strict=False)
        if network.num_addresses > limit:
            raise ValidationError(
                f"el rango {candidate} contiene {network.num_addresses} direcciones y "
                f"supera el límite de {limit}. Reduce el ámbito o usa un rango menor."
            )
        return (
            [str(ip) for ip in network.hosts()]
            if network.num_addresses > 1
            else [str(network.network_address)]
        )

    if is_domain(candidate):
        return [candidate.rstrip(".")]

    raise ValidationError(
        f"objetivo no reconocido: {candidate!r}. Debe ser una IP, un rango CIDR o un dominio."
    )


def load_scope(path: Path) -> Scope:
    """Carga un alcance autorizado desde un fichero JSON.

    El formato esperado es::

        {
          "name": "Laboratorio",
          "authorized_targets": ["127.0.0.1/8", "example.com"],
          "notes": "Opcional"
        }
    """
    try:
        raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScopeError(f"no existe el fichero de alcance: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ScopeError(f"el fichero de alcance no es JSON válido: {path}") from exc

    try:
        return Scope.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError
        raise ScopeError(f"el fichero de alcance no es válido: {exc}") from exc


def _domain_matches(target: str, authorized: str) -> bool:
    target = target.lower().rstrip(".")
    authorized = authorized.lower().rstrip(".")
    return target == authorized or target.endswith("." + authorized)


def is_target_in_scope(target: str, scope: Scope) -> bool:
    """Comprueba si un objetivo está dentro del alcance autorizado."""
    candidate = target.strip()

    if is_ip_address(candidate):
        address = ipaddress.ip_address(candidate)
        for authorized in scope.authorized_targets:
            if is_cidr(authorized):
                network = ipaddress.ip_network(authorized, strict=False)
                if address in network:
                    return True
            elif is_ip_address(authorized) and authorized == candidate:
                return True
        return False

    if is_domain(candidate):
        return any(_domain_matches(candidate, a) for a in scope.authorized_targets)

    return False


def resolve_host(host: str, timeout: float = 2.0) -> str | None:
    """Resuelve un nombre de host a su primera dirección IPv4.

    Returns:
        La dirección IP o ``None`` si no se pudo resolver.
    """
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
    except (TimeoutError, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous)
    if not infos:
        return None
    return str(infos[0][4][0])


def reverse_lookup(ip: str, timeout: float = 2.0) -> str | None:
    """Realiza una resolución inversa (PTR) de una dirección IP."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (TimeoutError, socket.herror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous)
