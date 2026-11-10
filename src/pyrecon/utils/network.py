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

# Prefijos de red permitidos para un barrido. El CO autorizó /24 y /23.
# Cualquier otro tamaño se rechaza con error explícito.
MIN_NETWORK_PREFIX = 23
MAX_NETWORK_PREFIX = 24

# Número de direcciones de red que se pueden expandir como máximo.
MAX_NETWORK_ADDRESSES = 512


def is_ip_address(value: str) -> bool:
    """Indica si ``value`` es una dirección IPv4 o IPv6 válida."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_cidr(value: str) -> bool:
    """Indica si ``value`` es un rango CIDR válido (con prefijo explícito)."""
    candidate = value.strip()
    if "/" not in candidate:
        return False
    try:
        ipaddress.ip_network(candidate, strict=False)
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


def validate_network_prefix(target: str) -> ipaddress.IPv4Network | None:
    """Valida que un CIDR de objetivo esté dentro de los prefijos permitidos.

    Args:
        target: Objetivo en formato CIDR.

    Returns:
        La red IPv4 normalizada, o ``None`` si el objetivo no es un CIDR.

    Raises:
        ValidationError: Si el prefijo no es /23 ni /24, o si la red no es IPv4.
    """
    if not is_cidr(target):
        return None
    network = ipaddress.ip_network(target, strict=False)
    if isinstance(network, ipaddress.IPv6Network):
        raise ValidationError(
            f"el objetivo {target!r} es IPv6. Solo se admiten redes IPv4 /23 o /24."
        )
    if network.prefixlen < MIN_NETWORK_PREFIX or network.prefixlen > MAX_NETWORK_PREFIX:
        raise ValidationError(
            f"el rango {target!r} tiene prefijo /{network.prefixlen}. "
            f"Solo se admiten redes /23 (510 hosts) y /24 (254 hosts). "
            "Reduce o amplía el objetivo según corresponda."
        )
    return network


def validate_scope_target(authorized: str) -> None:
    """Valida una entrada del alcance autorizado.

    El alcance puede ser más amplio que el objetivo (un scope /8 o /16 es legítimo
    porque autoriza redes /23 y /24 completas), pero no puede ser una subred más
    pequeña que /24: no tendría sentido autorizar un único host como rango.

    Raises:
        ValidationError: Si la entrada no es IP, CIDR o dominio válido.
    """
    candidate = authorized.strip()
    if not candidate:
        raise ValidationError("el alcance contiene una entrada vacía")
    if is_ip_address(candidate) or is_domain(candidate):
        return
    if is_cidr(candidate):
        network = ipaddress.ip_network(candidate, strict=False)
        if isinstance(network, ipaddress.IPv6Network):
            raise ValidationError(f"el alcance {candidate!r} es IPv6. Solo se admiten redes IPv4.")
        if network.prefixlen > MAX_NETWORK_PREFIX:
            raise ValidationError(
                f"el alcance {candidate!r} tiene prefijo /{network.prefixlen}. "
                f"El alcance no puede ser más pequeño que /{MAX_NETWORK_PREFIX}."
            )
        return
    raise ValidationError(
        f"el alcance contiene una entrada no válida: {candidate!r}. "
        "Debe ser una IP, un rango CIDR o un dominio."
    )


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


def _network_contains(authorized: ipaddress.IPv4Network, candidate: ipaddress.IPv4Network) -> bool:
    """Indica si la red autorizada cubre por completo la red candidata."""
    return candidate.subnet_of(authorized)


def is_target_in_scope(target: str, scope: Scope) -> bool:
    """Comprueba si un objetivo está dentro del alcance autorizado.

    Admite tres formas de objetivo: IP suelta, rango CIDR y dominio. Un CIDR se
    considera dentro del alcance cuando la red autorizada lo contiene por completo
    (incluido el caso de redes idénticas y el de subred contenida).
    """
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

    if is_cidr(candidate):
        candidate_network = ipaddress.ip_network(candidate, strict=False)
        if isinstance(candidate_network, ipaddress.IPv6Network):
            return False
        for authorized in scope.authorized_targets:
            if not is_cidr(authorized):
                continue
            authorized_network = ipaddress.ip_network(authorized, strict=False)
            if isinstance(authorized_network, ipaddress.IPv6Network):
                continue
            if _network_contains(authorized_network, candidate_network):
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
