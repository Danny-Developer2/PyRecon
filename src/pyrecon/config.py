"""Configuración del análisis de PyRecon."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from pyrecon.models import Scope

# Puertos más habituales en auditoría de infraestructura.
DEFAULT_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    5984,
    6379,
    8000,
    8080,
    8443,
    9200,
    27017,
)

# Puertos usados para decidir si un host está activo (sondeo TCP).
DEFAULT_PROBE_PORTS: tuple[int, ...] = (80, 443, 22, 445, 8080)

MAX_PORTS_PER_SCAN = 1000


class ScanConfig(BaseModel):
    """Parámetros de un análisis de red."""

    model_config = {"validate_assignment": True}

    target: str = Field(min_length=1, max_length=255)
    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS))
    probe_ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PROBE_PORTS))
    timeout: float = Field(default=1.0, ge=0.1, le=30.0)
    concurrency: int = Field(default=100, ge=1, le=500)
    rate_limit: float | None = Field(
        default=None, ge=1, le=1000, description="Peticiones por segundo (sin límite si es None)"
    )
    max_hosts: int = Field(default=1024, ge=1, le=65536)
    resolve_dns: bool = True
    grab_banners: bool = True
    banner_max_bytes: int = Field(default=1024, ge=64, le=8192)
    scope: Scope | None = None
    scope_file: Path | None = None
    confirm_authorized: bool = False

    @field_validator("ports", "probe_ports")
    @classmethod
    def _validate_ports(cls, values: list[int]) -> list[int]:
        if not values:
            raise ValueError("la lista de puertos no puede estar vacía")
        if len(values) > MAX_PORTS_PER_SCAN:
            raise ValueError(f"como máximo se permiten {MAX_PORTS_PER_SCAN} puertos")
        cleaned = {int(v) for v in values if isinstance(v, int) or str(v).isdigit()}
        if not cleaned:
            raise ValueError("no se indicó ningún puerto válido")
        if any(not 1 <= v <= 65535 for v in cleaned):
            raise ValueError("los puertos deben estar entre 1 y 65535")
        return sorted(cleaned)
