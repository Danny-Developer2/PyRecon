"""Modelos de datos de PyRecon.

Todos los resultados se representan con modelos Pydantic, lo que garantiza validación,
serialización consistente hacia JSON/CSV/HTML y tipado estricto.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HostState(StrEnum):
    """Estado de un host tras el descubrimiento."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class PortState(StrEnum):
    """Estado de un puerto TCP."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class Protocol(StrEnum):
    """Protocolo escaneado."""

    TCP = "tcp"


class Severity(StrEnum):
    """Severidad de un hallazgo, según la metodología del departamento."""

    CRITICO = "critico"
    ALTO = "alto"
    MEDIO = "medio"
    BAJO = "bajo"
    INFORMATIVO = "informativo"


class ConfirmationLevel(StrEnum):
    """Nivel de confirmación de un hallazgo."""

    CONFIRMADO = "confirmado"
    PROBABLE = "probable"
    POTENCIAL = "potencial"


class Finding(BaseModel):
    """Hallazgo del análisis, con severidad y nivel de confirmación."""

    model_config = ConfigDict(frozen=True)

    message: str
    severity: Severity = Severity.INFORMATIVO
    confirmation_level: ConfirmationLevel = ConfirmationLevel.POTENCIAL
    target: str | None = Field(default=None, description="Host o dirección afectada")
    port: int | None = Field(default=None, ge=1, le=65535)
    evidence: str | None = Field(default=None, max_length=1024)


class PortResult(BaseModel):
    """Resultado del análisis de un puerto."""

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    protocol: Protocol = Protocol.TCP
    state: PortState
    service: str | None = Field(default=None, description="Servicio identificado")
    banner: str | None = Field(default=None, max_length=1024)
    response_time_ms: float | None = Field(default=None, ge=0)


class DnsRecord(BaseModel):
    """Registro DNS observado."""

    model_config = ConfigDict(frozen=True)

    name: str
    type: str
    value: str
    ttl: int | None = Field(default=None, ge=0)


class HostResult(BaseModel):
    """Resultado agregado para un host."""

    host: str = Field(description="Nombre o dirección indicada por el usuario")
    resolved_ip: str | None = Field(default=None, description="Dirección IP resuelta")
    state: HostState = HostState.UNKNOWN
    ports: list[PortResult] = Field(default_factory=list)
    dns_records: list[DnsRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        """Devuelve la lista ordenada de puertos abiertos."""
        return sorted(p.port for p in self.ports if p.state is PortState.OPEN)


class ScanResult(BaseModel):
    """Resultado completo de un análisis."""

    tool: str = "PyRecon"
    version: str = "1.1.0"
    target: str
    scope: str | None = Field(default=None, description="Nombre del alcance autorizado")
    authorized: bool = Field(default=False, description="Autorización declarada")
    started_at: datetime
    finished_at: datetime
    duration_seconds: float = Field(ge=0)
    hosts: list[HostResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    statistics: dict[str, int] = Field(default_factory=dict)

    @field_validator("finished_at")
    @classmethod
    def _check_dates(cls, value: datetime, info: Any) -> datetime:
        started = info.data.get("started_at")
        if started is not None and value < started:
            raise ValueError("finished_at no puede ser anterior a started_at")
        return value

    @property
    def hosts_up(self) -> int:
        """Número de hosts activos."""
        return sum(1 for h in self.hosts if h.state is HostState.UP)

    @property
    def total_open_ports(self) -> int:
        """Número total de puertos abiertos."""
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Número de hallazgos por severidad."""
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


class Scope(BaseModel):
    """Declaración de alcance autorizado."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    authorized_targets: list[str] = Field(min_length=1)
    notes: str | None = None

    @field_validator("authorized_targets")
    @classmethod
    def _validate_targets(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip() for v in values if v and v.strip()]
        if not cleaned:
            raise ValueError("authorized_targets no puede quedar vacío")
        from pyrecon.utils.network import validate_scope_target

        for entry in cleaned:
            validate_scope_target(entry)
        return cleaned
