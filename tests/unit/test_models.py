"""Pruebas unitarias de los modelos de PyRecon."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pyrecon.models import (
    DnsRecord,
    HostResult,
    HostState,
    PortResult,
    PortState,
    ScanResult,
    Scope,
)


def _port(port: int, state: PortState = PortState.OPEN, service: str | None = "http") -> PortResult:
    return PortResult(port=port, state=state, service=service)


class TestPortResult:
    def test_puerto_valido(self):
        result = _port(8080)
        assert result.port == 8080
        assert result.state is PortState.OPEN

    @pytest.mark.parametrize("port", [0, -1, 65536, 100000])
    def test_puerto_fuera_de_rango(self, port):
        with pytest.raises(ValidationError):
            PortResult(port=port, state=PortState.OPEN)

    def test_banner_largo_es_recortado(self):
        with pytest.raises(ValidationError):
            PortResult(port=80, state=PortState.OPEN, banner="x" * 2000)


class TestHostResult:
    def test_open_ports_ordenados(self):
        host = HostResult(
            host="127.0.0.1",
            state=HostState.UP,
            ports=[_port(443), _port(22), _port(80, PortState.CLOSED), _port(8080)],
        )
        assert host.open_ports == [22, 443, 8080]

    def test_sin_puertos(self):
        host = HostResult(host="127.0.0.1", state=HostState.DOWN)
        assert host.open_ports == []


class TestScanResult:
    def test_propiedades_agregadas(self):
        now = datetime.now(UTC)
        result = ScanResult(
            target="127.0.0.1",
            started_at=now,
            finished_at=now + timedelta(seconds=1),
            duration_seconds=1.0,
            hosts=[
                HostResult(host="127.0.0.1", state=HostState.UP, ports=[_port(80), _port(443)]),
                HostResult(host="127.0.0.2", state=HostState.UP, ports=[_port(22)]),
            ],
        )
        assert result.hosts_up == 2
        assert result.total_open_ports == 3

    def test_fecha_final_anterior_a_la_inicial(self):
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            ScanResult(
                target="127.0.0.1",
                started_at=now,
                finished_at=now - timedelta(seconds=5),
                duration_seconds=1.0,
            )


class TestDnsRecord:
    def test_registro_basico(self):
        record = DnsRecord(name="ejemplo.com", type="A", value="1.2.3.4", ttl=300)
        assert record.type == "A"
        assert record.ttl == 300


class TestScope:
    def test_scope_valido(self):
        scope = Scope(name="Lab", authorized_targets=["127.0.0.1/8", "ejemplo.com"])
        assert scope.name == "Lab"
        assert len(scope.authorized_targets) == 2

    def test_scope_sin_objetivos(self):
        with pytest.raises(ValidationError):
            Scope(name="Lab", authorized_targets=[])

    def test_scope_con_campo_desconocido(self):
        with pytest.raises(ValidationError):
            Scope(name="Lab", authorized_targets=["127.0.0.1"], desconocido="x")

    def test_scope_limpia_espacios(self):
        scope = Scope(name="Lab", authorized_targets=["  127.0.0.1/8  ", ""])
        assert scope.authorized_targets == ["127.0.0.1/8"]
