"""Pruebas unitarias del inventario persistente y la detección de cambios."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pyrecon.core.inventory import Inventory
from pyrecon.exceptions import InventoryError
from pyrecon.models import (
    ConfirmationLevel,
    Finding,
    HostResult,
    HostState,
    PortResult,
    PortState,
    ScanResult,
    Severity,
)


def _result(
    target: str = "192.168.1.0/24",
    hosts: list[HostResult] | None = None,
) -> ScanResult:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    return ScanResult(
        target=target,
        scope="Lab",
        authorized=True,
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        duration_seconds=2.0,
        hosts=hosts or [],
        findings=[
            Finding(
                message="Host activo",
                severity=Severity.INFORMATIVO,
                confirmation_level=ConfirmationLevel.CONFIRMADO,
            )
        ],
        statistics={"hosts_evaluated": 254, "hosts_up": len(hosts or []), "open_ports": 0},
    )


def _host(ip: str, ports: list[int]) -> HostResult:
    return HostResult(
        host=ip,
        resolved_ip=ip,
        state=HostState.UP,
        ports=[PortResult(port=p, state=PortState.OPEN, service="http") for p in ports],
    )


class TestInventory:
    def test_crea_esquema_al_abrir(self, tmp_path: Path):
        db = tmp_path / "inv.db"
        with Inventory(db) as store:
            rows = store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        tablas = {row["name"] for row in rows}
        assert {"executions", "assets", "ports", "changes"} <= tablas

    def test_registra_ejecucion(self, tmp_path: Path):
        db = tmp_path / "inv.db"
        with Inventory(db) as store:
            execution_id = store.record(_result(hosts=[_host("192.168.1.10", [80])]))
            assert execution_id == 1
            last = store.last_execution()
            assert last is not None
            assert last["target"] == "192.168.1.0/24"
            assert last["hosts_up"] == 1

    def test_lista_execuciones_en_orden(self, tmp_path: Path):
        db = tmp_path / "inv.db"
        with Inventory(db) as store:
            store.record(_result())
            store.record(_result())
            executions = store.list_executions()
        assert [int(str(e["id"])) for e in executions] == [2, 1]

    def test_sin_ejecucion_previa_no_hay_cambios(self, tmp_path: Path):
        db = tmp_path / "inv.db"
        with Inventory(db) as store:
            assert store.diff(_result(hosts=[_host("192.168.1.10", [80])])) == []

    def test_detecta_puerto_cerrado(self, tmp_path: Path):
        db = tmp_path / "inv.db"
        with Inventory(db) as store:
            store.record(_result(hosts=[_host("192.168.1.10", [80, 443])]))
            cambios = store.diff(_result(hosts=[_host("192.168.1.10", [80])]))
        assert len(cambios) == 1
        assert cambios[0]["kind"] == "puerto_cerrado"
        assert cambios[0]["port"] == 443

    def test_detecta_puerto_nuevo(self, tmp_path: Path):
        db = tmp_path / "inv.db"
        with Inventory(db) as store:
            store.record(_result(hosts=[_host("192.168.1.10", [80])]))
            cambios = store.diff(_result(hosts=[_host("192.168.1.10", [80, 22])]))
        assert any(c["kind"] == "puerto_nuevo" and c["port"] == 22 for c in cambios)

    def test_detecta_host_nuevo_y_ausente(self, tmp_path: Path):
        db = tmp_path / "inv.db"
        with Inventory(db) as store:
            store.record(_result(hosts=[_host("192.168.1.10", [80])]))
            cambios = store.diff(
                _result(hosts=[_host("192.168.1.10", [80]), _host("192.168.1.20", [22])])
            )
        kinds = {str(c["kind"]) for c in cambios}
        assert "host_nuevo" in kinds
        assert any(c["target"] == "192.168.1.20" for c in cambios)

    def test_registra_cambios(self, tmp_path: Path):
        db = tmp_path / "inv.db"
        with Inventory(db) as store:
            store.record(_result(hosts=[_host("192.168.1.10", [80, 443])]))
            cambios = store.diff(_result(hosts=[_host("192.168.1.10", [80])]))
            execution_id = store.record(_result(hosts=[_host("192.168.1.10", [80])]))
            store.record_changes(execution_id, cambios)
            rows = store.connection.execute("SELECT * FROM changes").fetchall()
        assert len(rows) == 1
        assert rows[0]["kind"] == "puerto_cerrado"

    def test_inventario_no_abierto_da_error(self, tmp_path: Path):
        store = Inventory(tmp_path / "inv.db")
        with pytest.raises(InventoryError):
            store.last_execution()
