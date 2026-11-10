"""Pruebas unitarias de los exportadores de PyRecon."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pyrecon.exceptions import ExportError
from pyrecon.export import export_result
from pyrecon.export.csv_export import export_csv
from pyrecon.export.html_export import export_html
from pyrecon.export.json_export import export_json
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


def _sample_result() -> ScanResult:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    return ScanResult(
        target="127.0.0.1",
        scope="Lab",
        authorized=True,
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        duration_seconds=2.0,
        hosts=[
            HostResult(
                host="127.0.0.1",
                resolved_ip="127.0.0.1",
                state=HostState.UP,
                ports=[
                    PortResult(port=22, state=PortState.OPEN, service="ssh", response_time_ms=1.2),
                    PortResult(
                        port=80, state=PortState.OPEN, service="http", banner="HTTP/1.1 200 OK"
                    ),
                    PortResult(port=443, state=PortState.CLOSED),
                ],
                dns_records=[],
            )
        ],
        findings=[
            Finding(
                message="Host activo 127.0.0.1 con 2 puerto(s) abierto(s): 22, 80",
                severity=Severity.INFORMATIVO,
                confirmation_level=ConfirmationLevel.CONFIRMADO,
                target="127.0.0.1",
            )
        ],
        statistics={"hosts_evaluated": 1, "hosts_up": 1, "open_ports": 2},
    )


class TestJsonExport:
    def test_genera_json_valido(self, tmp_path: Path):
        path = export_json(_sample_result(), tmp_path / "resultado.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "PyRecon"
        assert data["schema"] == "pyrecon/scan-result"
        assert data["hosts"][0]["ports"][0]["port"] == 22

    def test_crea_directorios(self, tmp_path: Path):
        path = export_json(_sample_result(), tmp_path / "a" / "b" / "resultado.json")
        assert path.exists()


class TestCsvExport:
    def test_genera_una_fila_por_puerto(self, tmp_path: Path):
        path = export_csv(_sample_result(), tmp_path / "resultado.csv")
        with path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        assert len(rows) == 3
        assert rows[0]["port"] == "22"
        assert rows[0]["service"] == "ssh"
        assert rows[2]["port_state"] == "closed"

    def test_cabecera_completa(self, tmp_path: Path):
        path = export_csv(_sample_result(), tmp_path / "resultado.csv")
        with path.open(encoding="utf-8") as handle:
            header = handle.readline().strip().split(",")
        assert "host" in header
        assert "port" in header
        assert "banner" in header


class TestHtmlExport:
    def test_genera_html_con_datos(self, tmp_path: Path):
        path = export_html(_sample_result(), tmp_path / "resultado.html")
        html = path.read_text(encoding="utf-8")
        assert "Informe de reconocimiento de red" in html
        assert "127.0.0.1" in html
        assert "ssh" in html
        assert "<html" in html

    def test_escapa_contenido_malicioso(self, tmp_path: Path):
        result = _sample_result()
        # Los modelos son inmutables: se reconstruye el puerto con el banner malicioso.
        original = result.hosts[0].ports[1]
        result.hosts[0].ports[1] = PortResult(
            port=original.port,
            state=original.state,
            service=original.service,
            banner="<script>alert(1)</script>",
            response_time_ms=original.response_time_ms,
        )
        path = export_html(result, tmp_path / "resultado.html")
        html = path.read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


class TestExportResult:
    @pytest.mark.parametrize("fmt", ["json", "csv", "html", "pdf"])
    def test_formatos_soportados(self, tmp_path: Path, fmt: str):
        written = export_result(_sample_result(), tmp_path / "salida", fmt)
        assert written.exists()
        assert written.suffix == f".{fmt}"

    def test_extension_se_normaliza(self, tmp_path: Path):
        written = export_result(_sample_result(), tmp_path / "salida", ".JSON")
        assert written.suffix == ".json"

    def test_formato_no_soportado(self, tmp_path: Path):
        with pytest.raises(ExportError):
            export_result(_sample_result(), tmp_path / "salida", "docx")

    def test_informes_con_permisos_restrictivos(self, tmp_path: Path):
        for fmt in ("json", "csv", "html", "pdf"):
            written = export_result(_sample_result(), tmp_path / f"informe-{fmt}", fmt)
            assert written.stat().st_mode & 0o077 == 0, f"{fmt} no tiene permisos 0600"
