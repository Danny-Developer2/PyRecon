"""Pruebas de integración de la interfaz de línea de comandos."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pyrecon.cli import app

runner = CliRunner()


class TestComandoVersion:
    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "PyRecon" in result.output


class TestControlAutorizacion:
    def test_sin_autorizacion_sale_con_error(self):
        result = runner.invoke(app, ["scan", "127.0.0.1"])
        assert result.exit_code == 2

    def test_objetivo_invalido(self):
        result = runner.invoke(app, ["scan", "no es valido!", "--confirm-authorized"])
        assert result.exit_code == 2


class TestComandoScan:
    def test_scan_local_json(self, http_server_port: int, tmp_path: Path):
        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "--ports",
                str(http_server_port),
                "--confirm-authorized",
                "--output",
                str(salida),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0, result.output
        generado = tmp_path / "informe.json"
        assert generado.exists()
        datos = json.loads(generado.read_text(encoding="utf-8"))
        assert datos["schema"] == "pyrecon/scan-result"
        puertos = [p["port"] for p in datos["hosts"][0]["ports"]]
        assert puertos == [http_server_port]

    def test_scan_local_html(self, http_server_port: int, tmp_path: Path):
        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "--ports",
                str(http_server_port),
                "--confirm-authorized",
                "--output",
                str(salida),
                "--format",
                "html",
            ],
        )
        assert result.exit_code == 0, result.output
        html = (tmp_path / "informe.html").read_text(encoding="utf-8")
        assert "Informe de reconocimiento de red" in html

    def test_scan_local_csv(self, http_server_port: int, tmp_path: Path):
        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "--ports",
                str(http_server_port),
                "--confirm-authorized",
                "--output",
                str(salida),
                "--format",
                "csv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "informe.csv").exists()

    def test_scan_con_scope_fuera_de_alcance(self, tmp_path: Path):
        scope = tmp_path / "scope.json"
        scope.write_text(
            json.dumps({"name": "Otro", "authorized_targets": ["10.0.0.0/8"]}),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["scan", "127.0.0.1", "--scope", str(scope)],
        )
        assert result.exit_code == 2

    def test_scan_con_scope_dentro_de_alcance(self, http_server_port: int, tmp_path: Path):
        scope = tmp_path / "scope.json"
        scope.write_text(
            json.dumps({"name": "Lab", "authorized_targets": ["127.0.0.1/8"]}),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "scan",
                "127.0.0.1",
                "--ports",
                str(http_server_port),
                "--scope",
                str(scope),
            ],
        )
        assert result.exit_code == 0, result.output


class TestComandoResolve:
    def test_resolve_localhost(self):
        result = runner.invoke(app, ["resolve", "localhost"])
        assert result.exit_code == 0

    def test_resolve_dominio_inexistente(self):
        result = runner.invoke(app, ["resolve", "no-existe.invalid"])
        assert result.exit_code == 0
