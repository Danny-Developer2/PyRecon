"""Pruebas de integración de PyRecon contra el laboratorio local.

Todos los objetivos son 127.0.0.1 y servidores levantados en los fixtures de conftest,
por lo que las pruebas son seguras, deterministas y no tocan la red externa.
"""

from __future__ import annotations

from pyrecon.config import ScanConfig
from pyrecon.core.discovery import discover_hosts
from pyrecon.core.portscan import scan_host
from pyrecon.core.scanner import Scanner
from pyrecon.core.services import grab_banner, identify_service
from pyrecon.models import PortState


class TestDescubrimiento:
    async def test_detecta_host_local(self, http_server_port: int):
        config = ScanConfig(
            target="127.0.0.1",
            ports=[http_server_port],
            probe_ports=[http_server_port],
            confirm_authorized=True,
        )
        activos = await discover_hosts(["127.0.0.1"], config)
        assert "127.0.0.1" in activos

    async def test_no_detecta_host_inexistente(self):
        config = ScanConfig(
            target="192.0.2.1",
            ports=[80],
            probe_ports=[80],
            timeout=0.5,
            confirm_authorized=True,
        )
        # 192.0.2.0/24 es TEST-NET-1 (RFC 5737): no debe responder.
        activos = await discover_hosts(["192.0.2.1"], config)
        assert activos == []


class TestEscaneoPuertos:
    async def test_puerto_abierto(self, http_server_port: int):
        config = ScanConfig(target="127.0.0.1", ports=[http_server_port], confirm_authorized=True)
        resultados = await scan_host("127.0.0.1", [http_server_port], config)
        assert len(resultados) == 1
        assert resultados[0].state is PortState.OPEN

    async def test_puerto_cerrado(self, unused_port: int):
        config = ScanConfig(target="127.0.0.1", ports=[unused_port], confirm_authorized=True)
        resultados = await scan_host("127.0.0.1", [unused_port], config)
        assert resultados[0].state is PortState.CLOSED

    async def test_lista_vacia(self):
        config = ScanConfig(target="127.0.0.1", ports=[80], confirm_authorized=True)
        assert await scan_host("127.0.0.1", [], config) == []


class TestBanners:
    async def test_banner_ssh(self, tcp_banner_server: int):
        banner = await grab_banner("127.0.0.1", tcp_banner_server, timeout=2.0)
        assert banner is not None
        assert "SSH" in banner

    async def test_banner_http(self, http_server_port: int):
        banner = await grab_banner("127.0.0.1", http_server_port, timeout=2.0)
        assert banner is not None
        assert "HTTP" in banner

    async def test_banner_puerto_cerrado(self, unused_port: int):
        assert await grab_banner("127.0.0.1", unused_port, timeout=0.5) is None

    def test_identificar_http(self):
        assert identify_service(80, "HTTP/1.1 200 OK") == "http"


class TestScannerCompleto:
    async def test_analisis_con_puerto_abierto(self, http_server_port: int):
        config = ScanConfig(
            target="127.0.0.1",
            ports=[http_server_port, 1],
            probe_ports=[http_server_port],
            confirm_authorized=True,
        )
        resultado = await Scanner(config).run()
        assert resultado.hosts_up == 1
        assert resultado.total_open_ports == 1
        assert resultado.statistics["hosts_evaluated"] == 1
        assert any("http" in f.message for f in resultado.findings)

    async def test_analisis_sin_hosts_activos(self):
        config = ScanConfig(
            target="192.0.2.1",
            ports=[80],
            probe_ports=[80],
            timeout=0.4,
            concurrency=10,
            confirm_authorized=True,
        )
        resultado = await Scanner(config).run()
        assert resultado.hosts == []
        assert resultado.statistics["hosts_up"] == 0

    async def test_resolucion_dns_desactivada(self, http_server_port: int):
        config = ScanConfig(
            target="127.0.0.1",
            ports=[http_server_port],
            probe_ports=[http_server_port],
            resolve_dns=False,
            confirm_authorized=True,
        )
        resultado = await Scanner(config).run()
        assert resultado.hosts[0].dns_records == []
