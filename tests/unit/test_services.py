"""Pruebas unitarias de la identificación de servicios."""

from __future__ import annotations

from pyrecon.core.services import SERVICE_MAP, _sanitize, identify_service


class TestIdentifyService:
    def test_servicio_conocido_por_puerto(self):
        assert identify_service(22) == "ssh"
        assert identify_service(3306) == "mysql"
        assert identify_service(8080) == "http-proxy"

    def test_servicio_desconocido(self):
        assert identify_service(54321) is None

    def test_servicio_por_banner(self):
        assert identify_service(54321, "SSH-2.0-OpenSSH_8.9") == "ssh"
        assert identify_service(54321, "220 ProFTPD Server") == "ftp"

    def test_mapa_sin_duplicados(self):
        assert len(SERVICE_MAP) == len(set(SERVICE_MAP.values()))


class TestSanitize:
    def test_vacio(self):
        assert _sanitize(b"", 100) is None

    def test_texto_limpio(self):
        assert _sanitize(b"SSH-2.0-Lab\r\n", 100) == "SSH-2.0-Lab"

    def test_recorta_a_max_bytes(self):
        result = _sanitize(b"A" * 500, 50)
        assert result is not None
        assert len(result) <= 256

    def test_elimina_caracteres_no_imprimibles(self):
        assert _sanitize(b"ABC\x00\x01\x02DEF", 100) == "ABCDEF"

    def test_utf8_con_errores(self):
        result = _sanitize(b"caf\xe9 servicios", 100)
        assert result is not None
        assert "caf" in result
