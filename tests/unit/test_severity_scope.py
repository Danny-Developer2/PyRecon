"""Pruebas unitarias de las reglas de severidad y del alcance con CIDR."""

from __future__ import annotations

import pytest

from pyrecon.core.severity import classify_port_severity
from pyrecon.exceptions import ValidationError
from pyrecon.models import Scope, Severity
from pyrecon.utils.network import is_target_in_scope, validate_network_prefix
from pyrecon.utils.validators import ensure_authorized, validate_target


class TestSeveridad:
    @pytest.mark.parametrize("puerto", [22, 3389, 3306, 445, 5900, 27017])
    def test_servicios_sensibles_severidad_alta(self, puerto: int):
        assert classify_port_severity(puerto, "ssh") is Severity.ALTO

    @pytest.mark.parametrize("puerto", [80, 443, 8080, 8443])
    def test_servicios_web_severidad_media(self, puerto: int):
        assert classify_port_severity(puerto, "http") is Severity.MEDIO

    @pytest.mark.parametrize("puerto", [25, 110, 143, 587])
    def test_servicios_de_correo_severidad_media(self, puerto: int):
        assert classify_port_severity(puerto, "smtp") is Severity.MEDIO

    def test_puerto_con_servicio_desconocido_severidad_baja(self):
        assert classify_port_severity(59999 % 65535 + 1, "custom") is Severity.BAJO

    def test_puerto_sin_servicio_severidad_informativa(self):
        assert classify_port_severity(49999, None) is Severity.INFORMATIVO


class TestPrefijosDeRed:
    @pytest.mark.parametrize("target", ["192.168.1.0/24", "192.168.0.0/23"])
    def test_prefijos_permitidos(self, target: str):
        assert validate_network_prefix(target) is not None

    @pytest.mark.parametrize("target", ["10.0.0.0/16", "10.0.0.0/22", "10.0.0.0/30", "10.0.0.0/8"])
    def test_prefijos_rechazados(self, target: str):
        with pytest.raises(ValidationError):
            validate_network_prefix(target)

    def test_ip_suelta_no_es_cidr(self):
        assert validate_network_prefix("127.0.0.1") is None

    def test_ipv6_rechazado(self):
        with pytest.raises(ValidationError):
            validate_network_prefix("2001:db8::/32")


class TestAlcanceConCIDR:
    @pytest.fixture()
    def scope_24(self) -> Scope:
        return Scope(name="empresa", authorized_targets=["192.168.1.0/24"])

    @pytest.fixture()
    def scope_23(self) -> Scope:
        return Scope(name="corp", authorized_targets=["192.168.0.0/23"])

    def test_cidr_identico_al_scope(self, scope_24: Scope):
        assert is_target_in_scope("192.168.1.0/24", scope_24)

    def test_subred_contenida_en_el_scope(self, scope_23: Scope):
        assert is_target_in_scope("192.168.1.0/24", scope_23)

    def test_cidr_fuera_del_scope(self, scope_24: Scope):
        assert not is_target_in_scope("10.0.0.0/24", scope_24)

    def test_superred_no_contenida(self, scope_24: Scope):
        assert not is_target_in_scope("192.168.0.0/23", scope_24)

    def test_scope_amplio_con_objetivo_24(self):
        scope = Scope(name="corp", authorized_targets=["192.168.0.0/16"])
        assert is_target_in_scope("192.168.1.0/24", scope)

    def test_ensure_authorized_con_cidr(self, scope_24: Scope):
        ensure_authorized("192.168.1.0/24", scope=scope_24, confirm_authorized=False)

    def test_ensure_authorized_cidr_fuera(self, scope_24: Scope):
        with pytest.raises(ValidationError):
            ensure_authorized("10.0.0.0/24", scope=scope_24, confirm_authorized=False)

    def test_scope_mas_pequeno_que_24_rechazado(self):
        with pytest.raises(ValidationError):
            Scope(name="malo", authorized_targets=["192.168.1.0/25"])

    def test_validate_target_accept_cidr(self):
        assert validate_target("192.168.1.0/24") == "192.168.1.0/24"

    def test_validate_target_rechaza_cidr_grande(self):
        with pytest.raises(ValidationError):
            validate_target("10.0.0.0/16")
