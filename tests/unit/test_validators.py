"""Pruebas unitarias de validadores y control de autorización."""

from __future__ import annotations

import pytest

from pyrecon.exceptions import AuthorizationError, ValidationError
from pyrecon.models import Scope
from pyrecon.utils.validators import (
    ensure_authorized,
    ensure_path_writable,
    parse_ports,
    validate_concurrency,
    validate_rate_limit,
    validate_target,
    validate_timeout,
)


class TestValidateTarget:
    @pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.0/30", "ejemplo.com"])
    def test_objetivos_validos(self, target):
        assert validate_target(target) == target

    @pytest.mark.parametrize("target", ["", "   ", "no es valido!"])
    def test_objetivos_invalidos(self, target):
        with pytest.raises(ValidationError):
            validate_target(target)


class TestValidateNumericos:
    def test_timeout_valido(self):
        assert validate_timeout(2.5) == 2.5

    @pytest.mark.parametrize("value", [0, -1, 31])
    def test_timeout_invalido(self, value):
        with pytest.raises(ValidationError):
            validate_timeout(value)

    def test_concurrencia_valida(self):
        assert validate_concurrency(50) == 50

    @pytest.mark.parametrize("value", [0, -5, 501])
    def test_concurrencia_invalida(self, value):
        with pytest.raises(ValidationError):
            validate_concurrency(value)

    def test_rate_limit_valido(self):
        assert validate_rate_limit(10.0) == 10.0
        assert validate_rate_limit(None) is None

    @pytest.mark.parametrize("value", [0, -1, 1001])
    def test_rate_limit_invalido(self, value):
        with pytest.raises(ValidationError):
            validate_rate_limit(value)


class TestParsePorts:
    def test_lista_de_enteros(self):
        assert parse_ports([80, 443, 22]) == [80, 443, 22]

    def test_cadena_separada_por_comas(self):
        assert parse_ports("80,443,8080") == [80, 443, 8080]

    def test_rango(self):
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_mixto(self):
        assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]

    def test_puerto_no_numerico(self):
        with pytest.raises(ValidationError):
            parse_ports("80,abc")

    def test_rango_invertido(self):
        with pytest.raises(ValidationError):
            parse_ports("100-1")


class TestEnsureAuthorized:
    @pytest.fixture()
    def scope(self) -> Scope:
        return Scope(name="Lab", authorized_targets=["127.0.0.1/8"])

    def test_sin_scope_ni_confirmacion(self):
        with pytest.raises(AuthorizationError):
            ensure_authorized("127.0.0.1", scope=None, confirm_authorized=False)

    def test_confirmacion_sin_scope(self):
        ensure_authorized("127.0.0.1", scope=None, confirm_authorized=True)

    def test_objetivo_dentro_del_scope(self, scope):
        ensure_authorized("127.0.0.1", scope=scope, confirm_authorized=False)

    def test_objetivo_fuera_del_scope(self, scope):
        with pytest.raises(ValidationError):
            ensure_authorized("192.168.1.10", scope=scope, confirm_authorized=True)


class TestEnsurePathWritable:
    def test_ruta_valida(self, tmp_path):
        ensure_path_writable(tmp_path / "salida.json")

    def test_carpeta_como_fichero(self, tmp_path):
        with pytest.raises(ValidationError):
            ensure_path_writable(tmp_path)
