"""Pruebas unitarias de las utilidades de red y alcance."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyrecon.exceptions import ScopeError, ValidationError
from pyrecon.models import Scope
from pyrecon.utils.network import (
    expand_target,
    is_cidr,
    is_domain,
    is_ip_address,
    is_target_in_scope,
    load_scope,
)


class TestDeteccionFormato:
    @pytest.mark.parametrize("value", ["127.0.0.1", "192.168.1.10", "::1"])
    def test_ip_valida(self, value):
        assert is_ip_address(value)

    @pytest.mark.parametrize("value", ["", "999.999.999.999", "ejemplo.com", "10.0.0"])
    def test_ip_invalida(self, value):
        assert not is_ip_address(value)

    @pytest.mark.parametrize("value", ["10.0.0.0/8", "192.168.1.0/24"])
    def test_cidr_valida(self, value):
        assert is_cidr(value)

    @pytest.mark.parametrize("value", ["10.0.0.0/33", "no-es-cidr", "ejemplo.com"])
    def test_cidr_invalida(self, value):
        assert not is_cidr(value)

    @pytest.mark.parametrize("value", ["ejemplo.com", "sub.ejemplo.com", "localhost"])
    def test_dominio_valido(self, value):
        assert is_domain(value)

    @pytest.mark.parametrize("value", ["", "a" * 300, "espacio en blanco"])
    def test_dominio_invalido(self, value):
        assert not is_domain(value)


class TestExpandTarget:
    def test_ip_simple(self):
        assert expand_target("127.0.0.1") == ["127.0.0.1"]

    def test_cidr_pequeno(self):
        assert expand_target("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]

    def test_dominio(self):
        assert expand_target("ejemplo.com") == ["ejemplo.com"]

    def test_cidr_supera_limite(self):
        with pytest.raises(ValidationError):
            expand_target("10.0.0.0/8", limit=1000)

    def test_objetivo_invalido(self):
        with pytest.raises(ValidationError):
            expand_target("no es valido!")


class TestScope:
    @pytest.fixture()
    def scope(self) -> Scope:
        return Scope(name="Lab", authorized_targets=["127.0.0.1/8", "ejemplo.com"])

    def test_ip_dentro_del_scope(self, scope):
        assert is_target_in_scope("127.0.0.1", scope)

    def test_ip_fuera_del_scope(self, scope):
        assert not is_target_in_scope("192.168.1.10", scope)

    def test_dominio_permitido(self, scope):
        assert is_target_in_scope("ejemplo.com", scope)

    def test_subdominio_permitido(self, scope):
        assert is_target_in_scope("correo.ejemplo.com", scope)

    def test_dominio_denegado(self, scope):
        assert not is_target_in_scope("otro.com", scope)

    def test_cargar_scope_valido(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text(
            json.dumps({"name": "Lab", "authorized_targets": ["10.0.0.0/8"]}),
            encoding="utf-8",
        )
        loaded = load_scope(path)
        assert loaded.name == "Lab"
        assert is_target_in_scope("10.1.2.3", loaded)

    def test_scope_inexistente(self, tmp_path: Path):
        with pytest.raises(ScopeError):
            load_scope(tmp_path / "no-existe.json")

    def test_scope_json_invalido(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text("{ no es json", encoding="utf-8")
        with pytest.raises(ScopeError):
            load_scope(path)

    def test_scope_con_campos_erroneos(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text(json.dumps({"name": "Lab"}), encoding="utf-8")
        with pytest.raises(ScopeError):
            load_scope(path)
