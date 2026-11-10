"""Jerarquía de excepciones centralizada de PyRecon.

Todas las errores de la herramienta derivan de :class:`PyReconError`, lo que permite
capturarlos de forma uniforme en la CLI y en los exportadores.
"""

from __future__ import annotations


class PyReconError(Exception):
    """Excepción base de PyRecon."""


class ValidationError(PyReconError):
    """Entrada de usuario no válida (puertos, objetivo, tiempo de espera...)."""


class ScopeError(PyReconError):
    """El objetivo está fuera del alcance autorizado."""


class AuthorizationError(PyReconError):
    """No se ha declarado la autorización correspondiente."""


class NetworkError(PyReconError):
    """Error de red no recuperable (resolución, conexión, tiempo de espera agotado)."""


class ExportError(PyReconError):
    """Error al escribir un informe (JSON, CSV, HTML o PDF)."""


class InventoryError(PyReconError):
    """Error al abrir, leer o escribir el inventario de activos."""


__all__ = [
    "PyReconError",
    "ValidationError",
    "ScopeError",
    "AuthorizationError",
    "NetworkError",
    "ExportError",
    "InventoryError",
]
