"""Pruebas unitarias del sistema de registro."""

from __future__ import annotations

import logging
from pathlib import Path

from pyrecon.utils.logger import get_logger, setup_logger


def test_setup_logger_nivel_debug(tmp_path: Path):
    logger = setup_logger("DEBUG")
    assert logger.level == logging.DEBUG
    assert logger.name == "pyrecon"


def test_setup_logger_con_fichero(tmp_path: Path):
    log_path = tmp_path / "logs" / "pyrecon.log"
    logger = setup_logger("INFO", log_file=log_path)
    assert len(logger.handlers) == 2

    logger.info("mensaje de prueba")
    for handler in logger.handlers:
        handler.flush()

    assert log_path.exists()
    assert "mensaje de prueba" in log_path.read_text(encoding="utf-8")


def test_setup_logger_no_duplica_manejadores(tmp_path: Path):
    setup_logger("INFO")
    logger = setup_logger("INFO")
    assert len(logger.handlers) == 1


def test_get_logger_hijo():
    child = get_logger("core.test")
    assert child.name == "pyrecon.core.test"


def test_get_logger_raiz():
    assert get_logger().name == "pyrecon"
