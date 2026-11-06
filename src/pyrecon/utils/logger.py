"""Configuración de logging profesional de PyRecon.

Formato uniforme, nivel configurable y opción de volcar a fichero. Nunca se registran
credenciales ni datos personales.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_DEFAULT_FORMAT = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"

_LOGGER_NAME = "pyrecon"


def setup_logger(
    level: int | str = logging.INFO,
    log_file: Path | None = None,
    fmt: str = _DEFAULT_FORMAT,
    datefmt: str = _DEFAULT_DATEFMT,
) -> logging.Logger:
    """Configura y devuelve el logger principal de PyRecon.

    Args:
        level: Nivel de registro (``logging.INFO``, ``"DEBUG"``, ...).
        log_file: Ruta opcional donde volcar el registro.
        fmt: Formato de cada línea.
        datefmt: Formato de fecha.

    Returns:
        El logger configurado.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    # Evitar manejadores duplicados si se llama varias veces.
    logger.handlers.clear()

    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Devuelve un sublogger de ``pyrecon``."""
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)
