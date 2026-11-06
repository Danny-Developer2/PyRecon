"""Punto de entrada para ``python -m pyrecon``."""

from pyrecon.cli import app


def main() -> None:
    """Ejecuta la interfaz de línea de comandos."""
    app()


if __name__ == "__main__":
    main()
