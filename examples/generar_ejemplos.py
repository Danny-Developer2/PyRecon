"""Genera ejemplos reales de PyRecon contra el laboratorio local.

Ejecutar con el entorno virtual activo:
    .venv/bin/python examples/generar_ejemplos.py
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
RAIZ = BASE.parent


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):  # noqa: N802
        body = b"<html><body>Laboratorio PyRecon</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "LabServer/1.0")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        return


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    cli = [sys.executable, "-m", "pyrecon"]
    base = ["scan", "127.0.0.1", "--ports", str(port), "--confirm-authorized"]

    try:
        for fmt in ("json", "csv", "html"):
            destino = BASE / f"laboratorio-local.{fmt}"
            subprocess.run(
                cli + base + ["--output", str(destino), "--format", fmt],
                check=True,
                cwd=RAIZ,
            )
            print(f"generado: {destino.name}")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
