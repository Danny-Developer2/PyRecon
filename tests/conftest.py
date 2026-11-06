"""Configuración común de las pruebas de PyRecon."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class _Handler(BaseHTTPRequestHandler):
    """Handler HTTP mínimo para pruebas (cabeceras deliberadas)."""

    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - API de BaseHTTPRequestHandler
        body = b"<html><body>lab</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "LabServer/1.0")
        self.send_header("X-Powered-By", "LabTech/2.0")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Server", "LabServer/1.0")
        self.end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Allow", "GET,HEAD,OPTIONS,TRACE")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def log_message(self, *args: object) -> None:  # silencia el log del servidor
        return


@pytest.fixture(scope="session")
def http_server():
    """Servidor HTTP local en un puerto efímero."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def http_server_port(http_server) -> int:
    """Puerto del servidor HTTP local."""
    return http_server.server_address[1]


@pytest.fixture(scope="session")
def tcp_banner_server():
    """Servidor TCP que envía un banner inmediatamente (estilo SSH)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(5)

    stop = threading.Event()

    def _serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.sendall(b"SSH-2.0-LabServer_1.0\r\n")
                conn.recv(64)
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    yield listener.getsockname()[1]
    stop.set()
    listener.close()


@pytest.fixture()
def unused_port() -> int:
    """Devuelve un puerto libre (que cerramos inmediatamente)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
