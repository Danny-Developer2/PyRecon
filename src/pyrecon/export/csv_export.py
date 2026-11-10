"""Exportación de resultados a CSV."""

from __future__ import annotations

import csv
from pathlib import Path

from pyrecon.exceptions import ExportError
from pyrecon.models import ScanResult

FIELDNAMES = [
    "host",
    "resolved_ip",
    "host_state",
    "port",
    "protocol",
    "port_state",
    "service",
    "banner",
    "response_time_ms",
    "scan_started_at",
    "scan_finished_at",
]


def export_csv(result: ScanResult, path: Path) -> Path:
    """Escribe una fila por puerto analizado.

    Raises:
        ExportError: Si no se puede escribir el fichero.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
            writer.writeheader()
            for host in result.hosts:
                if not host.ports:
                    writer.writerow(
                        {
                            "host": host.host,
                            "resolved_ip": host.resolved_ip or "",
                            "host_state": host.state.value,
                            "scan_started_at": result.started_at.isoformat(),
                            "scan_finished_at": result.finished_at.isoformat(),
                        }
                    )
                    continue
                for port in host.ports:
                    writer.writerow(
                        {
                            "host": host.host,
                            "resolved_ip": host.resolved_ip or "",
                            "host_state": host.state.value,
                            "port": port.port,
                            "protocol": port.protocol.value,
                            "port_state": port.state.value,
                            "service": port.service or "",
                            "banner": (port.banner or "").replace("\n", " ")[:200],
                            "response_time_ms": port.response_time_ms or "",
                            "scan_started_at": result.started_at.isoformat(),
                            "scan_finished_at": result.finished_at.isoformat(),
                        }
                    )
        path.chmod(0o600)
    except OSError as exc:
        raise ExportError(f"no se pudo escribir el CSV en {path}: {exc}") from exc
    return path
