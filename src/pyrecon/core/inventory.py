"""Inventario persistente de activos en SQLite.

Almacena cada ejecución y permite comparar el barrido actual con el anterior
para detectar hosts nuevos, puertos nuevos y puertos cerrados.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pyrecon.exceptions import InventoryError
from pyrecon.models import ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    version TEXT NOT NULL,
    target TEXT NOT NULL,
    scope TEXT,
    authorized INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    hosts_evaluated INTEGER NOT NULL DEFAULT 0,
    hosts_up INTEGER NOT NULL DEFAULT 0,
    open_ports INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    resolved_ip TEXT,
    state TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY (execution_id) REFERENCES executions (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    banner TEXT,
    response_time_ms REAL,
    FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    port INTEGER,
    detail TEXT NOT NULL,
    FOREIGN KEY (execution_id) REFERENCES executions (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets (resolved_ip);
CREATE INDEX IF NOT EXISTS idx_ports_asset ON ports (asset_id);
CREATE INDEX IF NOT EXISTS idx_changes_execution ON changes (execution_id);
"""


class Inventory:
    """Persistencia del inventario de activos y detección de cambios."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._connection: sqlite3.Connection | None = None

    def open(self) -> None:
        """Abre la base de datos y crea el esquema si no existe.

        Raises:
            InventoryError: Si no se puede abrir o inicializar la base de datos.
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(self.path)
            self._connection.row_factory = sqlite3.Row
            self._connection.executescript(_SCHEMA)
            self._connection.commit()
        except sqlite3.Error as exc:
            raise InventoryError(f"no se pudo abrir el inventario en {self.path}: {exc}") from exc

    def close(self) -> None:
        """Cierra la conexión con la base de datos."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> Inventory:
        self.open()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def connection(self) -> sqlite3.Connection:
        """Conexión activa.

        Raises:
            InventoryError: Si la base de datos no está abierta.
        """
        if self._connection is None:
            raise InventoryError("el inventario no está abierto")
        return self._connection

    def record(self, result: ScanResult) -> int:
        """Guarda una ejecución completa con sus activos y puertos.

        Args:
            result: Resultado del análisis a persistir.

        Returns:
            El identificador de la ejecución registrada.

        Raises:
            InventoryError: Si no se puede registrar la ejecución.
        """
        now = datetime.now(UTC).isoformat()
        try:
            cursor = self.connection.execute(
                """
                INSERT INTO executions
                    (tool, version, target, scope, authorized, started_at, finished_at,
                     duration_seconds, hosts_evaluated, hosts_up, open_ports, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.tool,
                    result.version,
                    result.target,
                    result.scope,
                    1 if result.authorized else 0,
                    result.started_at.isoformat(),
                    result.finished_at.isoformat(),
                    result.duration_seconds,
                    result.statistics.get("hosts_evaluated", 0),
                    result.statistics.get("hosts_up", 0),
                    result.statistics.get("open_ports", 0),
                    now,
                ),
            )
            execution_id = int(cursor.lastrowid or 0)
            for host in result.hosts:
                asset_cursor = self.connection.execute(
                    """
                    INSERT INTO assets
                        (execution_id, host, resolved_ip, state, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (execution_id, host.host, host.resolved_ip, host.state.value, now, now),
                )
                asset_id = int(asset_cursor.lastrowid or 0)
                for port in host.ports:
                    self.connection.execute(
                        """
                        INSERT INTO ports
                            (asset_id, port, protocol, state, service, banner, response_time_ms)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            asset_id,
                            port.port,
                            port.protocol.value,
                            port.state.value,
                            port.service,
                            port.banner,
                            port.response_time_ms,
                        ),
                    )
            self.connection.commit()
        except sqlite3.Error as exc:
            raise InventoryError(f"no se pudo registrar la ejecución: {exc}") from exc
        return execution_id

    def last_execution(self) -> dict[str, object] | None:
        """Devuelve la última ejecución registrada.

        Returns:
            Un diccionario con los datos de la ejecución, o ``None`` si no hay.
        """
        row = self.connection.execute(
            "SELECT * FROM executions ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row is not None else None

    def list_executions(self, limit: int = 20) -> list[dict[str, object]]:
        """Lista las ejecuciones registradas, de la más reciente a la más antigua."""
        rows = self.connection.execute(
            "SELECT * FROM executions ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def diff(self, current: ScanResult) -> list[dict[str, object]]:
        """Compara un resultado con la última ejecución registrada.

        Args:
            current: Resultado del barrido actual.

        Returns:
            Lista de cambios detectados (host nuevo, puerto nuevo, puerto cerrado,
            host ausente). Vacía si no hay ejecución anterior.
        """
        previous = self.last_execution()
        if previous is None:
            return []
        previous_id = int(str(previous["id"]))
        previous_ports = self._ports_by_ip(previous_id)
        current_ports = self._ports_by_ip_from_result(current)

        changes: list[dict[str, object]] = []
        previous_ips = set(previous_ports)
        current_ips = set(current_ports)

        for ip in sorted(current_ips - previous_ips):
            changes.append(
                {
                    "kind": "host_nuevo",
                    "target": ip,
                    "port": None,
                    "detail": f"Host {ip} no estaba presente en el barrido anterior.",
                }
            )
        for ip in sorted(previous_ips - current_ips):
            changes.append(
                {
                    "kind": "host_ausente",
                    "target": ip,
                    "port": None,
                    "detail": f"Host {ip} ya no está activo.",
                }
            )
        for ip in sorted(current_ips & previous_ips):
            new_ports = current_ports[ip] - previous_ports[ip]
            closed_ports = previous_ports[ip] - current_ports[ip]
            for port in sorted(new_ports):
                changes.append(
                    {
                        "kind": "puerto_nuevo",
                        "target": ip,
                        "port": port,
                        "detail": f"Puerto {port}/tcp abierto en {ip} (antes cerrado o filtrado).",
                    }
                )
            for port in sorted(closed_ports):
                changes.append(
                    {
                        "kind": "puerto_cerrado",
                        "target": ip,
                        "port": port,
                        "detail": f"Puerto {port}/tcp ya no está abierto en {ip}.",
                    }
                )
        return changes

    def record_changes(self, execution_id: int, changes: list[dict[str, object]]) -> None:
        """Persiste los cambios detectados para una ejecución.

        Raises:
            InventoryError: Si no se pueden registrar los cambios.
        """
        try:
            for change in changes:
                self.connection.execute(
                    """
                    INSERT INTO changes (execution_id, kind, target, port, detail)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        str(change["kind"]),
                        str(change["target"]),
                        int(str(change["port"])) if change["port"] is not None else None,
                        str(change["detail"]),
                    ),
                )
            self.connection.commit()
        except sqlite3.Error as exc:
            raise InventoryError(f"no se pudieron registrar los cambios: {exc}") from exc

    def _ports_by_ip(self, execution_id: int) -> dict[str, set[int]]:
        """Puertos abiertos por IP de una ejecución persistida."""
        rows = self.connection.execute(
            """
            SELECT a.resolved_ip AS ip, p.port AS port
            FROM assets a
            JOIN ports p ON p.asset_id = a.id
            WHERE a.execution_id = ? AND p.state = 'open'
            """,
            (execution_id,),
        ).fetchall()
        result: dict[str, set[int]] = {}
        for row in rows:
            ip = row["ip"]
            if not ip:
                continue
            result.setdefault(ip, set()).add(int(row["port"]))
        return result

    def _ports_by_ip_from_result(self, result: ScanResult) -> dict[str, set[int]]:
        """Puertos abiertos por IP a partir de un resultado en memoria."""
        grouped: dict[str, set[int]] = {}
        for host in result.hosts:
            ip = host.resolved_ip or host.host
            grouped.setdefault(ip, set()).update(host.open_ports)
        return grouped
