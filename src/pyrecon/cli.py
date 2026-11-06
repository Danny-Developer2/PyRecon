"""Interfaz de línea de comandos de PyRecon (Typer + Rich)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pyrecon import __version__
from pyrecon.config import DEFAULT_PORTS, DEFAULT_PROBE_PORTS, ScanConfig
from pyrecon.core.scanner import Scanner
from pyrecon.exceptions import PyReconError
from pyrecon.export import export_result
from pyrecon.models import PortState, ScanResult
from pyrecon.utils.logger import setup_logger
from pyrecon.utils.validators import (
    ensure_authorized,
    ensure_path_writable,
    load_scope_file,
    parse_ports,
    validate_concurrency,
    validate_rate_limit,
    validate_target,
    validate_timeout,
)

app = typer.Typer(
    name="pyrecon",
    help="PyRecon — reconocimiento de infraestructura de red (solo auditorías autorizadas).",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

AVISO_LEGAL = (
    "[yellow]AVISO:[/yellow] esta herramienta está pensada exclusivamente para "
    "auditorías autorizadas. Comprueba que dispones de autorización expresa."
)


def _build_config(
    target: str,
    ports: str,
    timeout: float,
    concurrency: int,
    rate_limit: float | None,
    scope_file: Path | None,
    confirm_authorized: bool,
    output: Path | None,
    no_banners: bool,
    no_dns: bool,
) -> ScanConfig:
    """Construye la configuración validando todas las entradas."""
    validated_target = validate_target(target)
    port_list = parse_ports(ports) if ports else list(DEFAULT_PORTS)
    scope = load_scope_file(scope_file)
    ensure_authorized(validated_target, scope, confirm_authorized)

    config = ScanConfig(
        target=validated_target,
        ports=port_list,
        probe_ports=list(DEFAULT_PROBE_PORTS),
        timeout=validate_timeout(timeout),
        concurrency=validate_concurrency(concurrency),
        rate_limit=validate_rate_limit(rate_limit),
        scope=scope,
        scope_file=scope_file,
        confirm_authorized=confirm_authorized,
        resolve_dns=not no_dns,
        grab_banners=not no_banners,
    )
    if output is not None:
        ensure_path_writable(output)
    return config


def _print_summary(result: ScanResult) -> None:
    """Muestra un resumen en tabla por consola."""
    console.print(f"\n[bold]PyRecon[/bold] — objetivo: {result.target}")
    console.print(
        f"Inicio: {result.started_at:%Y-%m-%d %H:%M:%S} · Duración: {result.duration_seconds:.2f}s"
    )

    table = Table(title="Hosts activos", show_lines=False)
    table.add_column("Host", style="cyan")
    table.add_column("IP", style="dim")
    table.add_column("Puertos abiertos", justify="right", style="green")
    table.add_column("Servicios", style="magenta")

    for host in result.hosts:
        services = sorted(
            {p.service for p in host.ports if p.service and p.state is PortState.OPEN}
        )
        table.add_row(
            host.host,
            host.resolved_ip or "—",
            ", ".join(str(p) for p in host.open_ports) or "—",
            ", ".join(services) or "—",
        )

    if result.hosts:
        console.print(table)
    else:
        console.print("[yellow]No se detectaron hosts activos.[/yellow]")

    console.print(
        f"\nResumen: {result.statistics['hosts_up']} host(s) activo(s), "
        f"{result.statistics['open_ports']} puerto(s) abierto(s), "
        f"{len(result.findings)} hallazgo(s)."
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="IP, rango CIDR o dominio autorizado."),
    ports: str = typer.Option(
        ",".join(str(p) for p in DEFAULT_PORTS),
        "--ports",
        "-p",
        help="Puertos o rangos, p. ej. '80,443' o '1-1024'.",
    ),
    timeout: float = typer.Option(1.0, "--timeout", "-t", help="Tiempo de espera por puerto."),
    concurrency: int = typer.Option(100, "--concurrency", "-c", help="Conexiones simultáneas."),
    rate_limit: float | None = typer.Option(
        None, "--rate-limit", help="Peticiones por segundo (sin límite si se omite)."
    ),
    scope_file: Path | None = typer.Option(
        None, "--scope", help="Fichero JSON con el alcance autorizado."
    ),
    confirm_authorized: bool = typer.Option(
        False, "--confirm-authorized", help="Declara que se dispone de autorización expresa."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Ruta del informe (se añade la extensión)."
    ),
    format: str = typer.Option("json", "--format", "-f", help="Formato: json, csv o html."),
    log_file: Path | None = typer.Option(None, "--log-file", help="Volcar el log a fichero."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Registro detallado."),
    no_banners: bool = typer.Option(False, "--no-banners", help="No obtener banners."),
    no_dns: bool = typer.Option(False, "--no-dns", help="No resolver DNS."),
) -> None:
    """Ejecuta un análisis de red sobre el objetivo autorizado."""
    setup_logger("DEBUG" if verbose else "INFO", log_file)
    console.print(AVISO_LEGAL)

    try:
        config = _build_config(
            target=target,
            ports=ports,
            timeout=timeout,
            concurrency=concurrency,
            rate_limit=rate_limit,
            scope_file=scope_file,
            confirm_authorized=confirm_authorized,
            output=output,
            no_banners=no_banners,
            no_dns=no_dns,
        )
    except PyReconError as exc:
        err_console.print(f"[red]Error de validación:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    try:
        result = asyncio.run(Scanner(config).run())
    except KeyboardInterrupt:  # pragma: no cover - interrupción manual
        err_console.print("\n[yellow]Ejecución interrumpida por el usuario.[/yellow]")
        raise typer.Exit(code=130) from None
    except PyReconError as exc:
        err_console.print(f"[red]Error durante el análisis:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _print_summary(result)

    if output is not None:
        try:
            written = export_result(result, output, format)
        except PyReconError as exc:
            err_console.print(f"[red]Error al exportar:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]Informe guardado en:[/green] {written}")


@app.command()
def resolve(
    host: str = typer.Argument(..., help="Nombre de dominio a resolver."),
) -> None:
    """Muestra los registros DNS básicos de un dominio."""
    from pyrecon.core.dns_resolver import resolve_dns

    setup_logger("WARNING")
    records = asyncio.run(resolve_dns(host))
    if not records:
        console.print(f"[yellow]No se obtuvieron registros para {host}.[/yellow]")
        return
    table = Table(title=f"Registros DNS de {host}")
    table.add_column("Tipo", style="cyan")
    table.add_column("Nombre", style="dim")
    table.add_column("Valor")
    table.add_column("TTL", justify="right")
    for record in records:
        table.add_row(record.type, record.name, record.value, str(record.ttl or "—"))
    console.print(table)


@app.command()
def version() -> None:
    """Muestra la versión de PyRecon."""
    console.print(f"PyRecon {__version__}")


def main() -> None:
    """Punto de entrada de la CLI."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
