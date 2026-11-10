"""Orquestador principal del análisis de red de PyRecon."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from pyrecon.config import ScanConfig
from pyrecon.core.discovery import discover_hosts
from pyrecon.core.dns_resolver import resolve_dns, reverse_dns
from pyrecon.core.portscan import scan_host
from pyrecon.core.ratelimit import RateLimiter
from pyrecon.core.services import grab_banner, identify_service
from pyrecon.core.severity import classify_port_severity
from pyrecon.models import (
    ConfirmationLevel,
    DnsRecord,
    Finding,
    HostResult,
    HostState,
    PortResult,
    PortState,
    ScanResult,
    Severity,
)
from pyrecon.utils.logger import get_logger
from pyrecon.utils.network import expand_target, is_domain, resolve_host

_logger = get_logger("core.scanner")


class Scanner:
    """Ejecuta un análisis completo: descubrimiento, puertos, servicios y DNS."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.logger = _logger
        self._limiter = RateLimiter(config.rate_limit)

    async def run(self) -> ScanResult:
        """Ejecuta el análisis y devuelve el resultado consolidado.

        Raises:
            asyncio.CancelledError: Si el usuario interrumpe la ejecución.
        """
        started = datetime.now(UTC)
        self.logger.info(
            "análisis iniciado contra %s (puertos: %d, concurrencia: %d, timeout: %.1fs)",
            self.config.target,
            len(self.config.ports),
            self.config.concurrency,
            self.config.timeout,
        )

        targets = expand_target(self.config.target, limit=self.config.max_hosts)
        if len(targets) > 1:
            self.logger.info("el objetivo se expande a %d direcciones", len(targets))

        # El descubrimiento sondea los puertos habituales y, además, los primeros
        # puertos indicados por el usuario (hasta 10) para que un escaneo acotado
        # a puertos no estándar siga detectando hosts.
        probe_ports = list(dict.fromkeys([*self.config.probe_ports, *self.config.ports[:10]]))
        active = await discover_hosts(targets, self.config, self._limiter, probe_ports=probe_ports)
        if not active:
            self.logger.warning("no se detectaron hosts activos")

        hosts: list[HostResult] = []
        for address in active:
            try:
                hosts.append(await self._analyze_host(address))
            except asyncio.CancelledError:  # pragma: no cover - interrupción manual
                raise
            except Exception as exc:  # defensivo: un host no debe detener el análisis
                self.logger.error("error analizando %s: %s", address, exc)

        finished = datetime.now(UTC)
        duration = (finished - started).total_seconds()
        result = ScanResult(
            target=self.config.target,
            scope=self.config.scope.name if self.config.scope else None,
            authorized=self.config.confirm_authorized or self.config.scope is not None,
            started_at=started,
            finished_at=finished,
            duration_seconds=round(duration, 3),
            hosts=hosts,
            findings=self._build_findings(hosts),
            statistics={
                "hosts_evaluated": len(targets),
                "hosts_up": sum(1 for h in hosts if h.state is HostState.UP),
                "open_ports": sum(len(h.open_ports) for h in hosts),
            },
        )
        self.logger.info(
            "análisis finalizado en %.2f s: %d hosts activos, %d puertos abiertos",
            duration,
            result.statistics["hosts_up"],
            result.statistics["open_ports"],
        )
        return result

    async def _analyze_host(self, address: str) -> HostResult:
        """Analiza un único host: DNS, puertos, banners y servicios."""
        resolved_ip = address if not is_domain(address) else resolve_host(address)
        host_label = address

        dns_records: list[DnsRecord] = []
        if self.config.resolve_dns:
            if resolved_ip:
                dns_records = await resolve_dns(resolved_ip if resolved_ip else address)
            elif is_domain(address):
                dns_records = await resolve_dns(address)
            reverse = await reverse_dns(resolved_ip) if resolved_ip else None
            if resolved_ip and reverse and reverse != host_label:
                dns_records.append(DnsRecord(name=resolved_ip, type="PTR", value=reverse))

        open_ports = await scan_host(
            resolved_ip or address, self.config.ports, self.config, self._limiter
        )
        self.logger.info("%s: %d puertos abiertos", address, len(open_ports))

        enriched: list[PortResult] = []
        for port_result in open_ports:
            if port_result.state is not PortState.OPEN:
                continue
            banner = None
            if self.config.grab_banners:
                banner = await grab_banner(
                    resolved_ip or address,
                    port_result.port,
                    self.config.timeout,
                    self.config.banner_max_bytes,
                )
            enriched.append(
                PortResult(
                    port=port_result.port,
                    state=port_result.state,
                    service=identify_service(port_result.port, banner),
                    banner=banner,
                    response_time_ms=port_result.response_time_ms,
                )
            )

        return HostResult(
            host=host_label,
            resolved_ip=resolved_ip,
            state=HostState.UP,
            ports=enriched,
            dns_records=dns_records,
        )

    def _build_findings(self, hosts: list[HostResult]) -> list[Finding]:
        """Genera hallazgos con severidad y nivel de confirmación.

        Las reglas son objetivas y se basan únicamente en el puerto y el servicio
        identificados; no se infiere vulnerabilidad sin evidencia.
        """
        findings: list[Finding] = []
        for host in hosts:
            if not host.open_ports:
                continue
            target = host.resolved_ip or host.host
            findings.append(
                Finding(
                    message=(
                        f"Host activo {target} con {len(host.open_ports)} puerto(s) abierto(s): "
                        + ", ".join(str(p) for p in host.open_ports)
                    ),
                    severity=Severity.INFORMATIVO,
                    confirmation_level=ConfirmationLevel.CONFIRMADO,
                    target=target,
                )
            )
            for port in host.ports:
                if port.state is not PortState.OPEN:
                    continue
                severity = classify_port_severity(port.port, port.service)
                findings.append(
                    Finding(
                        message=(
                            f"Servicio {port.service or 'desconocido'} expuesto "
                            f"en {target}:{port.port}"
                        ),
                        severity=severity,
                        confirmation_level=ConfirmationLevel.POTENCIAL,
                        target=target,
                        port=port.port,
                        evidence=port.banner,
                    )
                )
        return findings
