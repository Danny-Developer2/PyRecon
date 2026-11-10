"""Exportación de resultados a PDF (informe ejecutivo con anexo técnico).

El informe se genera con ReportLab y mantiene las 11 secciones que exige la
metodología del departamento. No depende de GTK ni de binarios externos.
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from pyrecon.exceptions import ExportError
from pyrecon.models import ScanResult, Severity

_AVISO_LEGAL = (
    "Informe generado con fines de auditoría autorizada. No incluye datos personales "
    "ni credenciales. El uso de esta herramienta contra sistemas sin autorización "
    "expresa es ilegal."
)

_SECCIONES = (
    "1. Información general de la auditoría",
    "2. Alcance evaluado",
    "3. Metodología utilizada",
    "4. Activos identificados",
    "5. Hallazgos encontrados",
    "6. Severidad",
    "7. Evidencias",
    "8. Impacto potencial",
    "9. Recomendaciones",
    "10. Plan de remediación",
    "11. Conclusiones",
)


def _styles() -> dict[str, ParagraphStyle]:
    """Construye los estilos del informe."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1a2332"),
            spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#5a6b7d"),
            spaceAfter=12,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1a2332"),
            spaceBefore=14,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=9.5,
            leading=13,
            alignment=TA_LEFT,
        ),
        "small": ParagraphStyle(
            "Small",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#5a6b7d"),
        ),
        "cell": ParagraphStyle(
            "Cell",
            parent=base["Normal"],
            fontSize=8.5,
            leading=11,
        ),
        "cell_head": ParagraphStyle(
            "CellHead",
            parent=base["Normal"],
            fontSize=8.5,
            leading=11,
            textColor=colors.white,
        ),
    }


def _severity_color(severity: Severity) -> colors.Color:
    """Color asociado a cada severidad."""
    return {
        Severity.CRITICO: colors.HexColor("#b71c1c"),
        Severity.ALTO: colors.HexColor("#e65100"),
        Severity.MEDIO: colors.HexColor("#f9a825"),
        Severity.BAJO: colors.HexColor("#2e7d32"),
        Severity.INFORMATIVO: colors.HexColor("#5a6b7d"),
    }[severity]


def _header_footer(canvas: Canvas, doc: SimpleDocTemplate) -> None:
    """Dibuja la cabecera y el pie de página."""
    canvas.saveState()
    width, height = A4
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#8a97a5"))
    canvas.drawString(2 * cm, height - 1.2 * cm, "PyRecon — Informe de reconocimiento de red")
    canvas.drawRightString(width - 2 * cm, height - 1.2 * cm, "Uso autorizado")
    canvas.setStrokeColor(colors.HexColor("#d5dce4"))
    canvas.line(2 * cm, height - 1.4 * cm, width - 2 * cm, height - 1.4 * cm)
    canvas.drawCentredString(width / 2, 1.1 * cm, f"Página {doc.page}")
    canvas.restoreState()


def _info_table(result: ScanResult, styles: dict[str, ParagraphStyle]) -> Table:
    """Tabla de información general de la auditoría."""
    data = [
        [
            Paragraph("Herramienta", styles["cell_head"]),
            Paragraph(f"{result.tool} v{result.version}", styles["cell"]),
            Paragraph("Duración", styles["cell_head"]),
            Paragraph(f"{result.duration_seconds:.2f} s", styles["cell"]),
        ],
        [
            Paragraph("Inicio", styles["cell_head"]),
            Paragraph(result.started_at.strftime("%Y-%m-%d %H:%M:%S"), styles["cell"]),
            Paragraph("Fin", styles["cell_head"]),
            Paragraph(result.finished_at.strftime("%Y-%m-%d %H:%M:%S"), styles["cell"]),
        ],
        [
            Paragraph("Autorización", styles["cell_head"]),
            Paragraph("Declarada" if result.authorized else "No declarada", styles["cell"]),
            Paragraph("Alcance", styles["cell_head"]),
            Paragraph(result.scope or "no declarado", styles["cell"]),
        ],
    ]
    table = Table(data, colWidths=[3 * cm, 5.4 * cm, 3 * cm, 5.4 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f6")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#eef2f6")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dce4")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _summary_table(result: ScanResult, styles: dict[str, ParagraphStyle]) -> Table:
    """Tarjetas de resumen con los contadores principales."""
    stats = result.statistics
    data = [
        [
            Paragraph(str(stats.get("hosts_evaluated", 0)), styles["cell"]),
            Paragraph(str(stats.get("hosts_up", 0)), styles["cell"]),
            Paragraph(str(stats.get("open_ports", 0)), styles["cell"]),
            Paragraph(str(len(result.findings)), styles["cell"]),
        ],
        [
            Paragraph("Hosts evaluados", styles["cell_head"]),
            Paragraph("Hosts activos", styles["cell_head"]),
            Paragraph("Puertos abiertos", styles["cell_head"]),
            Paragraph("Hallazgos", styles["cell_head"]),
        ],
    ]
    table = Table(data, colWidths=[4.3 * cm] * 4)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#1a2332")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _severity_table(result: ScanResult, styles: dict[str, ParagraphStyle]) -> Table:
    """Tabla de hallazgos por severidad."""
    counts = result.findings_by_severity
    data = [
        [Paragraph("Severidad", styles["cell_head"]), Paragraph("Hallazgos", styles["cell_head"])]
    ]
    for severity in Severity:
        data.append(
            [
                Paragraph(severity.value.upper(), styles["cell"]),
                Paragraph(str(counts.get(severity.value, 0)), styles["cell"]),
            ]
        )
    table = Table(data, colWidths=[6 * cm, 4 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dce4")),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _findings_table(result: ScanResult, styles: dict[str, ParagraphStyle]) -> Table:
    """Tabla de hallazgos con severidad y nivel de confirmación."""
    data = [
        [
            Paragraph("Severidad", styles["cell_head"]),
            Paragraph("Hallazgo", styles["cell_head"]),
            Paragraph("Confirmación", styles["cell_head"]),
        ]
    ]
    for finding in result.findings:
        data.append(
            [
                Paragraph(finding.severity.value.upper(), styles["cell"]),
                Paragraph(finding.message, styles["cell"]),
                Paragraph(finding.confirmation_level.value, styles["cell"]),
            ]
        )
    table = Table(data, colWidths=[2.6 * cm, 10.4 * cm, 3.2 * cm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dce4")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _hosts_table(result: ScanResult, styles: dict[str, ParagraphStyle]) -> Table:
    """Tabla de activos identificados."""
    data = [
        [
            Paragraph("Host", styles["cell_head"]),
            Paragraph("IP", styles["cell_head"]),
            Paragraph("Puertos abiertos", styles["cell_head"]),
            Paragraph("Servicios", styles["cell_head"]),
        ]
    ]
    for host in result.hosts:
        services = sorted({p.service for p in host.ports if p.state.value == "open" and p.service})
        data.append(
            [
                Paragraph(host.host, styles["cell"]),
                Paragraph(host.resolved_ip or "—", styles["cell"]),
                Paragraph(", ".join(str(p) for p in host.open_ports) or "—", styles["cell"]),
                Paragraph(", ".join(services) or "—", styles["cell"]),
            ]
        )
    table = Table(data, colWidths=[3.6 * cm, 3.6 * cm, 4.6 * cm, 4.4 * cm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dce4")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _evidence_table(result: ScanResult, styles: dict[str, ParagraphStyle]) -> Table:
    """Tabla de evidencias (banners observados)."""
    data = [
        [
            Paragraph("Objetivo", styles["cell_head"]),
            Paragraph("Puerto", styles["cell_head"]),
            Paragraph("Evidencia", styles["cell_head"]),
        ]
    ]
    for host in result.hosts:
        target = host.resolved_ip or host.host
        for port in host.ports:
            if port.state.value != "open":
                continue
            data.append(
                [
                    Paragraph(target, styles["cell"]),
                    Paragraph(str(port.port), styles["cell"]),
                    Paragraph(port.banner or "—", styles["cell"]),
                ]
            )
    if len(data) == 1:
        data.append(
            [
                Paragraph("—", styles["cell"]),
                Paragraph("—", styles["cell"]),
                Paragraph("Sin evidencias.", styles["cell"]),
            ]
        )
    table = Table(data, colWidths=[3.4 * cm, 2 * cm, 10.8 * cm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dce4")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _build_story(result: ScanResult, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    """Construye el contenido del informe con las 11 secciones."""
    story: list[Flowable] = []
    body = styles["body"]

    story.append(Paragraph("Informe de reconocimiento de red", styles["title"]))
    story.append(
        Paragraph(
            f"Objetivo: {result.target}"
            + (f" &middot; Alcance: {result.scope}" if result.scope else ""),
            styles["subtitle"],
        )
    )
    story.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#1a2332")))
    story.append(Spacer(1, 10))

    # 1. Información general
    story.append(Paragraph(_SECCIONES[0], styles["h2"]))
    story.append(_info_table(result, styles))
    story.append(Spacer(1, 10))
    story.append(_summary_table(result, styles))

    # 2. Alcance evaluado
    story.append(Paragraph(_SECCIONES[1], styles["h2"]))
    if result.authorized:
        alcance = (
            f"Objetivo analizado: <b>{result.target}</b>.<br/>"
            f"Alcance autorizado: {result.scope or 'no declarado'}. "
            "Autorización expresa declarada por el operador."
        )
    else:
        alcance = (
            f"Objetivo analizado: <b>{result.target}</b>.<br/>"
            f"Alcance autorizado: {result.scope or 'no declarado'}."
        )
    story.append(Paragraph(alcance, body))

    # 3. Metodología
    story.append(Paragraph(_SECCIONES[2], styles["h2"]))
    story.append(
        Paragraph(
            "Análisis no destructivo basado en sondeo TCP (connect scan) sobre los puertos "
            "configurados. Descubrimiento de hosts activos, identificación de servicios por "
            "puerto y banner, y resolución DNS directa e inversa. No se ejecutan "
            "explotaciones, fuerza bruta ni ataques de denegación de servicio.",
            body,
        )
    )

    # 4. Activos identificados
    story.append(Paragraph(_SECCIONES[3], styles["h2"]))
    if result.hosts:
        story.append(_hosts_table(result, styles))
    else:
        story.append(Paragraph("No se detectaron hosts activos dentro del alcance evaluado.", body))

    # 5. Hallazgos
    story.append(Paragraph(_SECCIONES[4], styles["h2"]))
    if result.findings:
        story.append(_findings_table(result, styles))
    else:
        story.append(Paragraph("No se generaron hallazgos.", body))

    # 6. Severidad
    story.append(Paragraph(_SECCIONES[5], styles["h2"]))
    story.append(_severity_table(result, styles))

    # 7. Evidencias
    story.append(Paragraph(_SECCIONES[6], styles["h2"]))
    story.append(_evidence_table(result, styles))

    # 8. Impacto potencial
    story.append(Paragraph(_SECCIONES[7], styles["h2"]))
    story.append(
        Paragraph(
            "Los puertos abiertos identificados constituyen superficie de exposición. "
            "Los servicios sensibles (administración remota, bases de datos, compartición "
            "de archivos) expuestos en red merecen revisión prioritaria. Este informe no "
            "confirma vulnerabilidades: la confirmación requiere verificación adicional.",
            body,
        )
    )

    # 9. Recomendaciones
    story.append(Paragraph(_SECCIONES[8], styles["h2"]))
    story.append(
        Paragraph(
            "1. Restringir el acceso a los servicios sensibles expuestos.<br/>"
            "2. Verificar que cada servicio abierto es necesario para la operación.<br/>"
            "3. Actualizar los servicios identificados a versiones soportadas.<br/>"
            "4. Documentar el inventario de activos y revisarlo periódicamente.",
            body,
        )
    )

    # 10. Plan de remediación
    story.append(Paragraph(_SECCIONES[9], styles["h2"]))
    story.append(
        Paragraph(
            "Corto plazo: cerrar o restringir los puertos no necesarios.<br/>"
            "Medio plazo: segmentar la red y aplicar control de acceso por servicio.<br/>"
            "Largo plazo: establecer un ciclo de revisión periódica del inventario.",
            body,
        )
    )

    # 11. Conclusiones
    story.append(Paragraph(_SECCIONES[10], styles["h2"]))
    story.append(
        Paragraph(
            f"Se evaluaron {result.statistics.get('hosts_evaluated', 0)} direcciones, "
            f"se detectaron {result.statistics.get('hosts_up', 0)} hosts activos y "
            f"{result.statistics.get('open_ports', 0)} puertos abiertos. "
            f"Se generaron {len(result.findings)} hallazgos. Se recomienda revisar los "
            "servicios sensibles identificados y aplicar las medidas correctivas "
            "descritas en el plan de remediación.",
            body,
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("Anexo técnico: detalle por host", styles["h2"]))
    for host in result.hosts:
        story.append(Paragraph(f"{host.host}", styles["h2"]))
        if host.dns_records:
            story.append(
                Paragraph(
                    "DNS: " + ", ".join(f"{r.type} {r.value}" for r in host.dns_records[:6]),
                    styles["small"],
                )
            )
        if host.ports:
            port_data = [
                [
                    Paragraph("Puerto", styles["cell_head"]),
                    Paragraph("Estado", styles["cell_head"]),
                    Paragraph("Servicio", styles["cell_head"]),
                    Paragraph("Banner", styles["cell_head"]),
                ]
            ]
            for port in host.ports:
                port_data.append(
                    [
                        Paragraph(f"{port.port}/{port.protocol.value}", styles["cell"]),
                        Paragraph(port.state.value, styles["cell"]),
                        Paragraph(port.service or "—", styles["cell"]),
                        Paragraph(port.banner or "—", styles["cell"]),
                    ]
                )
            port_table = Table(port_data, colWidths=[2.6 * cm, 2.2 * cm, 3 * cm, 8.4 * cm])
            port_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dce4")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(port_table)
        else:
            story.append(Paragraph("Sin puertos abiertos.", styles["small"]))
        story.append(Spacer(1, 8))

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#d5dce4")))
    story.append(Paragraph(_AVISO_LEGAL, styles["small"]))
    return story


def render_pdf(result: ScanResult) -> bytes:
    """Genera el informe PDF en memoria.

    Returns:
        El contenido binario del PDF.

    Raises:
        ExportError: Si no se puede generar el documento.
    """
    import io

    buffer = io.BytesIO()
    try:
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            title=f"Informe PyRecon — {result.target}",
            author="PyRecon",
        )
        styles = _styles()
        doc.build(
            _build_story(result, styles), onFirstPage=_header_footer, onLaterPages=_header_footer
        )
    except Exception as exc:  # ReportLab lanza excepciones variadas
        raise ExportError(f"no se pudo generar el PDF: {exc}") from exc
    return buffer.getvalue()


def export_pdf(result: ScanResult, path: Path) -> Path:
    """Escribe el informe PDF en disco con permisos restrictivos.

    Raises:
        ExportError: Si no se puede escribir el fichero.
    """
    payload = render_pdf(result)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o600)
    except OSError as exc:
        raise ExportError(f"no se pudo escribir el PDF en {path}: {exc}") from exc
    return path
