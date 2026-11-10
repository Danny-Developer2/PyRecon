"""Exportación de resultados a JSON, CSV, HTML y PDF."""

from pathlib import Path

from pyrecon.exceptions import ExportError
from pyrecon.export.csv_export import export_csv
from pyrecon.export.html_export import export_html
from pyrecon.export.json_export import export_json
from pyrecon.export.pdf_export import export_pdf
from pyrecon.models import ScanResult

SUPPORTED_FORMATS = ("json", "csv", "html", "pdf")


def export_result(result: ScanResult, path: Path, fmt: str) -> Path:
    """Exporta un resultado al formato indicado.

    Args:
        result: Resultado del análisis.
        path: Ruta de salida (la extensión se ignora; se usa el formato).
        fmt: Formato deseado: ``json``, ``csv``, ``html`` o ``pdf``.

    Returns:
        La ruta final del informe generado.

    Raises:
        ExportError: Si el formato no está soportado o no se puede escribir.
    """
    normalized = fmt.lower().lstrip(".")
    if normalized not in SUPPORTED_FORMATS:
        raise ExportError(f"formato no soportado: {fmt!r}. Usa: {', '.join(SUPPORTED_FORMATS)}")

    destination = path.with_suffix(f".{normalized}")
    try:
        if normalized == "json":
            return export_json(result, destination)
        if normalized == "csv":
            return export_csv(result, destination)
        if normalized == "html":
            return export_html(result, destination)
        return export_pdf(result, destination)
    except ExportError:
        raise
    except OSError as exc:
        raise ExportError(f"no se pudo escribir el informe en {destination}: {exc}") from exc


__all__ = [
    "export_result",
    "SUPPORTED_FORMATS",
    "export_json",
    "export_csv",
    "export_html",
    "export_pdf",
]
