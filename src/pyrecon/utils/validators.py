"""Validación de entradas y control de autorización."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pyrecon.exceptions import AuthorizationError, ValidationError
from pyrecon.models import Scope
from pyrecon.utils.network import expand_target, is_target_in_scope


def validate_target(target: str, max_hosts: int = 4096) -> str:
    """Valida que el objetivo tenga formato correcto.

    Returns:
        El objetivo normalizado.

    Raises:
        ValidationError: Si el objetivo no es una IP, CIDR o dominio válido.
    """
    normalized = target.strip()
    if not normalized:
        raise ValidationError("debes indicar un objetivo (IP, rango CIDR o dominio)")
    try:
        expand_target(normalized, limit=max_hosts)
    except ValidationError:
        raise
    return normalized


def validate_timeout(value: float) -> float:
    """Valida el tiempo de espera."""
    if value <= 0:
        raise ValidationError("el tiempo de espera debe ser mayor que cero")
    if value > 30:
        raise ValidationError("el tiempo de espera no puede superar 30 segundos")
    return float(value)


def validate_concurrency(value: int) -> int:
    """Valida el nivel de concurrencia."""
    if value < 1:
        raise ValidationError("la concurrencia debe ser al menos 1")
    if value > 500:
        raise ValidationError("la concurrencia no puede superar 500")
    return int(value)


def validate_rate_limit(value: float | None) -> float | None:
    """Valida el límite de peticiones por segundo."""
    if value is None:
        return None
    if value < 1:
        raise ValidationError("el límite de ritmo debe ser al menos 1 petición/segundo")
    if value > 1000:
        raise ValidationError("el límite de ritmo no puede superar 1000 peticiones/segundo")
    return float(value)


def ensure_authorized(
    target: str,
    scope: Scope | None,
    confirm_authorized: bool,
) -> None:
    """Comprueba que el análisis está autorizado antes de ejecutarlo.

    Reglas:
      * Si se proporciona un alcance, el objetivo debe estar dentro de él.
      * Si no hay alcance, es obligatorio declarar la autorización con
        ``confirm_authorized``.

    Raises:
        AuthorizationError: Si no se declara autorización.
        ValidationError: Si el objetivo está fuera del alcance.
    """
    if scope is not None:
        if not is_target_in_scope(target, scope):
            raise ValidationError(
                f"el objetivo {target!r} está FUERA del alcance autorizado "
                f"({scope.name!r}). La ejecución se ha detenido."
            )
        return

    if not confirm_authorized:
        raise AuthorizationError(
            "no se ha declarado autorización. Especifica --scope con el alcance autorizado "
            "o usa --confirm-authorized para declarar que dispones de autorización expresa."
        )


def load_scope_file(path: Path | None) -> Scope | None:
    """Carga el alcance desde fichero si se proporciona."""
    if path is None:
        return None
    from pyrecon.utils.network import load_scope

    return load_scope(path)


def ensure_path_writable(path: Path) -> None:
    """Comprueba que se puede escribir en la ruta de salida."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and not path.is_file():
            raise ValidationError(f"la ruta de salida no es un fichero: {path}")
    except OSError as exc:
        raise ValidationError(f"no se puede escribir en {path}: {exc}") from exc


def parse_ports(raw: Any) -> list[int]:
    """Interpreta una lista de puertos en formato flexible.

    Admite listas de enteros o cadenas como ``"80,443"`` y ``"1-1024"``.
    """
    if isinstance(raw, str):
        tokens = [t.strip() for t in raw.replace("\n", ",").split(",") if t.strip()]
        ports: list[int] = []
        for token in tokens:
            if "-" in token:
                start_s, _, end_s = token.partition("-")
                try:
                    start, end = int(start_s), int(end_s)
                except ValueError as exc:
                    raise ValidationError(f"rango de puertos no válido: {token!r}") from exc
                if start > end or end - start > 4096:
                    raise ValidationError(f"rango de puertos no válido: {token!r}")
                ports.extend(range(start, end + 1))
            else:
                try:
                    ports.append(int(token))
                except ValueError as exc:
                    raise ValidationError(f"puerto no válido: {token!r}") from exc
        return ports
    if isinstance(raw, (list, tuple)):
        try:
            return [int(v) for v in raw]
        except (TypeError, ValueError) as exc:
            raise ValidationError("la lista de puertos contiene valores no numéricos") from exc
    raise ValidationError("formato de puertos no soportado")
