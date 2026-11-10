"""Exportación de resultados a HTML (informe autónomo y legible)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from pyrecon.exceptions import ExportError
from pyrecon.models import HostResult, PortState, ScanResult

_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe PyRecon — {{ result.target }}</title>
<style>
:root{--bg:#0f1419;--panel:#171e26;--line:#263140;--fg:#e6edf3;--muted:#8b98a5;--accent:#3ddc97;--warn:#f0b429;--bad:#ef5350}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.55;font-size:15px}
main{max-width:1100px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:19px;margin:32px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.sub{color:var(--muted);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .num{font-size:26px;font-weight:700;color:var(--accent)}
.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
.b-open{color:var(--accent);border-color:rgba(61,220,151,.4)}
.b-closed{color:var(--muted)}
.b-filtered{color:var(--warn);border-color:rgba(240,180,41,.4)}
.sev-critico{color:#ff6b6b;border-color:rgba(255,107,107,.5)}
.sev-alto{color:#ff9f43;border-color:rgba(255,159,67,.5)}
.sev-medio{color:#feca57;border-color:rgba(254,202,87,.5)}
.sev-bajo{color:#1dd1a1;border-color:rgba(29,209,161,.5)}
.sev-informativo{color:var(--muted)}
.host{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.host h3{margin:0 0 4px;font-size:16px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.find{background:rgba(61,220,151,.07);border:1px solid rgba(61,220,151,.25);border-radius:10px;padding:14px}
.find li{margin:4px 0}
.foot{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
.warn{color:var(--warn)}
</style>
</head>
<body>
<main>
  <h1>Informe de reconocimiento de red</h1>
  <p class="sub">
    Herramienta: <strong>{{ result.tool }}</strong> v{{ result.version }}
    &middot; Objetivo: <span class="mono">{{ result.target }}</span>
    {% if result.scope %}&middot; Alcance: {{ result.scope }}{% endif %}
  </p>
  <p class="sub">
    Inicio: {{ result.started_at.strftime('%Y-%m-%d %H:%M:%S') }} &middot;
    Fin: {{ result.finished_at.strftime('%Y-%m-%d %H:%M:%S') }} &middot;
    Duración: {{ "%.2f"|format(result.duration_seconds) }} s
  </p>

  <div class="cards">
    <div class="card"><div class="num">{{ result.statistics.get('hosts_evaluated', 0) }}</div><div class="lbl">Hosts evaluados</div></div>
    <div class="card"><div class="num">{{ result.statistics.get('hosts_up', 0) }}</div><div class="lbl">Hosts activos</div></div>
    <div class="card"><div class="num">{{ result.statistics.get('open_ports', 0) }}</div><div class="lbl">Puertos abiertos</div></div>
    <div class="card"><div class="num">{{ result.findings|length }}</div><div class="lbl">Hallazgos</div></div>
  </div>

  <h2>1. Información general de la auditoría</h2>
  <table>
    <tbody>
      <tr><th>Herramienta</th><td>{{ result.tool }} v{{ result.version }}</td><th>Duración</th><td>{{ "%.2f"|format(result.duration_seconds) }} s</td></tr>
      <tr><th>Inicio</th><td>{{ result.started_at.strftime('%Y-%m-%d %H:%M:%S') }}</td><th>Fin</th><td>{{ result.finished_at.strftime('%Y-%m-%d %H:%M:%S') }}</td></tr>
      <tr><th>Autorización</th><td>{{ 'Declarada' if result.authorized else 'No declarada' }}</td><th>Alcance</th><td>{{ result.scope or 'no declarado' }}</td></tr>
    </tbody>
  </table>

  <h2>2. Alcance evaluado</h2>
  <p>Objetivo analizado: <span class="mono">{{ result.target }}</span>. Alcance autorizado: {{ result.scope or 'no declarado' }}.</p>

  <h2>3. Metodología utilizada</h2>
  <p>Análisis no destructivo basado en sondeo TCP (connect scan) sobre los puertos configurados. Descubrimiento de hosts activos, identificación de servicios por puerto y <em>banner</em>, y resolución DNS directa e inversa. No se ejecutan explotaciones, fuerza bruta ni ataques de denegación de servicio.</p>

  <h2>4. Activos identificados</h2>
  {% if result.hosts %}
  <table>
    <thead><tr><th>Host</th><th>IP</th><th>Puertos abiertos</th><th>Servicios</th></tr></thead>
    <tbody>
    {% for host in result.hosts %}
      <tr>
        <td class="mono">{{ host.host }}</td>
        <td class="mono">{{ host.resolved_ip or '—' }}</td>
        <td class="mono">{{ host.open_ports|join(', ') or '—' }}</td>
        <td>{{ host.ports|selectattr('service')|map(attribute='service')|unique|join(', ') or '—' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="warn">No se detectaron hosts activos dentro del alcance evaluado.</p>
  {% endif %}

  <h2>5. Hallazgos encontrados</h2>
  {% if result.findings %}
  <table>
    <thead><tr><th>Severidad</th><th>Hallazgo</th><th>Confirmación</th></tr></thead>
    <tbody>
    {% for finding in result.findings %}
      <tr>
        <td><span class="badge sev-{{ finding.severity.value }}">{{ finding.severity.value.upper() }}</span></td>
        <td>{{ finding.message }}</td>
        <td>{{ finding.confirmation_level.value }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No se generaron hallazgos.</p>
  {% endif %}

  <h2>6. Severidad</h2>
  <table>
    <thead><tr><th>Severidad</th><th>Hallazgos</th></tr></thead>
    <tbody>
    {% for severity, count in result.findings_by_severity.items() %}
      <tr><td><span class="badge sev-{{ severity }}">{{ severity.upper() }}</span></td><td class="mono">{{ count }}</td></tr>
    {% endfor %}
    </tbody>
  </table>

  <h2>7. Evidencias</h2>
  {% set evidencias = [] %}
  {% for host in result.hosts %}{% for p in host.ports %}{% if p.state.value == 'open' %}{% set _ = evidencias.append((host, p)) %}{% endif %}{% endfor %}{% endfor %}
  {% if evidencias %}
  <table>
    <thead><tr><th>Objetivo</th><th>Puerto</th><th>Evidencia</th></tr></thead>
    <tbody>
    {% for host, p in evidencias %}
      <tr>
        <td class="mono">{{ host.resolved_ip or host.host }}</td>
        <td class="mono">{{ p.port }}</td>
        <td class="mono">{{ p.banner or '—' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>Sin evidencias.</p>
  {% endif %}

  <h2>8. Impacto potencial</h2>
  <p>Los puertos abiertos identificados constituyen superficie de exposición. Los servicios sensibles (administración remota, bases de datos, compartición de archivos) expuestos en red merecen revisión prioritaria. Este informe no confirma vulnerabilidades: la confirmación requiere verificación adicional.</p>

  <h2>9. Recomendaciones</h2>
  <ol>
    <li>Restringir el acceso a los servicios sensibles expuestos.</li>
    <li>Verificar que cada servicio abierto es necesario para la operación.</li>
    <li>Actualizar los servicios identificados a versiones soportadas.</li>
    <li>Documentar el inventario de activos y revisarlo periódicamente.</li>
  </ol>

  <h2>10. Plan de remediación</h2>
  <p><strong>Corto plazo:</strong> cerrar o restringir los puertos no necesarios.<br>
     <strong>Medio plazo:</strong> segmentar la red y aplicar control de acceso por servicio.<br>
     <strong>Largo plazo:</strong> establecer un ciclo de revisión periódica del inventario.</p>

  <h2>11. Conclusiones</h2>
  <p>Se evaluaron {{ result.statistics.get('hosts_evaluated', 0) }} direcciones, se detectaron
  {{ result.statistics.get('hosts_up', 0) }} hosts activos y
  {{ result.statistics.get('open_ports', 0) }} puertos abiertos. Se generaron
  {{ result.findings|length }} hallazgos. Se recomienda revisar los servicios sensibles
  identificados y aplicar las medidas correctivas descritas en el plan de remediación.</p>

  <h2>Anexo técnico: detalle por host</h2>
  {% for host in result.hosts %}
  <div class="host">
    <h3>{{ host.host }} {% if host.resolved_ip %}<span class="sub mono">({{ host.resolved_ip }})</span>{% endif %}</h3>
    {% if host.dns_records %}
    <p class="sub">DNS: {% for r in host.dns_records[:6] %}<span class="mono">{{ r.type }} {{ r.value }}</span>{% if not loop.last %} · {% endif %}{% endfor %}</p>
    {% endif %}
    {% if host.ports %}
    <table>
      <thead><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Banner</th><th>ms</th></tr></thead>
      <tbody>
      {% for p in host.ports %}
        <tr>
          <td class="mono">{{ p.port }}/{{ p.protocol.value }}</td>
          <td><span class="badge b-{{ p.state.value }}">{{ p.state.value }}</span></td>
          <td>{{ p.service or '—' }}</td>
          <td class="mono">{{ p.banner or '—' }}</td>
          <td class="mono">{{ p.response_time_ms if p.response_time_ms is not none else '—' }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="sub">Sin puertos abiertos.</p>
    {% endif %}
  </div>
  {% else %}
  <p class="warn">No se detectaron hosts activos dentro del alcance evaluado.</p>
  {% endfor %}

  <div class="foot">
    <p>Generado por {{ result.tool }} v{{ result.version }}. Informe generado con fines de
    auditoría autorizada. No incluye datos personales ni credenciales.</p>
  </div>
</main>
</body>
</html>
"""


def render_html(result: ScanResult) -> str:
    """Renderiza el informe HTML a partir de la plantilla."""
    env = Environment(autoescape=select_autoescape(("html", "xml")))
    template = env.from_string(_TEMPLATE)
    return template.render(result=result, HostResult=HostResult, PortState=PortState)


def export_html(result: ScanResult, path: Path) -> Path:
    """Escribe el informe HTML.

    Raises:
        ExportError: Si no se puede escribir el fichero.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_html(result), encoding="utf-8")
        path.chmod(0o600)
    except OSError as exc:
        raise ExportError(f"no se pudo escribir el HTML en {path}: {exc}") from exc
    return path
