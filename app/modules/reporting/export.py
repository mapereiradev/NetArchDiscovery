from __future__ import annotations
import os, json
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, BaseLoader


JINJA_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Informe — {{ job.id[:8] }}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Arial;
           background: #0b1020; color: #e5e7eb; margin: 1.5rem; }
    h1,h2,h3 { margin: .4rem 0; }
    .muted { color:#94a3b8 }
    .card{border:1px solid #334155;border-radius:10px;padding:1rem;background:#0b1028;margin:1rem 0}
    table{border-collapse:collapse;width:100%}
    th,td{border:1px solid #334155;padding:.5rem;text-align:left}
    th{background:#0f172a}
    code,pre{background:#0f172a;padding:.25rem .5rem;border-radius:6px}
    .kv{display:grid;grid-template-columns:180px 1fr;gap:.4rem}
  </style>
</head>
<body>
  <h1>Informe de escaneo</h1>
  <div class="card kv">
    <div><strong>Job</strong></div><div><code>{{ job.id }}</code></div>
    <div><strong>Creado</strong></div><div>{{ job.created_at }}</div>
    <div><strong>Generado</strong></div><div>{{ generated }}</div>
    <div><strong>Target</strong></div><div>{{ job.target or "(local)" }}</div>
    <div><strong>Herramientas</strong></div><div>{{ job.tools|join(", ") }}</div>
  </div>

  {% if job.results.nmap %}
  <div class="card">
    <h2>Resultados Nmap</h2>
    {% set assets = job.results.nmap.assets %}
    {% if assets %}
    <table>
      <thead>
        <tr>
          <th>IP</th><th>Hostname</th><th>SO</th><th>Puerto</th><th>Servicio</th><th>Producto</th><th>Versión</th>
        </tr>
      </thead>
      <tbody>
        {% for host in assets %}
          {% if host.ports and host.ports|length > 0 %}
            {% for p in host.ports %}
            <tr>
              <td>{{ host.ip }}</td>
              <td>{{ host.hostname or "" }}</td>
              <td>{{ host.os or "" }}</td>
              <td>{{ p.port }}/{{ p.proto }}</td>
              <td>{{ p.service or "" }}</td>
              <td>{{ p.product or "" }}</td>
              <td>{{ p.version or "" }}</td>
            </tr>
            {% endfor %}
          {% else %}
            <tr>
              <td>{{ host.ip }}</td><td>{{ host.hostname or "" }}</td><td>{{ host.os or "" }}</td>
              <td colspan="4" class="muted">Sin puertos abiertos</td>
            </tr>
          {% endif %}
        {% endfor %}
      </tbody>
    </table>
    {% else %}
      <p class="muted">Nmap no devolvió activos.</p>
    {% endif %}
  </div>
  {% endif %}

  {% if job.results.local_enum %}
  <div class="card">
    <h2>Enumeración local</h2>
    <h3>Rutas</h3>
    <pre>{{ job.results.local_enum.routes }}</pre>
    <h3>Sockets en escucha</h3>
    <pre>{{ job.results.local_enum.listening }}</pre>
    <details>
      <summary>/etc/resolv.conf</summary>
      <pre>{{ job.results.local_enum.resolv }}</pre>
    </details>
    <details>
      <summary>/etc/hosts</summary>
      <pre>{{ job.results.local_enum.hosts }}</pre>
    </details>
  </div>
  {% endif %}

  {% if job.errors %}
  <div class="card">
    <h2>Errores</h2>
    <pre>{{ job.errors | tojson(indent=2) }}</pre>
  </div>
  {% endif %}

{# ===== Resultados theHarvester ===== #}
{% set hv0 = job.results.theHarvester or job.results.theharvester %}
{% if hv0 %}
  {# Diccionario real de datos (hosts/emails/...) #}
  {% set data = hv0.results if hv0.results is defined else hv0 %}
  {% set cmd  = (hv0.meta.cmd if (hv0.meta is defined and hv0.meta.cmd is defined) else (data.cmd if data.cmd is defined else None)) %}

  <div class="card">
    <h2>Resultados theHarvester</h2>

    {% if cmd %}
      <p class="muted"><strong>Comando:</strong></p>
      <pre class="muted" style="white-space:pre-wrap;word-break:break-word">{{ cmd }}</pre>
    {% endif %}

    <div class="grid two">
      <section>
        <h3>Hosts ({{ data.hosts|length if data.hosts is defined else 0 }})</h3>
        {% if data.hosts is defined and data.hosts|length > 0 %}
          <ul class="mono">
            {% for h in data.hosts[:20] %}
              <li>{{ h }}</li>
            {% endfor %}
          </ul>
          {% if data.hosts|length > 20 %}
            <details>
              <summary>Ver los {{ data.hosts|length - 20 }} restantes</summary>
              <ul class="mono">
                {% for h in data.hosts[20:] %}
                  <li>{{ h }}</li>
                {% endfor %}
              </ul>
            </details>
          {% endif %}
        {% else %}
          <p class="muted">Sin hosts.</p>
        {% endif %}
      </section>

      <section>
        <h3>Emails ({{ data.emails|length if data.emails is defined else 0 }})</h3>
        {% if data.emails is defined and data.emails|length > 0 %}
          <ul class="mono">
            {% for e in data.emails[:20] %}
              <li>{{ e }}</li>
            {% endfor %}
          </ul>
          {% if data.emails|length > 20 %}
            <details>
              <summary>Ver los {{ data.emails|length - 20 }} restantes</summary>
              <ul class="mono">
                {% for e in data.emails[20:] %}
                  <li>{{ e }}</li>
                {% endfor %}
              </ul>
            </details>
          {% endif %}
        {% else %}
          <p class="muted">Sin emails.</p>
        {% endif %}
      </section>
    </div>

    <section>
      <h3>Shodan ({{ data.shodan|length if data.shodan is defined else 0 }})</h3>
      {% if data.shodan is defined and data.shodan|length > 0 %}
        <details open>
          <summary>Ver resultados</summary>
          <ul class="mono">
            {% for item in data.shodan %}
              <li>{{ item }}</li>
            {% endfor %}
          </ul>
        </details>
      {% else %}
        <p class="muted">Sin resultados de Shodan.</p>
      {% endif %}
    </section>

    {# Opcional: más campos si existen en tu JSON #}
    {% if data.interesting_urls is defined and data.interesting_urls|length > 0 %}
      <section>
        <h3>URLs de interés ({{ data.interesting_urls|length }})</h3>
        <ul class="mono">
          {% for u in data.interesting_urls[:20] %}
            <li>{{ u }}</li>
          {% endfor %}
        </ul>
        {% if data.interesting_urls|length > 20 %}
          <details><summary>Ver todas</summary>
            <ul class="mono">
              {% for u in data.interesting_urls[20:] %}<li>{{ u }}</li>{% endfor %}
            </ul>
          </details>
        {% endif %}
      </section>
    {% endif %}

    {% if data.ips is defined and data.ips|length > 0 %}
      <section>
        <h3>IPs ({{ data.ips|length }})</h3>
        <ul class="mono">
          {% for ip in data.ips[:50] %}<li>{{ ip }}</li>{% endfor %}
        </ul>
      </section>
    {% endif %}
  </div>
{% endif %}

{% if include_routes %}
<script>
  window.APP_ROUTES = {
    EVENTS_URL: "{{ url_for('main.events') }}",
    API_REPORTS_URL: "{{ url_for('main.api_reports') }}",
    API_HARVESTER_URL: "{{ url_for('main.harvester_scan') }}",
    JOB_DETAIL_URL_TMPL: "{{ url_for('main.job_detail', job_id='__ID__') }}",
    REPORT_URL_TMPL: "{{ url_for('main.get_report', name='__NAME__') }}"
  };
</script>
<script src="{{ url_for('static', filename='js/harvester.js') }}"></script>
{% endif %}

</body>
</html>"""


def _render_findings(findings):
    if not findings: return "<p class='muted'>Sin hallazgos.</p>"
    buf=[]
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        buf.append(
            f"<p><strong class='sev-{sev}'>{sev.upper()}</strong> – {f.get('title','')}</p>"
            f"<pre>{json.dumps(f.get('evidence',{}), indent=2, ensure_ascii=False)}</pre>"
        )
    return "\n".join(buf)

def _render_nmap(nmap):
    if not nmap or not nmap.get("assets"): return "<p class='muted'>Sin resultados de Nmap.</p>"
    rows=["<table><thead><tr><th>IP</th><th>Hostname</th><th>Puerto</th><th>Servicio</th><th>Versión</th></tr></thead><tbody>"]
    for h in nmap["assets"]:
        for p in h.get("ports", []):
            rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}/{} {}</td><td>{}</td><td>{}</td></tr>".format(
                    h.get("ip",""), h.get("hostname",""),
                    p.get("port",""), p.get("proto","tcp"), p.get("state",""),
                    p.get("service",""), ("{} {}".format(p.get("product","") or "", p.get("version","") or "")).strip()
                )
            )
    rows.append("</tbody></table>")
    return "\n".join(rows)

def export_to_jsonl(job) -> str:
    """
    Exporta resultados en formato JSONL para facilitar ingestión en SIEM u otras herramientas.
    Genera una línea por recurso (host, email, shodan, etc.).
    """
    out_dir = Path(getattr(job, "report_dir", "reports/output"))
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"results_{job.id}.jsonl"
    path = out_dir / name

    with path.open("w", encoding="utf-8") as f:
        results = job.results or {}

        # Hosts de Nmap
        for h in results.get("nmap", {}).get("assets", []):
            f.write(json.dumps({"type": "nmap_host", **h}, ensure_ascii=False) + "\n")

        # Hosts de theharvester
        for h in results.get("theharvester", {}).get("hosts", []):
            f.write(json.dumps({"type": "harvester_host", "host": h}, ensure_ascii=False) + "\n")

        # Emails de theharvester
        for e in results.get("theharvester", {}).get("emails", []):
            f.write(json.dumps({"type": "harvester_email", "email": e}, ensure_ascii=False) + "\n")

        # Shodan (si devuelve lista)
        for s in results.get("theharvester", {}).get("shodan", []):
            f.write(json.dumps({"type": "harvester_shodan", "entry": s}, ensure_ascii=False) + "\n")

        # Otros módulos locales
        local = results.get("local_enum") or {}
        if local:
            f.write(json.dumps({"type": "local_enum", **local}, ensure_ascii=False) + "\n")

    return name

def export_to_html(job) -> str:
    """
    Genera report_<job>.html usando la plantilla Jinja que espera:
    - job.id, job.status, job.created_at, job.target, job.tools
    - job.results.nmap.assets[*].ports[*]
    - job.results.local_enum
    - job.results.theharvester (cmd, hosts[], emails[], shodan[])
    - job.errors (opcional)
    """
    # (Opcional) corre correlación si la usas en otra parte
    try:
        from app.modules.correlation.rules import run_rules
        corr = run_rules(job.results or {})
        job.results["findings"] = corr.get("findings", [])
    except Exception:
        # Silencioso: la plantilla actual no muestra findings
        pass

    # Prepara entorno Jinja (tojson sencillo)
    env = Environment(loader=BaseLoader(), autoescape=False, trim_blocks=True, lstrip_blocks=True)
    env.filters["tojson"] = lambda v, indent=None: json.dumps(v, ensure_ascii=False, indent=indent)

    template = env.from_string(JINJA_TEMPLATE)
    html = template.render(job=job, generated=datetime.utcnow().isoformat() + "Z")

    out_dir = Path(getattr(job, "report_dir", "reports/output"))
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"report_{job.id}.html"
    (out_dir / name).write_text(html, encoding="utf-8")
    return name
