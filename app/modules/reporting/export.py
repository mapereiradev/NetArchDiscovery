# app/modules/reporting/export.py
from __future__ import annotations
import os, json
from pathlib import Path
from datetime import datetime

TEMPLATE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Informe {{JOB}}</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial;background:#0b1020;color:#e5e7eb;margin:20px}
 code,pre{background:#0f172a;padding:.5rem;border-radius:8px;overflow-x:auto}
 table{border-collapse:collapse;width:100%} th,td{border:1px solid #334155;padding:.4rem;text-align:left}
 .card{border:1px solid #334155;border-radius:10px;padding:1rem;margin:1rem 0}
 .muted{color:#94a3b8}
 .sev-high{color:#ef4444}.sev-medium{color:#f59e0b}.sev-low{color:#22c55e}.sev-info{color:#60a5fa}
</style></head><body>
<h1>Informe de escaneo – {{JOB}}</h1>
<p class="muted">Generado: {{TS}}</p>
<div class="card"><h2>Resumen</h2><p><strong>Target:</strong> {{TARGET}}<br><strong>Herramientas:</strong> {{TOOLS}}</p></div>
<div class="card"><h2>Hallazgos</h2>{{FINDINGS}}</div>
<div class="card"><h2>Hosts y puertos (Nmap)</h2>{{NMAP}}</div>
<div class="card"><h2>Enumeración local (resumen)</h2><pre>{{LOCAL}}</pre></div>
<div class="card"><h2>Resultados completos (JSON)</h2><pre>{{JSON}}</pre></div>
</body></html>
"""

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
    """Guarda un JSONL con los hosts de Nmap (dict-safe)."""
    out_dir = Path("reports/output"); out_dir.mkdir(parents=True, exist_ok=True)
    name = f"nmap_{job.id}.jsonl"
    path = out_dir / name
    nmap = (job.results or {}).get("nmap", {})
    with path.open("w", encoding="utf-8") as f:
        for h in nmap.get("assets", []):
            f.write(json.dumps(h, ensure_ascii=False) + "\n")
    return name

def export_to_html(job) -> str:
    """Genera report_<job>.html y devuelve el nombre del archivo."""
    from app.modules.correlation.rules import run_rules
    corr = run_rules(job.results or {})
    job.results["findings"] = corr.get("findings", [])

    html = TEMPLATE
    html = html.replace("{{JOB}}", job.id[:8])
    html = html.replace("{{TS}}", datetime.utcnow().isoformat()+"Z")
    html = html.replace("{{TARGET}}", job.target or "(local)")
    html = html.replace("{{TOOLS}}", ", ".join(job.tools or []))
    html = html.replace("{{FINDINGS}}", _render_findings(job.results.get("findings")))
    html = html.replace("{{NMAP}}", _render_nmap(job.results.get("nmap")))

    local = job.results.get("local_enum") or {}
    local_summary = {
        "interfaces": (local.get("network") or {}).get("interfaces", []),
        "listening": (local.get("network") or {}).get("listening", [])[:10],
        "ssh_config_audit": local.get("ssh_config_audit"),
        "suid_count": len((local.get("files") or {}).get("suid_bins") or []),
    }
    html = html.replace("{{LOCAL}}", json.dumps(local_summary, indent=2, ensure_ascii=False))
    html = html.replace("{{JSON}}", json.dumps(job.results, indent=2, ensure_ascii=False))

    out_dir = Path(getattr(job, "report_dir", "reports/output"))
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"report_{job.id}.html"
    (out_dir / name).write_text(html, encoding="utf-8")
    return name
