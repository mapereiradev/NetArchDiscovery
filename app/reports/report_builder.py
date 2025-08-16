from __future__ import annotations
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
OUTPUT_DIR = Path("reports/output")

env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape()
)

def ensure_dirs():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def build_html(job) -> str:
    """
    Renderiza el informe HTML del job y lo guarda en reports/output/.
    Devuelve el nombre del archivo (p.ej. report_abcd1234.html).
    """
    ensure_dirs()
    tpl = env.get_template("report.html")
    html = tpl.render(job=job, generated=datetime.utcnow().isoformat()+"Z")
    name = f"report_{job.id}.html"
    (OUTPUT_DIR / name).write_text(html, encoding="utf-8")
    return name