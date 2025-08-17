from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, Response
import json
from app.job_manager import EVENT_BUS   # para SSE
import queue
from flask import send_from_directory
from pathlib import Path
import os

REPORT_DIR = Path("reports/output")

main = Blueprint("main", __name__)

@main.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@main.route("/scanning", methods=["GET"])
def scanning():
    jm = current_app.jobmanager
    jobs = jm.list_jobs()
    # tu plantilla original "scanning.html" (MISMO diseño)
    return render_template("scanning.html", jobs=jobs)

@main.route("/api/scan", methods=["POST"])
def api_scan():
    jm = current_app.jobmanager
    target = (request.form.get("target") or "").strip()
    tools = request.form.getlist("tools") or []

    if not tools:
        return {"error": "Debes seleccionar al menos una herramienta."}, 400
    if "nmap" in tools and not target:
        return {"error": "Debes indicar un target para Nmap."}, 400

    # Construir opciones de Nmap (si está marcado)
    nmap_opts = build_nmap_options(request.form) if "nmap" in tools else []

    job_id = jm.enqueue(
        target=target,
        tools=tools,
        meta={"ui": "original", "nmap_opts": nmap_opts}
    )
    # Respuesta para pintar fila de inmediato
    return {"job_id": job_id, "target": target, "tools": tools, "nmap_opts": nmap_opts}

@main.route("/jobs/<job_id>")
def job_detail(job_id):
    jm = current_app.jobmanager
    job = jm.get(job_id)
    if not job:
        flash("Job no encontrado", "error")
        return redirect(url_for("main.index"))
    # crea una plantilla job.html con tu estilo (abajo te doy solo el JS)
    return render_template("job.html", job=job)

@main.route("/events")
def events():
    job_filter = request.args.get("job_id")

    # 🔧 CAPTURA referencias ANTES de crear el Response/generador:
    app_obj = current_app._get_current_object()
    jm = app_obj.jobmanager

    def stream():
        q = EVENT_BUS.subscribe()
        try:
            # Replay inicial (opcional)
            if job_filter:
                job = jm.get(job_filter)
                if job:
                    for e in job.events[-50:]:
                        yield f"event: {e.kind}\ndata: {json.dumps(e.payload, ensure_ascii=False)}\n\n"

            # Bucle principal
            while True:
                try:
                    # Espera con timeout para poder emitir keep-alive
                    e = q.get(timeout=15)
                    if job_filter and e.meta.get("job_id") != job_filter:
                        continue
                    yield f"event: {e.kind}\ndata: {json.dumps(e.payload, ensure_ascii=False)}\n\n"
                except queue.Empty:
                    # 🔸 Mantén viva la conexión (útil con proxies)
                    yield ": keep-alive\n\n"
        finally:
            EVENT_BUS.unsubscribe(q)

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        # Opcional en dev: desactiva buffering en algunos proxies/NGINX
        # "X-Accel-Buffering": "no",
    }
    return Response(stream(), headers=headers)

# @main.route("/reports/<name>")
# def get_report(name):
#     # informes en reports/output
#     base = Path("reports/output").resolve()
#     f = (base / name).resolve()
#     if not str(f).startswith(str(base)) or not f.exists():
#         flash("Reporte no encontrado", "error")
#         return redirect(url_for("main.index"))
#     return send_from_directory(str(base), f.name)

@main.route("/api/jobs/<job_id>")
def api_job(job_id):
    jm = current_app.jobmanager
    job = jm.get(job_id)
    if not job:
        return {"error": "not found"}, 404
    return job.to_dict()

def build_nmap_options(form) -> list[str]:
    """Lee el formulario y construye la lista de flags para Nmap."""
    opts: list[str] = []

    # Tipos de escaneo
    if form.get("opt_sS"): opts.append("-sS")       # SYN
    if form.get("opt_sT"): opts.append("-sT")       # TCP connect
    if form.get("opt_sU"): opts.append("-sU")       # UDP

    # Detección / fingerprint
    if form.get("opt_sV"): opts.append("-sV")       # versiones
    if form.get("opt_O"):  opts.append("-O")        # OS
    if form.get("opt_A"):  opts.append("-A")        # -O -sV -sC --traceroute
    if form.get("opt_sC"): opts.append("-sC")       # scripts por defecto
    if form.get("opt_script_vuln"): opts.append("--script=vuln")  # scripts de vulns

    # Puertos
    ports = (form.get("opt_ports") or "").strip()
    if ports:
        opts += ["-p", ports]
    if form.get("opt_F"):
        opts.append("-F")                            # 100 puertos más comunes

    # Timing
    t = (form.get("opt_T") or "").strip()
    if t != "":
        try:
            tval = int(t)
            if 0 <= tval <= 5:
                opts.append(f"-T{tval}")
        except ValueError:
            pass  # ignoramos valores inválidos

    # DNS
    if form.get("opt_n"):
        opts.append("-n")                            # no resolver DNS

    return opts


@main.route("/reports/<path:name>")
def get_report(name):
    REPORT_DIR = Path("reports/output")
    safe = os.path.normpath(name).replace("\\", "/")
    if safe.startswith("../"):
        return {"error": "invalid path"}, 400
    return send_from_directory(REPORT_DIR, safe, as_attachment=False)

@main.route("/api/reports")
def api_reports():
    REPORT_DIR = Path("reports/output")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted([f.name for f in REPORT_DIR.glob("*") if f.is_file()])
    return {"files": files}