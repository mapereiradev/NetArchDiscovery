from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, Response, jsonify
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
    wants_json = (
        "application/json" in (request.headers.get("Accept") or "")
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    target = (request.form.get("target") or "").strip()
    tools  = request.form.getlist("tools")  # ["nmap", "local_enum", "dns_reverse", ...]

    # crea + encola el job
    jm  = current_app.jobmanager
    job = jm.create_job(target=target, tools=tools)     # -> objeto Job con id
    jm.start_job(job)                                   # -> lanza hilos/queue

    if wants_json:
        # respuesta inmediata para el fetch del front
        return jsonify({"job_id": job.id, "tools": tools}), 200

    # fallback navegador (si alguien envía sin AJAX)
    return redirect(url_for("main.job_detail", job_id=job.id))

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

    # Captura referencias antes de crear el Response/generador
    app_obj = current_app._get_current_object()
    jm = app_obj.jobmanager

    def _serialize(ev):
        """Devuelve (kind, data_json, last_id) listo para enviar por SSE."""
        kind = getattr(ev, "kind", "message")
        meta = getattr(ev, "meta", {}) or {}
        payload = (getattr(ev, "payload", {}) or {}).copy()
        job_id = meta.get("job_id")
        # garantiza job_id en payload
        if job_id and "job_id" not in payload:
            payload["job_id"] = job_id
        data = json.dumps(payload, ensure_ascii=False)
        last_id = job_id or ""  # útil para e.lastEventId en el cliente
        return kind, data, last_id

    def stream():
        q = EVENT_BUS.subscribe()
        try:
            # Sugerencia: que el cliente reintente en 3s si se corta
            yield "retry: 3000\n"
            # Ping inicial para abrir el flujo en algunos proxies
            yield ": ping\n\n"

            # Replay de últimos eventos del job (si se pide)
            if job_filter:
                job = jm.get(job_filter)
                if job:
                    for ev in job.events[-50:]:
                        kind, data, last_id = _serialize(ev)
                        yield (f"id: {last_id}\n" if last_id else "")
                        yield f"event: {kind}\n"
                        yield f"data: {data}\n\n"

            # Bucle principal
            while True:
                try:
                    ev = q.get(timeout=15)
                except queue.Empty:
                    # Mantén viva la conexión
                    yield ": keep-alive\n\n"
                    continue

                # Filtrado por job si procede
                if job_filter:
                    if not getattr(ev, "meta", None):
                        continue
                    if ev.meta.get("job_id") != job_filter:
                        continue

                kind, data, last_id = _serialize(ev)
                if last_id:
                    yield f"id: {last_id}\n"
                yield f"event: {kind}\n"
                yield f"data: {data}\n\n"

        except GeneratorExit:
            # cliente cerró la conexión
            pass
        finally:
            EVENT_BUS.unsubscribe(q)

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",   # útil detrás de NGINX
    }
    return Response(stream(), mimetype="text/event-stream", headers=headers)

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
    """
    Sirve un informe HTML generado por un job.
    Usamos el report_dir configurado en JobManager en lugar de asumir siempre
    'reports/output'.
    """
    jm = current_app.jobmanager
    # Si JobManager tiene configurado report_dir, lo usamos; si no, se usa 'reports/output'
    report_dir = Path(jm.report_dir) if getattr(jm, "report_dir", None) else Path("reports/output")

    safe = os.path.normpath(name).replace("\\", "/")
    # Evita rutas que escapen del directorio de informes
    if safe.startswith("../"):
        return {"error": "invalid path"}, 400

    return send_from_directory(report_dir, safe, as_attachment=False)

@main.route("/api/reports")
def api_reports():
    """
    Devuelve la lista de informes disponibles.
    Utiliza el mismo report_dir que JobManager para listar los archivos.
    """
    jm = current_app.jobmanager
    report_dir = Path(jm.report_dir) if getattr(jm, "report_dir", None) else Path("reports/output")
    report_dir.mkdir(parents=True, exist_ok=True)
    files = sorted([f.name for f in report_dir.glob("*") if f.is_file()])
    return {"files": files}
