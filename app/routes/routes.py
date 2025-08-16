from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, Response
import json
from app.job_manager import EVENT_BUS   # para SSE
import queue
from flask import send_from_directory
from pathlib import Path

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

@main.route("/scan", methods=["POST"])
def scan():
    jm = current_app.jobmanager

    # Datos del formulario
    target = (request.form.get("target") or "").strip()
    tools = request.form.getlist("tools") or []

    # Validaciones mínimas
    if not tools:
        flash("Selecciona al menos una herramienta.", "error")
        return redirect(url_for("main.index"))

    if "nmap" in tools and not target:
        flash("Debes indicar un target para ejecutar Nmap.", "error")
        return redirect(url_for("main.index"))

    # Lanzar job concurrente
    try:
        job_id = jm.enqueue(target=target, tools=tools, meta={"ui": "original"})
        flash(f"Job {job_id[:8]} lanzado.", "success")
        return redirect(url_for("main.job_detail", job_id=job_id))
    except Exception as ex:
        current_app.logger.exception("Error al encolar job")
        flash(f"Error al lanzar el job: {ex}", "error")
        return redirect(url_for("main.index"))

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

@main.route("/reports/<name>")
def get_report(name):
    # informes en reports/output
    base = Path("reports/output").resolve()
    f = (base / name).resolve()
    if not str(f).startswith(str(base)) or not f.exists():
        flash("Reporte no encontrado", "error")
        return redirect(url_for("main.index"))
    return send_from_directory(str(base), f.name)