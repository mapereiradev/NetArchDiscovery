import os, subprocess, json, shlex
from pathlib import Path
import os


def run(target, emit, meta=None):
    """
    Ejecuta theHarvester con las opciones indicadas y devuelve un resumen en JSON.
    meta debe contener 'harvester_opts' (diccionario con flags) y 'job_id', 'report_dir'.
    """
    PROYECTO = Path(os.getenv("FILEPATH_THE_HARVESTER", ""))
    SALIDA = Path(os.getenv("OUTPUT_PATH_THE_HARVESTER", ""))

    meta = meta or {}
    opts = meta.get("harvester_opts", {})
    job_id = meta.get("job_id", "")
    report_dir = meta.get("report_dir", ".")

    # Base de nombre para los informes
    base = f"theharvester_{job_id[:8]}"
    out_html = os.path.join(report_dir, f"{base}.html")
    out_json = os.path.join(report_dir, f"{base}.json")

    # Construir comando
    cmd = ["uv", "run", "theHarvester", "-d", target]
    if opts.get("limit"):       cmd += ["-l", str(opts["limit"])]
    if opts.get("start"):       cmd += ["-S", str(opts["start"])]
    if opts.get("proxies"):     cmd += ["-p"]
    if opts.get("shodan"):      cmd += ["-s"]
    if opts.get("screenshot"):  cmd += ["--screenshot", opts["screenshot"]]
    if opts.get("dns_server"):  cmd += ["-e", opts["dns_server"]]
    if opts.get("take_over"):   cmd += ["-t"]
    if opts.get("dns_resolve"):
        cmd += ["-r"]
        if opts["dns_resolve"] not in (True, False):
            cmd.append(opts["dns_resolve"])
    if opts.get("dns_lookup"):  cmd += ["-n"]
    if opts.get("dns_brute"):   cmd += ["-c"]
    if opts.get("filename"):    cmd += ["-f", opts["filename"]]
    if opts.get("wordlist"):    cmd += ["-w", opts["wordlist"]]
    if opts.get("api_scan"):    cmd += ["-a"]
    if opts.get("quiet"):       cmd += ["-q"]
    # Fuentes: lista de strings
    for src in opts.get("sources", []):
        cmd += ["-b", src]

    # Siempre generar HTML y JSON en report_dir si no se especifica filename
    if "filename" not in opts:
        cmd += ["-f", out_html, "-j", out_json]

    emit({"cmd": " ".join(shlex.quote(c) for c in cmd)})

    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=PROYECTO)
    if proc.returncode != 0:
        error = str(proc.stderr)
        emit({"error": proc.stderr.strip()})
        print(error)
        raise RuntimeError(f"theHarvester returned {proc.returncode}")

    # Cargar JSON si existe
    data = {}
    if os.path.exists(out_json):
        with open(out_json, encoding="utf-8") as f:
            data = json.load(f)
    emit({"info": f"Generados {out_html} y {out_json}"})
    return {"results": data, "html": os.path.basename(out_html), "json": os.path.basename(out_json)}