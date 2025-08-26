import os, subprocess, json, shlex
from pathlib import Path
from shutil import which

def run(target, emit, meta=None):
    meta = meta or {}

    # 1) Rutas
    HARVESTER_PROJ = Path(os.getenv("FILEPATH_THE_HARVESTER", "")).resolve()
    if not (HARVESTER_PROJ / "pyproject.toml").exists():
        raise RuntimeError(f"FILEPATH_THE_HARVESTER inválido: {HARVESTER_PROJ}")

    report_dir = Path(meta.get("report_dir") or os.getenv("OUTPUT_PATH_THE_HARVESTER", "reports")).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    job_id = meta.get("job_id", "")
    base = os.path.join(report_dir, f"theharvester_{job_id[:8]}")

    out_json = base + ".json"

    # 2) Comando uv usando el proyecto de theHarvester
    if not which("uv"):
        raise RuntimeError("No se encuentra 'uv' en PATH del proceso Flask")

    opts = meta.get("harvester_opts", {}) or {}
    cmd = ["uv", "run", "theHarvester", "-d", target, "-f", base]
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
    if opts.get("wordlist"):    cmd += ["-w", opts["wordlist"]]
    if opts.get("api_scan"):    cmd += ["-a"]
    if opts.get("quiet"):       cmd += ["-q"]
    for src in opts.get("sources", []):
        cmd += ["-b", src]

    emit({"cmd": " ".join(shlex.quote(c) for c in cmd)})

    # 3) Entorno: sin contaminar con el venv de Flask
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)   # para que uv no avise y use su .venv del proyecto

    proc = subprocess.run(
        cmd,
        cwd=str(HARVESTER_PROJ),   # <- clave: uv apunta al proyecto de theHarvester
        env=env,
        capture_output=True,
        text=True,
    )

    if proc.stdout:
        emit({"stdout": proc.stdout[:4000] + ("…" if len(proc.stdout) > 4000 else "")})
    if proc.stderr:
        emit({"stderr": proc.stderr[:4000] + ("…" if len(proc.stderr) > 4000 else "")})

    if proc.returncode != 0:
        raise RuntimeError(f"theHarvester returned {proc.returncode}")

    data = {}
    if os.path.isfile(out_json):
        with open(out_json, encoding="utf-8") as f:
            data = json.load(f)
    else:
        emit({"warn": f"No se encontró JSON en {out_json}. ¿flags/permiso/ruta?"})

    return {"results": data, "meta": meta}
