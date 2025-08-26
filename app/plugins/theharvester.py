# import os, subprocess, json, shlex
# from pathlib import Path
# from shutil import which

# HARVESTER_PROJ = Path(os.getenv("FILEPATH_THE_HARVESTER", "")).resolve()

# def run(target, emit, meta=None):
#     meta = meta or {}
#     report_dir = Path(meta.get("report_dir") or os.getenv("OUTPUT_PATH_THE_HARVESTER", "reports")).resolve()
#     report_dir.mkdir(parents=True, exist_ok=True)

#     job_id = meta.get("job_id", "")
#     base = os.path.join(report_dir, f"theharvester_{job_id[:8]}")

#     out_json = base + ".json"

#     # 2) Comando uv usando el proyecto de theHarvester
#     if not which("uv"):
#         raise RuntimeError("No se encuentra 'uv' en PATH del proceso Flask")

#     opts = meta.get("harvester_opts", {}) or {}
#     cmd = ["uv", "run", "theHarvester", "-d", target, "-f", base]
#     if opts.get("limit"):       cmd += ["-l", str(opts["limit"])]
#     if opts.get("start"):       cmd += ["-S", str(opts["start"])]
#     if opts.get("proxies"):     cmd += ["-p"]
#     if opts.get("shodan"):      cmd += ["-s"]
#     if opts.get("screenshot"):  cmd += ["--screenshot", opts["screenshot"]]
#     if opts.get("dns_server"):  cmd += ["-e", opts["dns_server"]]
#     if opts.get("take_over"):   cmd += ["-t"]
#     if opts.get("dns_resolve"):
#         cmd += ["-r"]
#         if opts["dns_resolve"] not in (True, False):
#             cmd.append(opts["dns_resolve"])
#     if opts.get("dns_lookup"):  cmd += ["-n"]
#     if opts.get("dns_brute"):   cmd += ["-c"]
#     if opts.get("wordlist"):    cmd += ["-w", opts["wordlist"]]
#     if opts.get("api_scan"):    cmd += ["-a"]
#     if opts.get("quiet"):       cmd += ["-q"]
#     for src in opts.get("sources", []):
#         cmd += ["-b", src]

#     emit({"cmd": " ".join(shlex.quote(c) for c in cmd)})

#     # 3) Entorno: sin contaminar con el venv de Flask
#     env = os.environ.copy()
#     env.pop("VIRTUAL_ENV", None)   # para que uv no avise y use su .venv del proyecto

#     proc = subprocess.run(
#         cmd,
#         cwd=str(HARVESTER_PROJ),   # <- clave: uv apunta al proyecto de theHarvester
#         env=env,
#         capture_output=True,
#         text=True,
#     )

#     if proc.stdout:
#         emit({"stdout": proc.stdout[:4000] + ("…" if len(proc.stdout) > 4000 else "")})
#     if proc.stderr:
#         emit({"stderr": proc.stderr[:4000] + ("…" if len(proc.stderr) > 4000 else "")})

#     if proc.returncode != 0:
#         raise RuntimeError(f"theHarvester returned {proc.returncode}")

#     data = {}
#     if os.path.isfile(out_json):
#         with open(out_json, encoding="utf-8") as f:
#             data = json.load(f)
#     else:
#         emit({"warn": f"No se encontró JSON en {out_json}. ¿flags/permiso/ruta?"})

#     return {"results": data, "meta": meta}


# app/plugins/theHarvester.py
from __future__ import annotations
import os
import json
import shlex
import time
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

# === CONFIG ===
# Ruta al proyecto local de theHarvester (donde está el pyproject.toml)
HARVESTER_PROJ = Path(os.getenv("FILEPATH_THE_HARVESTER", "")).resolve()
# Tiempo de espera para que se materialice el JSON si el FS se retrasa (normalmente no hace falta)
JSON_TIMEOUT_SECS = 10.0
JSON_POLL_SECS = 0.2


def _wait_for_json(path: Path, timeout: float = JSON_TIMEOUT_SECS, poll: float = JSON_POLL_SECS) -> Dict[str, Any]:
    """
    Espera a que 'path' exista y contenga JSON válido.
    Normalmente subprocess.run ya garantiza que el fichero está, pero en FS lentos puede tardar milisegundos.
    """
    deadline = time.time() + timeout
    last_exc: Optional[Exception] = None
    while time.time() < deadline:
        try:
            if path.is_file() and path.stat().st_size > 2:
                with path.open(encoding="utf-8") as f:
                    return json.load(f)
        except Exception as ex:  # JSONDecodeError u otros
            last_exc = ex
        time.sleep(poll)
    if last_exc:
        raise RuntimeError(f"JSON inválido en {path}: {last_exc}")
    raise FileNotFoundError(f"No se generó JSON en {path} (timeout {timeout}s)")


def _build_cmd(target: str, out_base: Path, opts: Dict[str, Any]) -> List[str]:
    """
    Construye la línea de comandos de theHarvester.
    - Siempre usa `-f <base>` (sin extensión) para que se generen base.html/xml/json
    - Soporta subconjunto de flags comunes; extiéndelo si necesitas más.
    """
    cmd: List[str] = ["uv", "run", "theHarvester", "-d", target, "-f", str(out_base)]

    # Fuentes (lista de strings) o "all"
    sources = opts.get("sources")
    if sources and isinstance(sources, (list, tuple)) and len(sources) > 0:
        for src in sources:
            cmd += ["-b", str(src)]
    else:
        # por defecto puedes poner "all" o una selección razonable
        # cmd += ["-b", "all"]
        # Mejor: deja que el usuario pase sources; si no, usa algunas conocidas:
        for src in ["brave", "censys", "duckduckgo", "otx", "urlscan"]:
            cmd += ["-b", src]

    # Límites / paginación
    if opts.get("limit"):   cmd += ["-l", str(opts["limit"])]
    if opts.get("start"):   cmd += ["-S", str(opts["start"])]

    # DNS / red
    if opts.get("dns_lookup"):   cmd += ["-n"]          # resolver A/AAAA
    if opts.get("dns_brute"):    cmd += ["-c"]          # brute-force subdominios
    if opts.get("dns_server"):   cmd += ["-e", str(opts["dns_server"])]
    if opts.get("take_over"):    cmd += ["-t"]

    # Otros flags comunes
    if opts.get("proxies"):      cmd += ["-p"]
    if opts.get("shodan"):       cmd += ["-s"]
    if opts.get("api_scan"):     cmd += ["-a"]
    if opts.get("quiet"):        cmd += ["-q"]
    if opts.get("screenshot"):   cmd += ["--screenshot", str(opts["screenshot"])]
    if opts.get("wordlist"):     cmd += ["-w", str(opts["wordlist"])]

    return cmd


def run(target: str, emit, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Runner para theHarvester.
    - target: dominio objetivo (ej. "ucam.edu")
    - emit: callable(dict) -> None para logs en vivo (EventBus)
    - meta: {
        "job_id": "...",
        "report_dir": "reports/output",
        "harvester_opts": { ... }   # ver _build_cmd
      }

    Devuelve:
    {
      "results": <dict JSON de theHarvester>,
      "meta": {"cmd": "<cmd string>", "html": "<ruta html>", "json": "<ruta json>"}
    }
    """
    meta = meta or {}
    opts = meta.get("harvester_opts", {}) or {}

    # Directorio de salida (respetando lo que el JobManager configuró)
    out_dir = Path(meta.get("report_dir", "reports/output")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Base de nombre usando el job_id si está
    base = f"theharvester_{(meta.get('job_id') or '')[:8] or 'run'}"
    out_base = out_dir / base
    out_html = out_base.with_suffix(".html")
    out_xml  = out_base.with_suffix(".xml")
    out_json = out_base.with_suffix(".json")

    # Construye comando
    cmd = _build_cmd(target, out_base, opts)
    emit({"cmd": " ".join(shlex.quote(c) for c in cmd)})

    # Limpia restos previos para evitar confusiones
    for p in (out_html, out_xml, out_json):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

    # Prepara entorno: que uv use el pyproject del repo local
    env = os.environ.copy()
    # Evitar interferir con el venv de Flask si lo hay
    env.pop("VIRTUAL_ENV", None)

    # Ejecuta theHarvester desde su repo (uv resolverá deps allí)
    proc = subprocess.run(
        cmd,
        cwd=str(HARVESTER_PROJ),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    # Logs compactos
    if proc.stdout:
        s = proc.stdout
        emit({"stdout": s[:8000] + ("…" if len(s) > 8000 else "")})
    if proc.stderr:
        s = proc.stderr
        emit({"stderr": s[:4000] + ("…" if len(s) > 4000 else "")})

    if proc.returncode != 0:
        raise RuntimeError(f"theHarvester returned {proc.returncode}")

    # Carga el JSON que theHarvester genera automáticamente con -f <base>
    data: Dict[str, Any] = {}
    try:
        data = _wait_for_json(out_json, timeout=JSON_TIMEOUT_SECS, poll=JSON_POLL_SECS)
    except Exception as ex:
        # Fallback: algunos forks generan JSON como <base>.json después de un pelín de tiempo
        emit({"warn": f"No se pudo leer {out_json}: {ex}"})

    # Estructura de retorno que espera tu UI/JobManager
    return {
        "results": data,
        "meta": {
            "cmd": " ".join(shlex.quote(c) for c in cmd[2:]) if cmd[:2] == ["uv", "run"] else " ".join(cmd),
            "html": str(out_html),
            "json": str(out_json),
        },
    }

