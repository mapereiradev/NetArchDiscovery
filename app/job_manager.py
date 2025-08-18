from __future__ import annotations

import uuid
import queue
import threading
import inspect
from dataclasses import dataclass, field, asdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

# Registro de plugins (nmap, local_enum, dns_reverse, etc.)
from app.plugins import get_available_tools

# Exportadores (JSONL + HTML)
from app.modules.reporting.export import export_to_jsonl, export_to_html


# =========================
#   Eventos y EventBus
# =========================

class Event:
    """Evento simple para publicar en el bus y reemitir por SSE."""
    def __init__(self, kind: str, payload: dict, meta: Optional[dict] = None):
        self.kind = kind
        self.payload = payload
        self.meta = meta or {}


class EventBus:
    """Bus en memoria; cada suscriptor recibe una Queue con eventos."""
    def __init__(self) -> None:
        self.subs: set[queue.Queue] = set()
        self.lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self.lock:
            self.subs.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            self.subs.discard(q)

    def publish(self, event: Event) -> None:
        with self.lock:
            subs = list(self.subs)
        for q in subs:
            try:
                q.put(event, block=False)
            except queue.Full:
                pass


EVENT_BUS = EventBus()


# =========================
#   Modelo de Job
# =========================

@dataclass
class Job:
    id: str
    target: str
    tools: List[str]
    status: str = "queued"
    progress: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    results: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    events: List[Event] = field(default_factory=list)  # replay para SSE
    report_file: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # No “inundar” con eventos: deja solo los últimos 100
        d["events"] = [{"kind": e.kind, "payload": e.payload, "meta": e.meta}
                       for e in self.events[-100:]]
        return d


# =========================
#   Gestor de Jobs
# =========================

class JobManager:
    def __init__(self, max_workers: int = 4, report_dir: str = "reports/output") -> None:
        self.max_workers = max_workers
        self.report_dir = report_dir
        self.jobs: Dict[str, Job] = {}
        self.lock = threading.Lock()

    # -------- API pública --------
    def list_jobs(self) -> List[Job]:
        with self.lock:
            return list(self.jobs.values())

    def get(self, job_id: str) -> Optional[Job]:
        with self.lock:
            return self.jobs.get(job_id)

    def enqueue(self, *, target: str, tools: List[str],
                meta: Optional[Dict[str, Any]] = None) -> str:
        """Crea el job, emite 'job_created' (para pintar fila instantánea) y lanza el hilo."""
        job_id = uuid.uuid4().hex
        job = Job(id=job_id, target=target, tools=tools, meta=meta or {})
        with self.lock:
            self.jobs[job_id] = job

        # Aviso inmediato para la UI (aparece en tabla al pulsar el botón)
        self._emit(job, "job_created", {
            "job_id": job.id,
            "status": job.status,
            "tools": job.tools,
            "progress": job.progress,
        })

        threading.Thread(target=self._run_job, args=(job,), daemon=True).start()
        return job_id

    # -------- Internals --------
    def _emit(self, job: Job, kind: str, payload: Dict[str, Any]) -> None:
        """Publica un evento y lo guarda para replay. Añade siempre job_id."""
        payload.setdefault("job_id", job.id)
        e = Event(kind, payload, meta={"job_id": job.id})
        job.events.append(e)
        EVENT_BUS.publish(e)

    def _run_tool(self, name: str, job: Job) -> Tuple[str, Any]:
        """Ejecuta un plugin/tool concreto y devuelve (nombre, salida)."""
        registry = get_available_tools()
        if name not in registry:
            raise RuntimeError(f"Tool no registrada: {name}")
        runner = registry[name]

        self._emit(job, "log", {"tool": name, "msg": "inicio"})

        # Construimos kwargs y filtramos según la firma real del runner
        candidate_kwargs = {
            "emit": lambda m: self._emit(job, "log", {"tool": name, "msg": m}),
            "meta": job.meta,
            "target": job.target,  # por si algún runner declara 'target' como kw
        }
        sig = inspect.signature(runner)
        kwargs = {k: v for k, v in candidate_kwargs.items() if k in sig.parameters}

        # Si 'target' no está en kwargs, pásalo posicional
        args = []
        if "target" not in kwargs:
            args.append(job.target)

        out = runner(*args, **kwargs)

        self._emit(job, "log", {"tool": name, "msg": "fin"})
        return name, out

    def _run_job(self, job: Job) -> None:
        job.status = "running"
        # Informa a la UI del arranque + herramientas del job
        self._emit(job, "status", {"status": job.status, "tools": job.tools, "progress": 0})

        results: Dict[str, Any] = {}
        errors: Dict[str, str] = {}

        total = max(1, len(job.tools))
        done = 0

        # Ejecuta todas las herramientas del job en paralelo
        with ThreadPoolExecutor(max_workers=min(total, self.max_workers)) as pool:
            futures = {pool.submit(self._run_tool, t, job): t for t in job.tools}

            for f in as_completed(futures):
                tool_name = futures.get(f, "unknown")
                try:
                    k, v = f.result()
                    results[k] = v
                except Exception as ex:
                    errors[tool_name] = str(ex)
                    self._emit(job, "log", {"tool": tool_name, "msg": f"ERROR: {ex}"})
                finally:
                    done += 1
                    job.progress = int(done * 100 / total)
                    self._emit(job, "progress", {"progress": job.progress})

        # Guardar resultados y errores
        job.results, job.errors = results, errors

        # Exportación a JSONL (no crítica)
        try:
            jsonl_name = export_to_jsonl(job)
            self._emit(job, "log", {"tool": "export", "msg": f"JSONL: {jsonl_name}"})
        except Exception as ex:
            self._emit(job, "log", {
                "tool": "export",
                "msg": f"Error exportando a JSONL: {ex}"
            })

        # Informe HTML (incluye correlación dentro de export_to_html)
        report_name: Optional[str] = None
        try:
            report_name = export_to_html(job)
            job.report_file = report_name
        except Exception as ex:
            self._emit(job, "log", {"tool": "report", "msg": f"Error generando informe: {ex}"})

        # Estado final (se emite UNA sola vez)
        job.status = "done"
        payload = {"status": job.status}
        if report_name:
            payload["report"] = report_name
        self._emit(job, "status", payload)
