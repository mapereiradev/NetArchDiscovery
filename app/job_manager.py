import queue, threading, uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# tus plugins: usa los que ya tenemos (nmap + enum local) o los que vayas añadiendo
from .plugins import get_available_tools
from app.reports.report_builder import build_html
from app.modules.reporting.export import export_results


# ——— bus de eventos para SSE ———
class Event:
    def __init__(self, kind, payload, meta=None):
        self.kind = kind
        self.payload = payload
        self.meta = meta or {}

class EventBus:
    def __init__(self):
        self.subs = set()
        self.lock = threading.Lock()
    def subscribe(self):
        q = queue.Queue()
        with self.lock: self.subs.add(q)
        return q
    def unsubscribe(self, q):
        with self.lock: self.subs.discard(q)
    def publish(self, event: Event):
        with self.lock: subs = list(self.subs)
        for q in subs:
            try: q.put(event, block=False)
            except queue.Full: pass

EVENT_BUS = EventBus()

# ——— modelo de job ———
@dataclass
class Job:
    id: str
    target: str
    tools: list[str]
    status: str = "queued"
    progress: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat()+"Z")
    results: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)
    events: list = field(default_factory=list)  # replay en SSE
    report_file: str | None = None
    meta: dict = field(default_factory=dict)
    def to_dict(self):
        d = asdict(self); d["events"] = d["events"][-100:]; return d

class JobManager:
    def __init__(self, max_workers=4, report_dir="reports/output"):
        self.max_workers = max_workers
        self.report_dir = report_dir
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def list_jobs(self):
        with self.lock: return list(self.jobs.values())

    def get(self, job_id):
        with self.lock: return self.jobs.get(job_id)

    def enqueue(self, *, target: str, tools: list[str], meta=None) -> str:
        job_id = uuid.uuid4().hex
        job = Job(id=job_id, target=target, tools=tools, meta=meta or {})
        with self.lock: self.jobs[job_id] = job
        threading.Thread(target=self._run_job, args=(job,), daemon=True).start()
        return job_id

    def _emit(self, job: Job, kind: str, payload: dict):
        e = Event(kind, payload, meta={"job_id": job.id})
        job.events.append(e)
        EVENT_BUS.publish(e)

    def _run_tool(self, name: str, job: Job):
        runner = get_available_tools()[name]
        self._emit(job, "log", {"tool": name, "msg": "inicio"})
        out = runner(job.target, emit=lambda m: self._emit(job, "log", {"tool": name, "msg": m}))
        self._emit(job, "log", {"tool": name, "msg": "fin"})
        return name, out

def _run_job(self, job: Job):
    job.status = "running"
    self._emit(job, "status", {"status": job.status})
    results, errors = {}, {}
    total = max(1, len(job.tools))

    with ThreadPoolExecutor(max_workers=min(total, self.max_workers)) as pool:
        futures = [pool.submit(self._run_tool, t, job) for t in job.tools]
        done = 0
        for f in as_completed(futures):
            try:
                k, v = f.result()
                results[k] = v
            except Exception as ex:
                errors[k if 'k' in locals() else "unknown"] = str(ex)
                self._emit(job, "log", {
                    "tool": k if 'k' in locals() else "unknown",
                    "msg": f"ERROR: {ex}"
                })
            done += 1
            job.progress = int(done * 100 / total)
            self._emit(job, "progress", {"progress": job.progress})

    # Guardar resultados y errores en el job
    job.results, job.errors = results, errors

    # 🔹 Exportar resultados a JSONL (assets + findings)
    try:
        export_results(job, results)
        self._emit(job, "log", {"tool": "export", "msg": "Resultados exportados a JSONL"})
    except Exception as ex:
        self._emit(job, "log", {"tool": "export", "msg": f"Error exportando a JSONL: {ex}"})

    # 🔹 Generar informe HTML
    try:
        filename = build_html(job)
        job.report_file = filename
        self._emit(job, "status", {"status": "done", "report": filename, "job_id": job.id})
    except Exception as ex:
        self._emit(job, "log", {"tool": "report", "msg": f"Error generando informe: {ex}", "job_id": job.id})
        job.status = "done"
        self._emit(job, "status", {"status": "done", "job_id": job.id})