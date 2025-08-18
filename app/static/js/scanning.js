// static/js/scanning.js
(function () {
  "use strict";

  // === Rutas inyectadas por la plantilla (scanning.html) ===
  const R = window.APP_ROUTES || {};
  const EVENTS_URL       = R.EVENTS_URL;                 // url_for('main.events')
  const API_REPORTS_URL  = R.API_REPORTS_URL;            // url_for('main.api_reports')
  const API_SCAN_URL     = R.API_SCAN_URL;               // url_for('main.api_scan')
  const JOB_DETAIL_TMPL  = R.JOB_DETAIL_URL_TMPL;        // url_for('main.job_detail', job_id='__ID__')
  const REPORT_URL_TMPL  = R.REPORT_URL_TMPL;            // url_for('main.get_report', name='__NAME__')

  // === Helpers de UI ===
  function detalleUrl(jobId) {
    return (JOB_DETAIL_TMPL || "").replace("__ID__", encodeURIComponent(String(jobId)));
  }
  function reportUrl(name) {
    return (REPORT_URL_TMPL || "").replace("__NAME__", encodeURIComponent(String(name)));
  }
  function setProgress(jobId, pct) {
    const bar = document.getElementById("bar-" + jobId);
    const txt = document.getElementById("pct-" + jobId);
    if (bar) bar.style.width = (pct | 0) + "%";
    if (txt) txt.textContent = (pct | 0) + "%";
  }
  function setStatus(jobId, status) {
    const el = document.getElementById("status-" + jobId);
    if (el) el.textContent = status;
  }

  // Crea la tabla "Trabajos recientes" si aún no existe (primera vez)
  function ensureJobsTable() {
    let table = document.getElementById("jobs-table");
    if (table) return table.tBodies[0];

    const cards = document.querySelectorAll("section.card");
    const jobsCard = cards[1] || document.body;

    const emptyP = jobsCard.querySelector("p.muted");
    if (emptyP) emptyP.remove();

    const wrapper = document.createElement("div");
    wrapper.innerHTML = `
      <table id="jobs-table">
        <thead>
          <tr>
            <th>Job</th>
            <th>Estado</th>
            <th>Progreso</th>
            <th>Herramientas</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>`;
    jobsCard.appendChild(wrapper.firstElementChild);
    return document.querySelector("#jobs-table tbody");
  }

  // Inserta/asegura una fila de job
  function ensureRow(job) {
    const job_id = String(job.id);
    let row = document.getElementById("row-" + job_id);

    const tbody = ensureJobsTable();
    if (!tbody) return;

    if (row) {
      const tc = document.getElementById("tools-" + job_id);
      if (tc && job.tools && job.tools.length) tc.textContent = job.tools.join(", ");
      return;
    }

    const detallesLink = detalleUrl(job_id);
    row = document.createElement("tr");
    row.id = "row-" + job_id;
    row.innerHTML = `
      <td><code>${job_id.slice(0, 8)}</code></td>
      <td id="status-${job_id}">${job.status || "running"}</td>
      <td style="min-width:180px;">
        <div class="progress"><div id="bar-${job_id}" class="bar" style="width:${job.progress || 0}%"></div></div>
        <small id="pct-${job_id}" class="muted">${job.progress || 0}%</small>
      </td>
      <td id="tools-${job_id}">${(job.tools || []).join(", ")}</td>
      <td class="actions"><a class="btn" href="${detallesLink}">Detalle</a></td>`;
    tbody.prepend(row);
  }

  // Añade botón "Informe" a la fila del job
  function addReportLink(jobId, reportName) {
    const row = document.getElementById("row-" + jobId);
    if (!row) return;
    const cell = row.querySelector("td.actions") || row.lastElementChild;
    if (!cell) return;
    if (cell.querySelector(`[data-report="${CSS.escape(reportName)}"]`)) return;

    const a = document.createElement("a");
    a.className = "btn";
    a.href = reportUrl(reportName);
    a.textContent = "Informe";
    a.setAttribute("data-report", reportName);
    cell.appendChild(a);
  }

  // Añade un informe a la lista de "Reportes generados"
  function addReportToList(name) {
    const ul = document.getElementById("reports-list");
    if (!ul) return;
    if (ul.querySelector(`[data-report="${CSS.escape(name)}"]`)) return;
    const li = document.createElement("li");
    li.setAttribute("data-report", name);
    li.innerHTML = `<a class="btn" target="_blank" href="${reportUrl(name)}">${name}</a>`;
    ul.prepend(li);
  }

  // Cargar informes al entrar (opcional)
  document.addEventListener("DOMContentLoaded", async () => {
    const ul = document.getElementById("reports-list");
    if (!ul || !API_REPORTS_URL) return;
    try {
      const res = await fetch(API_REPORTS_URL);
      const data = await res.json();
      (data.files || []).forEach(addReportToList);
    } catch (_) {}
  });

  // Normaliza job_id de los eventos SSE
  function getJobId(d, e) {
    if (d && d.job_id) return d.job_id;
    if (d && d.meta && d.meta.job_id) return d.meta.job_id;
    const id = (e && e.lastEventId) ? String(e.lastEventId).trim() : "";
    return id || null;
  }

  // ===== SSE global =====
  if (EVENTS_URL) {
    const src = new EventSource(EVENTS_URL);

    src.addEventListener("job_created", e => {
      const d = JSON.parse(e.data);
      ensureRow({ id: d.job_id, status: d.status || "queued", progress: d.progress || 0, tools: d.tools || [] });
    });

    src.addEventListener("status", (e) => {
      try {
        const d = JSON.parse(e.data);
        const jobId = getJobId(d, e);
        if (!jobId) return;

        ensureRow({ id: jobId, status: d.status, progress: 0, tools: d.tools || [] });
        setStatus(jobId, d.status);
        if (d.status === "done") setProgress(jobId, 100);

        if (d.report) {
          addReportLink(jobId, d.report);
          addReportToList(d.report);
        }
      } catch (_) {}
    });

    src.addEventListener("progress", (e) => {
      try {
        const d = JSON.parse(e.data); // {progress, job_id}
        const jobId = getJobId(d, e);
        if (!jobId) return;
        ensureRow({ id: jobId, status: "running", progress: d.progress, tools: [] });
        setProgress(jobId, d.progress);
      } catch (_) {}
    });

    src.addEventListener("log", () => { /* listado no muestra logs */ });

    src.addEventListener("finished", (e) => {
      try {
        const d = JSON.parse(e.data);
        const jobId = getJobId(d, e);
        if (jobId) {
          setStatus(jobId, "done");
          setProgress(jobId, 100);
        }
      } catch (_) {}
    });
  }

  // ===== Envío AJAX del formulario (sin redirección) =====
  const form = document.getElementById("scanForm");
  if (form) {
    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      const btn = form.querySelector('button[type="submit"]');
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Lanzando…";
      }

      try {
        const fd = new FormData(form);
        const res = await fetch(API_SCAN_URL || form.action, {
          method: "POST",
          body: fd,
          credentials: "same-origin",
          headers: {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/plain, */*",
          },
        });

        // 1) Camino feliz: JSON
        let jobId = null,
          tools = [];
        try {
          const data = await res.clone().json();
          jobId = (data && data.job_id) || null;
          tools = data && Array.isArray(data.tools) ? data.tools : [];
        } catch (_) {
          // 2) Fallback: HTML/Texto → intenta extraer job_id
          const text = await res.text();
          const mUrl = text.match(/\/jobs\/([a-f0-9]{32})/i);
          const mHex = text.match(/\b[a-f0-9]{32}\b/i);
          const found = (mUrl && mUrl[1]) || (mHex && mHex[0]) || null;
          if (found) jobId = found.toLowerCase();
        }

        if (!jobId) {
          console.warn("No se pudo obtener job_id del servidor.");
          alert("El escaneo se lanzó, pero la UI no pudo leer el job_id.\nEl job aparecerá al recibir eventos SSE.");
          return;
        }

        // pinta fila inicial; el SSE seguirá actualizando
        ensureRow({ id: jobId, status: "running", progress: 0, tools });

        const row = document.getElementById("row-" + jobId);
        if (row) {
          row.style.outline = "2px solid #60a5fa";
          setTimeout(() => (row.style.outline = ""), 1200);
        }
      } catch (err) {
        console.error(err);
        alert("No se pudo lanzar el escaneo (conexión o servidor).");
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Iniciar escaneo";
        }
      }
    });
  }

  // ===== Inicialización de toggles de Nmap (si existen) =====
  (function initNmapToggles() {
    const nmapChk = document.getElementById("nmap");
    const adv = document.getElementById("nmap_opciones_avanzadas");
    if (nmapChk && adv) {
      const setAdv = () => (adv.style.display = nmapChk.checked ? "block" : "none");
      nmapChk.addEventListener("change", setAdv);
      setAdv();
    }

    const pt = document.getElementById("opt_ports_toggle");
    const ptBox = document.getElementById("ports_options");
    if (pt && ptBox) {
      const setPorts = () => (ptBox.style.display = pt.checked ? "block" : "none");
      pt.addEventListener("change", setPorts);
      setPorts();
    }

    const tt = document.getElementById("opt_timing_toggle");
    const ttBox = document.getElementById("timing_options");
    if (tt && ttBox) {
      const setTiming = () => (ttBox.style.display = tt.checked ? "block" : "none");
      tt.addEventListener("change", setTiming);
      setTiming();
    }
  })();
})();