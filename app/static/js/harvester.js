// static/js/harvester.js
(function () {
  "use strict";

  // === Rutas inyectadas por la plantilla (theHarvester.html) ===
  const R = window.APP_ROUTES || {};
  const EVENTS_URL       = R.EVENTS_URL;                      // url_for('main.events')
  const API_REPORTS_URL  = R.API_REPORTS_URL;                 // url_for('main.api_reports')
  const API_HARVESTER_URL= R.API_HARVESTER_URL;               // url_for('main.harvester_scan')
  const JOB_DETAIL_TMPL  = R.JOB_DETAIL_URL_TMPL;             // url_for('main.job_detail', job_id='__ID__')
  const REPORT_URL_TMPL  = R.REPORT_URL_TMPL;                 // url_for('main.get_report', name='__NAME__')

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

  // Crea la tabla "Trabajos recientes" si aún no existe
  function ensureJobsTable() {
    let table = document.getElementById("jobs-table");
    if (table) return table.tBodies[0];

    // Busca la card de “Trabajos recientes”, si no existe añade una al final
    const cards = Array.from(document.querySelectorAll("section.card"));
    const jobsCard = cards.find(c => c.querySelector("h2")?.textContent?.toLowerCase().includes("trabajos"))
                  || document.body;

    // Elimina el “No hay trabajos…” si está
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
            <th>Opciones</th>
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
      const oc = document.getElementById("opts-" + job_id);
      if (oc && job.opts_summary) oc.textContent = job.opts_summary;
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
      <td id="opts-${job_id}"><small class="muted">${job.opts_summary || ""}</small></td>
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

  // Al entrar, cargar informes si hay endpoint configurado
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

  // Intenta determinar si un evento corresponde a theHarvester
  function isHarvesterEvent(d) {
    const t = (d && (d.tool || (d.meta && d.meta.tool))) ? String(d.tool || d.meta.tool).toLowerCase() : null;
    if (t) return t === "theharvester" || t === "harvester";
    // Si no hay marca de herramienta, inferimos por campos típicos
    if (d && (d.opts_summary || (d.meta && d.meta.harvester_opts))) return true;
    // Último recurso: si ya hay fila para ese job, seguimos actualizándola
    const jid = (d && (d.job_id || (d.meta && d.meta.job_id))) || null;
    return !!(jid && document.getElementById("row-" + jid));
  }

  // ===== SSE global =====
  if (EVENTS_URL) {
    const src = new EventSource(EVENTS_URL);

    src.addEventListener("job_created", e => {
      try {
        const d = JSON.parse(e.data);
        if (!isHarvesterEvent(d)) return;
        ensureRow({
          id: d.job_id,
          status: d.status || "queued",
          progress: d.progress || 0,
          opts_summary: d.opts_summary || ""
        });
      } catch (_) {}
    });

    src.addEventListener("status", (e) => {
      try {
        const d = JSON.parse(e.data);
        if (!isHarvesterEvent(d)) return;
        const jobId = getJobId(d, e);
        if (!jobId) return;

        ensureRow({ id: jobId, status: d.status, progress: 0, opts_summary: d.opts_summary || "" });
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
        const d = JSON.parse(e.data);
        if (!isHarvesterEvent(d)) return;
        const jobId = getJobId(d, e);
        if (!jobId) return;
        ensureRow({ id: jobId, status: "running", progress: d.progress, opts_summary: d.opts_summary || "" });
        setProgress(jobId, d.progress);
      } catch (_) {}
    });

    src.addEventListener("finished", (e) => {
      try {
        const d = JSON.parse(e.data);
        if (!isHarvesterEvent(d)) return;
        const jobId = getJobId(d, e);
        if (jobId) {
          setStatus(jobId, "done");
          setProgress(jobId, 100);
        }
      } catch (_) {}
    });

    // (Opcional) logs si quieres interceptarlos
    src.addEventListener("log", () => {});
  }

    const $ = (s) => document.querySelector(s);
    const $$ = (s) => Array.from(document.querySelectorAll(s));
    const domain = $('#domain');
    const limit = $('#limit');
    const start = $('#start');
    const proxies = $('input[name="proxies"]');
    const shodan = $('input[name="shodan"]');
    const screenshot = $('#screenshot_dir');
    const dnsServer = $('#dns_server');
    const takeOver = $('input[name="take_over"]');
    const dnsResolveChk = $('#dns_resolve_chk');
    const dnsResolveVal = $('#dns_resolve_val');
    const dnsLookup = $('input[name="dns_lookup"]');
    const dnsBrute = $('input[name="dns_brute"]');
    const filename = $('#filename');
    const wordlist = $('#wordlist');
    const apiScan = $('input[name="api_scan"]');
    const quiet = $('input[name="quiet"]');
    const sources = $('#sources');
    const preview = $('#cmdPreview');
    const form = $('#harvesterForm');

      // Mostrar/ocultar input de -r cuando está activo
  dnsResolveChk?.addEventListener('change', () => {
    dnsResolveVal.style.display = dnsResolveChk.checked ? 'block' : 'none';
  });

  // Construye una vista estilo CLI
  function buildCmdPreview() {
    let cmd = ['theHarvester'];
    if (domain.value) { cmd.push('-d', shellEscape(domain.value)); }
    if (limit.value) { cmd.push('-l', String(limit.value)); }
    if (start.value) { cmd.push('-S', String(start.value)); }
    if (proxies?.checked) { cmd.push('-p'); }
    if (shodan?.checked) { cmd.push('-s'); }
    if (screenshot.value) { cmd.push('--screenshot', shellEscape(screenshot.value)); }
    if (dnsServer.value) { cmd.push('-e', shellEscape(dnsServer.value)); }
    if (takeOver?.checked) { cmd.push('-t'); }
    if (dnsResolveChk?.checked) {
      cmd.push('-r');
      if (dnsResolveVal.value) cmd.push(shellEscape(dnsResolveVal.value));
    }
    if (dnsLookup?.checked) { cmd.push('-n'); }
    if (dnsBrute?.checked) { cmd.push('-c'); }
    if (filename.value) { cmd.push('-f', shellEscape(filename.value)); }
    if (wordlist.value) { cmd.push('-w', shellEscape(wordlist.value)); }
    if (apiScan?.checked) { cmd.push('-a'); }
    if (quiet?.checked) { cmd.push('-q'); }
    const selectedSources = Array.from(sources?.selectedOptions || []).map(o => o.value.trim()).filter(Boolean);
    selectedSources.forEach(src => { cmd.push('-b', src); });

    preview.textContent = cmd.join(' ');
  }

    function shellEscape(v){
      if (/^[A-Za-z0-9._:\\/\\-]+$/.test(v)) return v;
      return `'${v.replace(/'/g, `'\\''`)}'`;
    }

      // Eventos para refrescar la vista
    [
      domain, limit, start, proxies, shodan, screenshot, dnsServer, takeOver,
      dnsResolveChk, dnsResolveVal, dnsLookup, dnsBrute, filename, wordlist,
      apiScan, quiet, sources
    ].filter(Boolean).forEach(el => {
      const evt = (el.tagName === 'SELECT' || el.type === 'checkbox' || el.type === 'radio') ? 'change' : 'input';
      el.addEventListener(evt, buildCmdPreview);
    });
    buildCmdPreview();

  // ===== Envío AJAX del formulario (sin redirección) =====

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
        const res = await fetch(API_HARVESTER_URL || form.action, {
          method: "POST",
          body: fd,
          credentials: "same-origin",
          headers: {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/plain, */*",
          },
        });

        // 1) Camino feliz: JSON
        let jobId = null, opts_summary = "";
        try {
          const data = await res.clone().json();
          jobId = (data && data.job_id) || null;
          opts_summary = (data && data.opts_summary) || "";
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
          alert("La búsqueda se lanzó, pero la UI no pudo leer el job_id.\nEl job aparecerá al recibir eventos SSE.");
          return;
        }

        // pinta fila inicial; el SSE seguirá actualizando
        ensureRow({ id: jobId, status: "running", progress: 0, opts_summary });

        const row = document.getElementById("row-" + jobId);
        if (row) {
          row.style.outline = "2px solid #60a5fa";
          setTimeout(() => (row.style.outline = ""), 1200);
        }
      } catch (err) {
        console.error(err);
        alert("No se pudo lanzar theHarvester (conexión o servidor).");
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Iniciar búsqueda";
        }
      }
    });
  }
})();