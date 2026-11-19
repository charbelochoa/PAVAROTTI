"use strict";

const byId = (id) => document.getElementById(id);
const element = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
};
let selectedKey = "";
let selectedRevision = 0;
let selectedRecord;
let selectedAsset;
let selectedSTIXPage;
let returnToEvidence;
let editing;
let pageStarts = [""];
let pageIndex = 0;
let nextPage = "";
let pageFilters = "";
let pageRequest;
let inspectorRequest;
let refreshRequest;
let searchTimer;
let analysisQueue = false;
let checkingQueue = false;
let queueSignature = "";
let currentView = "records";
let assetSearch = "";
let recordSearch = "";

const assetKinds = {dominio: "Dominio", ipv4: "IPv4", ipv6: "IPv6", red: "Red", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5"};
const assetKey = ({type, value}) => `${type}/${value}`;
const assetCount = ({count, indicators}) =>
  `${count} ${count === 1 ? "registro" : "registros"}${indicators ? ` · ${indicators} ${indicators === 1 ? "indicador" : "indicadores"}` : ""}`;

async function request(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error((await response.text()).trim());
  return response.json();
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function inspect(record, message = "Selecciona un registro para examinarlo.") {
  selectedRecord = record;
  byId("note-tools").hidden = record?.kind !== "nota" || !record.id || selectedRevision > 0;
  const view = byId("record-detail");
  view.replaceChildren();
  if (!record) {
    view.append(element("p", message));
    return;
  }
  view.append(element("span", record.kind, "type"), element("h3", record.title), element("p", formatTime(record.time)));
  if (record.source) view.append(element("p", record.source));
  if (record.source_id) view.append(element("p", "ID · " + record.source_id));
  if (selectedRevision) {
    view.append(element("p", "Revisión citada " + record.revision));
  } else if (record.id && record.kind === "nota") {
    view.append(element("p", "Revisión " + record.revision));
  }
  if (selectedRevision || returnToEvidence) {
    const tools = element("div", "", "tools");
    if (selectedRevision) {
      const current = element("button", "Abrir revisión vigente");
      current.onclick = () => selectRecord(record.id, 0, returnToEvidence, selectedSTIXPage);
      tools.append(current);
    }
    if (returnToEvidence) {
      const back = element("button", returnToEvidence.label);
      back.onclick = returnToEvidence.open;
      tools.append(back);
    }
    view.append(tools);
  }
  if (record.sha256) view.append(element("p", "SHA-256 · " + record.sha256));
  if (record.kind === "stix") view.append(stixPanel(record));
  if (record.traffic) {
    const item = record.traffic;
    view.append(element("p", `${item.type || "Tipo desconocido"} · ${item.millis} ms`));
  }
  if (record.signals?.length) {
    const list = element("ul");
    for (const signal of record.signals) list.append(element("li", signal));
    view.append(list);
  }
  if (record.details) view.append(element("pre", record.details));
}

function selectRecord(id, revision = 0, back, stixPage) {
  selectedAsset = undefined;
  selectedSTIXPage = stixPage;
  returnToEvidence = back;
  selectedKey = id;
  selectedRevision = revision;
  paintSelection();
  if (revision || back) byId("inspector-heading").focus({preventScroll: true});
  return loadRecord(id, true);
}

function stixPanel(record) {
  const panel = element("details", "", "stix-links");
  panel.append(element("summary", "Relaciones STIX"));
  const list = element("div", "", "asset-sources");
  panel.append(list);
  let loaded = false;
  const prior = returnToEvidence;
  const revision = selectedRevision;
  const signal = inspectorRequest.signal;
  const load = async (offset = 0) => {
    loaded = true;
    selectedSTIXPage = offset;
    list.replaceChildren(element("p", "Consultando relaciones…"));
    try {
      const page = await request(`/api/registro/${encodeURIComponent(record.id)}/stix?despues=${offset}`, {signal});
      if (signal.aborted) return;
      list.replaceChildren();
      for (const link of page.rows) {
        const direction = link.incoming ? "Entrante" : "Saliente";
        const label = `${direction} · ${link.role}`;
        if (!link.evidence) {
          list.append(element("p", `${label} · Objeto por importar · ${link.id}`));
          continue;
        }
        const evidence = link.evidence;
        const button = element("button");
        button.append(element("strong", evidence.title),
          element("span", `${label} · ${link.same_package ? "Mismo paquete" : "Otro paquete"} · rev. ${evidence.revision}`, "type"));
        if (evidence.source_id) button.append(element("span", evidence.source_id, "muted"));
        button.onclick = () => selectRecord(evidence.id, evidence.revision, {
          label: "Volver al objeto STIX", open: () => selectRecord(record.id, revision, prior, offset)
        });
        list.append(button);
      }
      if (!page.rows.length) list.append(element("p", "Sin relaciones en el expediente."));
      const tools = element("div", "", "tools");
      if (offset) {
        const previous = element("button", "Relaciones anteriores");
        previous.onclick = () => load(page.previous);
        tools.append(previous);
      }
      if (page.next) {
        const next = element("button", "Más relaciones");
        next.onclick = () => load(page.next);
        tools.append(next);
      }
      list.append(tools);
    } catch (error) {
      if (!signal.aborted) {
        list.replaceChildren(element("p", error.message));
        loaded = false;
      }
    }
  };
  panel.ontoggle = () => {
    if (panel.open && !loaded) load(selectedSTIXPage);
  };
  panel.open = selectedSTIXPage !== undefined;
  return panel;
}

function beginInspection(message) {
  inspectorRequest?.abort();
  const controller = new AbortController();
  inspectorRequest = controller;
  inspect(undefined, message);
  return controller;
}

async function loadRecord(id, scroll = false) {
  const controller = beginInspection("Consultando evidencia…");
  if (scroll && (selectedRevision || window.matchMedia("(max-width: 970px)").matches)) {
    byId("inspector").scrollIntoView({block: "nearest"});
  }
  try {
    const query = selectedRevision ? "?revision=" + selectedRevision : "";
    const record = await request("/api/registro/" + encodeURIComponent(id) + query, {signal: controller.signal});
    if (!controller.signal.aborted) inspect(record);
  } catch (error) {
    if (!controller.signal.aborted) inspect(undefined, error.message);
  }
}

function selectAsset(asset, after = "") {
  selectedKey = "";
  selectedRevision = 0;
  returnToEvidence = undefined;
  selectedAsset = {type: asset.type, value: asset.value, after};
  paintSelection();
  byId("inspector-heading").focus({preventScroll: true});
  if (window.matchMedia("(max-width: 970px)").matches) {
    byId("inspector").scrollIntoView({block: "nearest"});
  }
  return loadAsset(selectedAsset);
}

async function loadAsset(asset) {
  const controller = beginInspection("Consultando activo…");
  const params = new URLSearchParams({tipo: asset.type, valor: asset.value, despues: asset.after});
  try {
    const detail = await request("/api/activos/ficha?" + params, {signal: controller.signal});
    if (!controller.signal.aborted) inspectAsset(detail, asset);
  } catch (error) {
    if (!controller.signal.aborted) inspect(undefined, error.message);
  }
}

function inspectAsset(detail, asset) {
  const list = element("div", "", "asset-sources");
  for (const reference of detail.rows) {
    const button = element("button");
    button.append(element("strong", reference.title || reference.kind),
      element("span", `${reference.kind} · ${reference.role} · rev. ${reference.revision}`, "type"));
    if (reference.network && reference.title !== "Red · " + reference.network) {
      button.append(element("span", reference.network, "muted"));
    }
    if (reference.time) button.append(element("span", formatTime(reference.time), "muted"));
    button.onclick = () => selectRecord(reference.id, reference.revision, {
      label: "Volver al activo", open: () => selectAsset(asset, asset.after)
    });
    list.append(button);
  }
  const controls = element("div", "", "tools");
  if (asset.after) {
    const first = element("button", "Primeros registros");
    first.onclick = () => selectAsset(asset);
    controls.append(first);
  }
  if (detail.next) {
    const next = element("button", "Más registros");
    next.onclick = () => selectAsset(asset, detail.next);
    controls.append(next);
  }
  const view = byId("record-detail");
  view.replaceChildren(element("span", assetKinds[detail.type], "type"), element("h3", detail.value),
    element("p", assetCount(detail)), list, controls);
  if (detail.coverage) list.before(element("p", `Cobertura de red · ${detail.coverage}`));
  view.scrollTop = 0;
}

function paintSelection() {
  for (const row of byId("records").querySelectorAll("[data-record-id], [data-asset-key]")) {
    const pressed = selectedAsset ? row.dataset.assetKey === assetKey(selectedAsset) :
      !selectedRevision && row.dataset.recordId === selectedKey;
    row.setAttribute("aria-pressed", String(pressed));
  }
}

function recordNode(record) {
  const row = element("button", "", "record");
  row.type = "button";
  row.dataset.recordId = record.id;
  row.setAttribute("aria-controls", "record-detail");
  const traffic = record.traffic;
  if (traffic) {
    row.append(element("span", `${traffic.method} ${traffic.status}`, "type"),
      element("strong", record.source || record.title));
    const details = [record.kind === "archivo HAR" ? "HAR" : "Proxy", traffic.type || "Sin tipo MIME", traffic.millis + " ms"];
    if (record.signal_count) details.push(`${record.signal_count} ${record.signal_count === 1 ? "señal" : "señales"}`);
    row.append(element("span", details.join(" · "), "muted"));
  } else {
    row.append(element("span", record.kind, "type"), element("strong", record.title));
    if (record.source) row.append(element("span", record.source, "muted"));
  }
  row.onclick = () => selectRecord(record.id);
  return row;
}

function assetNode(asset) {
  const row = element("button", "", "record");
  row.type = "button";
  row.dataset.assetKey = assetKey(asset);
  row.setAttribute("aria-controls", "record-detail");
  row.append(element("span", assetKinds[asset.type], "type"), element("strong", asset.value),
    element("span", assetCount(asset), "muted"));
  row.onclick = () => selectAsset(asset);
  return row;
}

function render(rows) {
  const listing = byId("records");
  const onAssets = currentView === "assets";
  listing.replaceChildren(...rows.map(onAssets ? assetNode : recordNode));
  paintSelection();
  listing.scrollTop = 0;
  if (rows.length === 0) listing.append(element("p", onAssets ? "Sin activos para mostrar." : "Sin registros para mostrar."));
}

function summarize(summary) {
  byId("total").textContent = summary.total;
  byId("traffic").textContent = summary.traffic;
  byId("signals").textContent = summary.signals;
  const counts = (category, label = (name) => name) =>
    Object.entries(category).sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `${label(name)} (${count})`).join(" · ") || "Sin datos";
  byId("groups").replaceChildren(
    element("dt", "Estado"), element("dd", counts(summary.status)),
    element("dt", "Tipo MIME"), element("dd", counts(summary.mime, (name) => name || "Sin tipo")),
    element("dt", "Latencia"), element("dd", counts(summary.bucket, (name) => "< " + (name === "0" ? "1" : name) + " ms"))
  );
}

function pagingBusy(busy) {
  byId("records").setAttribute("aria-busy", String(busy));
  const changed = filterKey() !== pageFilters;
  byId("previous-page").disabled = busy || changed || pageIndex === 0;
  byId("next-page").disabled = busy || changed || nextPage === "";
}

function filters() {
  const type = currentView === "http" ? "http" : byId(currentView === "assets" ? "filter-asset" : "filter").value;
  const params = new URLSearchParams({tipo: type, buscar: byId("query").value.trim()});
  if (currentView === "http" && byId("filter-http").value) params.set("clase_http", byId("filter-http").value);
  return params;
}

function filterKey() { return currentView + "?" + filters(); }

async function loadPage(index, starts = pageStarts) {
  pageRequest?.abort();
  const controller = new AbortController();
  pageRequest = controller;
  pagingBusy(true);
  const onAssets = currentView === "assets";
  const items = onAssets ? "activos" : "registros";
  byId("page-state").textContent = `Cargando ${items}…`;
  const search = filters();
  const currentFilters = filterKey();
  search.set("despues", starts[index]);
  try {
    const path = onAssets ? "/api/activos?" : "/api/registro/pagina?";
    const page = await request(path + search, {signal: controller.signal});
    if (controller.signal.aborted) return;
    pageIndex = index;
    pageStarts = starts;
    pageFilters = currentFilters;
    nextPage = page.next || "";
    render(page.rows);
    const count = page.rows.length;
    const label = count === 1 ? (onAssets ? "activo" : "registro") : items;
    byId("page-state").textContent = `Página ${pageIndex + 1} · ${count} ${label}`;
  } catch (error) {
    if (!controller.signal.aborted) byId("page-state").textContent = error.message;
  } finally {
    if (!controller.signal.aborted) pagingBusy(false);
  }
}

async function refresh(message = "", first = false) {
  clearTimeout(searchTimer);
  refreshRequest?.abort();
  const controller = new AbortController();
  refreshRequest = controller;
  byId("status").textContent = message;
  const page = first || filterKey() !== pageFilters ? loadPage(0, [""]) : loadPage(pageIndex);
  const detail = selectedAsset ? loadAsset(selectedAsset) : selectedKey && loadRecord(selectedKey);
  try {
    const summary = await request("/api/registro/resumen", {signal: controller.signal});
    if (!controller.signal.aborted) summarize(summary);
  } catch (error) {
    if (!controller.signal.aborted) byId("status").textContent = error.message;
  }
  await Promise.all([page, detail]);
}

byId("previous-page").onclick = () => loadPage(pageIndex - 1);
byId("next-page").onclick = () => loadPage(pageIndex + 1, [...pageStarts.slice(0, pageIndex + 1), nextPage]);
byId("query").addEventListener("input", () => {
  clearTimeout(searchTimer);
  pageRequest?.abort();
  pagingBusy(true);
  searchTimer = setTimeout(() => loadPage(0, [""]), 230);
});
for (const id of ["filter", "filter-asset", "filter-http"]) {
  byId(id).addEventListener("change", () => {
    clearTimeout(searchTimer);
    loadPage(0, [""]);
  });
}
function showView(view) {
  if (currentView === view) return;
  const query = byId("query");
  if (currentView === "assets") assetSearch = query.value;
  else recordSearch = query.value;
  currentView = view;
  clearTimeout(searchTimer);
  for (const name of ["records", "assets", "http"]) {
    byId("view-" + name).setAttribute("aria-pressed", String(name === view));
  }
  byId("filter").hidden = view !== "records";
  byId("filter-asset").hidden = view !== "assets";
  byId("filter-http").hidden = view !== "http";
  query.placeholder = view === "assets" ? "Buscar dominio, IP, red o huella" : "Buscar texto, origen, ID o SHA-256";
  query.maxLength = view === "assets" ? 253 : 256;
  query.value = view === "assets" ? assetSearch : recordSearch;
  byId("records").replaceChildren();
  loadPage(0, [""]);
}
for (const view of ["records", "assets", "http"]) byId("view-" + view).onclick = () => showView(view);
byId("refresh").addEventListener("click", () => refresh());

byId("export-stix").onclick = async (event) => {
  const button = event.currentTarget;
  const status = byId("status");
  button.disabled = true;
  status.textContent = "Preparando paquete STIX…";
  try {
    const response = await fetch("/api/exportar/stix");
    if (!response.ok) throw new Error((await response.text()).trim());
    const url = URL.createObjectURL(await response.blob());
    const download = element("a");
    download.href = url;
    download.download = "PAVAROTTI-STIX.json";
    download.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status.textContent = `STIX · ${response.headers.get("X-Pavarotti-Objects")} objetos · ` +
      `${response.headers.get("X-Pavarotti-Exported")} registros representados · ` +
      `${response.headers.get("X-Pavarotti-Excluded")} fuera del formato`;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

byId("upload").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  const selected = byId("evidence").files[0];
  try {
    const result = await request("/api/archivo/" + byId("file-kind").value,
      {method: "POST", body: selected, headers: {"Content-Type": "application/octet-stream"}});
    byId("evidence").value = "";
    await refresh(result.message, true);
  } catch (error) {
    byId("status").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

function noteDialog(record) {
  editing = record;
  byId("note-title").textContent = record ? "Editar nota" : "Registrar nota";
  for (const field of ["title", "source", "details"]) byId(field).value = record?.[field] || "";
  byId("note-error").textContent = "";
  byId("note-panel").showModal();
}
byId("add-note").onclick = () => noteDialog();
byId("edit-note").onclick = () => noteDialog(selectedRecord);
byId("note-cancel").onclick = () => byId("note-panel").close();
byId("note-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  try {
    const note = Object.fromEntries(new FormData(event.currentTarget));
    if (editing) note.revision = editing.revision;
    const path = editing ? "/api/nota/" + encodeURIComponent(editing.id) : "/api/nota";
    const result = await request(path, {
      method: editing ? "PATCH" : "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(note)
    });
    byId("note-panel").close();
    byId("note-form").reset();
    if (result.id) {
      selectedAsset = undefined;
      selectedKey = result.id;
      selectedRevision = 0;
    }
    await refresh(result.message || "Nota actualizada");
  } catch (error) {
    byId("note-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

const reportSections = [
  ["matches", "Coincidencias"], ["hash_matches", "Coincidencias SHA-256"], ["network_matches", "Cobertura de red"],
  ["assets", "Activos"], ["signals", "Señales HTTP"],
  ["responses", "Respuestas HTTP"], ["indicators", "Indicadores"], ["hashes", "Huellas"], ["timeline", "Cronología"]
];

function reportDialog(title, text, report) {
  byId("report-title").textContent = title;
  byId("report-text").textContent = text;
  const panel = byId("report-evidence");
  const choice = byId("report-section");
  const listing = byId("report-references");
  const sections = reportSections.flatMap(([key, label]) => {
    const values = report?.[key] || [];
    const groups = key === "timeline" ? [{evidence: values}] : values;
    const cited = groups.map((group) => ({...group, evidence: (group.evidence || [])
      .filter((item) => item.id && Number.isInteger(item.revision) && item.revision > 0)}))
      .filter((group) => group.evidence.length);
    return cited.length ? [{label, groups: cited}] : [];
  });
  panel.hidden = sections.length === 0;
  panel.open = false;
  listing.replaceChildren();
  choice.replaceChildren(...sections.map(({label}) => element("option", label)));
  const renderReferences = () => {
    const section = sections[choice.selectedIndex];
    const groups = (section?.groups || []).map(({value, scope, evidence, samples}) => {
      const group = element("div", "", "reference-group");
      if (value) group.append(element("strong", scope ? `${value} · ${scope}` : value));
      if (samples?.length) group.append(element("span", "IP citadas · " + samples.join(", "), "muted"));
      for (const item of evidence) {
        const action = element("button", `${item.title || item.kind} · rev. ${item.revision}`);
        action.title = `${item.id} · revisión ${item.revision}`;
        action.onclick = () => {
          byId("report-panel").close();
          selectRecord(item.id, item.revision, {
            label: "Volver al informe", open: () => byId("report-panel").showModal()
          });
        };
        group.append(action);
      }
      return group;
    });
    listing.replaceChildren(...groups);
    listing.scrollTop = 0;
  };
  choice.onchange = renderReferences;
  renderReferences();
  byId("report-panel").showModal();
}

const jobLabels = {queued: "En cola", running: "En ejecución", succeeded: "Informe listo", canceled: "Cancelada", failed: "Falló"};
const priorityLabels = ["baja", "normal", "alta"];

async function showAnalysisJob(id) {
  try {
    const result = await request("/api/analisis/tareas/" + encodeURIComponent(id));
    const job = result.job;
    const text = result.text || job.error || jobLabels[job.state];
    reportDialog("Análisis " + job.id.slice(0, 8), text, job.result);
  } catch (error) {
    byId("status").textContent = error.message;
  }
}

async function cancelAnalysisJob(id, button) {
  button.disabled = true;
  try {
    await request("/api/analisis/tareas/" + encodeURIComponent(id) + "/cancelar", {method: "POST"});
    byId("status").textContent = "Tarea cancelada";
  } catch (error) {
    byId("status").textContent = error.message;
  } finally {
    button.disabled = false;
    await refreshQueue();
  }
}

function analysisJobNode(job) {
  const row = element("div", "", "analysis-job");
  const details = element("div");
  details.append(element("strong", jobLabels[job.state], "job-state"),
    element("p", `${job.id.slice(0, 8)} · prioridad ${priorityLabels[job.priority]} · ${formatTime(job.created_at)}`));
  if (job.attempts) details.append(element("p", `Intento ${job.attempts}`));
  if (job.error) details.append(element("p", job.error));
  const actions = element("div", "", "job-actions");
  if (job.state === "succeeded") {
    const open = element("button", "Abrir informe");
    open.dataset.jobAction = job.id + ":open";
    open.onclick = () => showAnalysisJob(job.id);
    actions.append(open);
  } else if (job.state === "queued" || job.state === "running") {
    const cancel = element("button", "Cancelar");
    cancel.dataset.jobAction = job.id + ":cancel";
    cancel.onclick = () => cancelAnalysisJob(job.id, cancel);
    actions.append(cancel);
  }
  row.append(details, actions);
  return row;
}

async function refreshQueue() {
  if (!analysisQueue || checkingQueue || document.hidden) return;
  checkingQueue = true;
  try {
    const jobs = await request("/api/analisis/tareas");
    const active = jobs.filter((job) => job.state === "queued" || job.state === "running").length;
    const status = jobs.length ? `${active} activas · ${jobs.length} recientes` : "Sin tareas de análisis.";
    if (byId("queue-status").textContent !== status) byId("queue-status").textContent = status;
    const signature = JSON.stringify(jobs);
    if (signature !== queueSignature) {
      queueSignature = signature;
      const listing = byId("analysis-jobs");
      const action = listing.contains(document.activeElement) ? document.activeElement.dataset.jobAction : "";
      listing.replaceChildren(...jobs.map(analysisJobNode));
      if (action) [...listing.querySelectorAll("[data-job-action]")].find((button) => button.dataset.jobAction === action)?.focus();
    }
  } catch (error) {
    byId("queue-status").textContent = error.message;
  } finally {
    checkingQueue = false;
  }
}

byId("history").onclick = async () => {
  try {
    const record = selectedRecord;
    const history = await request("/api/nota/" + encodeURIComponent(record.id) + "/historial");
    const text = (history || []).map((item) =>
      `Revisión ${item.revision} · ${formatTime(item.updated_at || item.time)}\n${item.title}\n${item.source || ""}\n${item.details}`
    ).join("\n\n");
    reportDialog("Versiones anteriores de la nota", text || "Aún no hay versiones anteriores.");
  } catch (error) {
    byId("status").textContent = error.message;
  }
};

byId("analyze").onclick = async () => {
  const button = byId("analyze");
  button.disabled = true;
  try {
    if (analysisQueue) {
      const job = await request("/api/analisis/tareas", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({priority: Number(byId("analysis-priority").value)})
      });
      const action = job.state === "succeeded" ? "Informe recuperado" : "Tarea registrada";
      byId("status").textContent = `${action} · ${job.id.slice(0, 8)}`;
      await refreshQueue();
      if (job.state === "succeeded") await showAnalysisJob(job.id);
      return;
    }
    const result = await request("/api/analisis", {method: "POST"});
    reportDialog("Análisis del expediente", result.text, result.report);
  } catch (error) {
    byId("status").textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

byId("credits").onclick = () => byId("credit-panel").showModal();
Promise.all([request("/api/app"), request("/credits.json")]).then(([app, credits]) => {
  analysisQueue = app.analysis_queue;
  if (analysisQueue) {
    byId("analysis-queue").hidden = false;
    byId("analyze").textContent = "Encolar análisis";
    refreshQueue();
    setInterval(refreshQueue, 2500);
    document.addEventListener("visibilitychange", refreshQueue);
  }
  byId("version").textContent = "PAVAROTTI " + app.version;
  byId("proxy-status").textContent = app.proxy ? "Escucha local · " + app.target : "Desactivado";
  if (app.proxy) {
    byId("proxy-link").href = app.proxy;
    byId("proxy-link").hidden = false;
  }
  for (const credit of credits) {
    const row = element("li");
    const link = element("a", credit.name);
    link.href = credit.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    row.append(link, document.createTextNode(" · " + credit.detail));
    byId("references").append(row);
  }
}).catch(() => { byId("proxy-status").textContent = "No se pudo leer la configuración"; });
refresh();
