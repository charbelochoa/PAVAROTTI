"use strict";

const byId = (id) => document.getElementById(id);
const element = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
};
let selectedKey = "";
let selectedRecord;
let editing;
let pageStarts = [""];
let pageIndex = 0;
let nextPage = "";
let pageFilters = "";
let pageRequest;
let inspectorRequest;
let refreshRequest;
let searchTimer;

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
  byId("note-tools").hidden = record?.kind !== "nota" || !record.id;
  const view = byId("record-detail");
  view.replaceChildren();
  if (!record) {
    view.append(element("p", message));
    return;
  }
  view.append(element("span", record.kind, "type"), element("h3", record.title), element("p", formatTime(record.time)));
  if (record.source) view.append(element("p", record.source));
  if (record.source_id) view.append(element("p", "ID · " + record.source_id));
  if (record.id && record.kind === "nota") view.append(element("p", "Revisión " + record.revision));
  if (record.sha256) view.append(element("p", "SHA-256 · " + record.sha256));
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

async function loadRecord(id, focus = false) {
  inspectorRequest?.abort();
  const controller = new AbortController();
  inspectorRequest = controller;
  inspect(undefined, "Consultando evidencia…");
  if (focus && window.matchMedia("(max-width: 970px)").matches) {
    byId("inspector").scrollIntoView({block: "nearest"});
  }
  try {
    const record = await request("/api/registro/" + encodeURIComponent(id), {signal: controller.signal});
    if (!controller.signal.aborted) inspect(record);
  } catch (error) {
    if (!controller.signal.aborted) inspect(undefined, error.message);
  }
}

function recordNode(record) {
  const row = element("button", "", "record");
  row.type = "button";
  row.setAttribute("aria-controls", "record-detail");
  row.setAttribute("aria-pressed", String(record.id === selectedKey));
  row.append(element("span", record.kind, "type"), element("strong", record.title));
  if (record.source) row.append(element("span", record.source, "muted"));
  row.onclick = () => {
    const prior = byId("records").querySelector('[aria-pressed="true"]');
    prior?.setAttribute("aria-pressed", "false");
    selectedKey = record.id;
    row.setAttribute("aria-pressed", "true");
    loadRecord(record.id, true);
  };
  return row;
}

function render(rows) {
  const listing = byId("records");
  listing.replaceChildren(...rows.map(recordNode));
  listing.scrollTop = 0;
  if (rows.length === 0) listing.append(element("p", "Sin registros para mostrar."));
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
  const changed = String(filters()) !== pageFilters;
  byId("previous-page").disabled = busy || changed || pageIndex === 0;
  byId("next-page").disabled = busy || changed || nextPage === "";
}

function filters() {
  return new URLSearchParams({tipo: byId("filter").value, buscar: byId("query").value.trim()});
}

async function loadPage(index, starts = pageStarts) {
  pageRequest?.abort();
  const controller = new AbortController();
  pageRequest = controller;
  pagingBusy(true);
  byId("page-state").textContent = "Cargando registros…";
  const search = filters();
  const currentFilters = String(search);
  search.set("despues", starts[index]);
  try {
    const page = await request("/api/registro/pagina?" + search, {signal: controller.signal});
    if (controller.signal.aborted) return;
    pageIndex = index;
    pageStarts = starts;
    pageFilters = currentFilters;
    nextPage = page.next || "";
    render(page.rows);
    byId("page-state").textContent = `Página ${pageIndex + 1} · ${page.rows.length} registros`;
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
  const page = first || String(filters()) !== pageFilters ? loadPage(0, [""]) : loadPage(pageIndex);
  const detail = selectedKey ? loadRecord(selectedKey) : Promise.resolve();
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
byId("filter").addEventListener("change", () => {
  clearTimeout(searchTimer);
  loadPage(0, [""]);
});
byId("refresh").addEventListener("click", () => refresh());

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
    if (result.id) selectedKey = result.id;
    await refresh(result.message || "Nota actualizada");
  } catch (error) {
    byId("note-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

function reportDialog(title, text) {
  byId("report-title").textContent = title;
  byId("report-text").textContent = text;
  byId("report-panel").showModal();
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
    const result = await request("/api/analisis", {method: "POST"});
    reportDialog("Análisis del expediente", result.text);
  } catch (error) {
    byId("status").textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

byId("credits").onclick = () => byId("credit-panel").showModal();
Promise.all([request("/api/app"), request("/credits.json")]).then(([app, credits]) => {
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
