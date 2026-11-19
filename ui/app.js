"use strict";

const byId = (id) => document.getElementById(id);
const element = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
};
let records = [];
let selectedKey = "";
let selectedRecord;
let editing;

async function request(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error((await response.text()).trim());
  return response.json();
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function key(record) {
  return record.id || JSON.stringify([record.kind, record.time, record.title, record.source_id, record.sha256]);
}

function inspect(record) {
  selectedRecord = record;
  byId("note-tools").hidden = record?.kind !== "nota" || !record.id;
  const view = byId("record-detail");
  view.replaceChildren();
  if (!record) {
    view.append(element("p", "Selecciona un registro para examinarlo."));
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

function recordNode(record) {
  const row = element("button", "", "record");
  row.type = "button";
  row.setAttribute("aria-controls", "record-detail");
  row.setAttribute("aria-pressed", String(key(record) === selectedKey));
  row.append(element("span", record.kind, "type"), element("strong", record.title));
  if (record.source) row.append(element("span", record.source, "muted"));
  row.onclick = () => {
    const prior = byId("records").querySelector('[aria-pressed="true"]');
    prior?.setAttribute("aria-pressed", "false");
    selectedKey = key(record);
    row.setAttribute("aria-pressed", "true");
    inspect(record);
    if (window.matchMedia("(max-width: 970px)").matches) byId("inspector").scrollIntoView({block: "nearest"});
  };
  return row;
}

function render() {
  const query = byId("query").value.trim().toLowerCase();
  const kind = byId("filter").value;
  const matching = records.filter((entry) =>
    (!kind || entry.kind === kind) && JSON.stringify(entry).toLowerCase().includes(query));
  const listing = byId("records");
  const shown = matching.slice(0, 250);
  inspect(shown.find((record) => key(record) === selectedKey));
  listing.replaceChildren(...shown.map(recordNode));
  if (matching.length === 0) listing.append(element("p", "Sin registros para mostrar."));
  if (matching.length > 250) listing.append(element("p", "Primeros 250 resultados. Usa la búsqueda para acotar."));
}

function summarize() {
  const traffic = records.filter((record) => record.traffic);
  byId("total").textContent = records.length;
  byId("traffic").textContent = traffic.length;
  byId("signals").textContent = records.reduce((sum, record) => sum + (record.signals?.length || 0), 0);
  const counts = (category) => {
    const counter = new Map();
    for (const {traffic: entry} of traffic) {
      const group = category(entry);
      counter.set(group, (counter.get(group) || 0) + 1);
    }
    return Array.from(counter).sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `${name} (${count})`).join(" · ") || "Sin datos";
  };
  byId("groups").replaceChildren(
    element("dt", "Estado"), element("dd", counts((entry) => entry.status)),
    element("dt", "Tipo MIME"), element("dd", counts((entry) => entry.type || "Sin tipo")),
    element("dt", "Latencia"), element("dd", counts((entry) => entry.bucket ? "< " + entry.bucket + " ms" : "< 1 ms"))
  );
}

async function refresh(message = "") {
  try {
    records = await request("/api/registro");
    summarize();
    render();
    byId("status").textContent = message;
  } catch (error) {
    byId("status").textContent = error.message;
  }
}

byId("query").addEventListener("input", render);
byId("filter").addEventListener("change", render);
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
    await refresh(result.message);
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
