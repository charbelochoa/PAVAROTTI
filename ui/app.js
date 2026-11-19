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
  return JSON.stringify([record.kind, record.time, record.title, record.source_id, record.sha256]);
}

function inspect(record) {
  const view = byId("record-detail");
  view.replaceChildren();
  if (!record) {
    view.append(element("p", "Selecciona un registro para examinarlo."));
    return;
  }
  view.append(element("span", record.kind, "type"), element("h3", record.title), element("p", formatTime(record.time)));
  if (record.source) view.append(element("p", record.source));
  if (record.source_id) view.append(element("p", "ID · " + record.source_id));
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

byId("add-note").onclick = () => {
  byId("note-error").textContent = "";
  byId("note-panel").showModal();
};
byId("note-cancel").onclick = () => byId("note-panel").close();
byId("note-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  try {
    const result = await request("/api/nota", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget)))
    });
    byId("note-panel").close();
    byId("note-form").reset();
    await refresh(result.message);
  } catch (error) {
    byId("note-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

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
