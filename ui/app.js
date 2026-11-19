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
let activeTriage;
let pageStarts = [""];
let pageIndex = 0;
let nextPage = "";
let pageFilters = "";
let pageRequest;
let inspectorRequest;
let refreshRequest;
let searchTimer;
let analysisQueue = false;
let canWrite = false;
let checkingQueue = false;
let queueSignature = "";
let currentView = "records";
const viewSearch = new Map();
const views = {
  records: {filter: "filter", placeholder: "Buscar texto, origen, ID o SHA-256"},
  assets: {filter: "filter-asset", placeholder: "Buscar dominio, IP, red o huella"},
  binaries: {kind: "binario", placeholder: "Buscar archivo, formato, cadena o SHA-256"},
  http: {kind: "http", placeholder: "Buscar origen, señal o tipo MIME"}
};

const httpFilters = {"filter-http": "clase_http", "filter-capture": "captura", "filter-method": "metodo",
  "filter-http-rule": "regla_http", "filter-from": "desde", "filter-to": "hasta"};
const captureLabel = (kind) => ({"tráfico": "Proxy inverso", "archivo HAR": "Archivo HAR"})[kind] || kind;

const assetKinds = {dominio: "Dominio", ipv4: "IPv4", ipv6: "IPv6", red: "Red", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5"};
const assetKey = ({type, value}) => `${type}/${value}`;
const assetCount = ({count, indicators}) =>
  `${count} ${count === 1 ? "registro" : "registros"}${indicators ? ` · ${indicators} ${indicators === 1 ? "indicador" : "indicadores"}` : ""}`;
const triageLabels = {pendiente: "Pendiente", confirmada: "Confirmada", descartada: "Descartada"};
const findingKey = ({rule, line, column}) => `${line}:${column}:${rule}`;

async function requireResponse(response) {
  if (response.status === 401) window.location.replace("/ingresar");
  if (!response.ok) throw new Error((await response.text()).trim());
  return response;
}

async function request(path, options) {
  return (await requireResponse(await fetch(path, options))).json();
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function inspect(record, message = "Selecciona un registro para examinarlo.", citation) {
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
  if (record.source_id) {
    const label = record.kind === "archivo HAR" ? "Entrada HAR" : record.code_review || record.dependencies || record.kind === "binario" ? "Archivo" : "ID";
    view.append(element("p", `${label} · ${record.source_id}`));
  }
  if (selectedRevision) {
    view.append(element("p", "Revisión citada " + record.revision));
  } else if (record.id && record.kind === "nota") {
    view.append(element("p", "Revisión " + record.revision));
  }
  if (selectedRevision || returnToEvidence) {
    const tools = element("div", "", "tools");
    if (selectedRevision) {
      const current = element("button", "Abrir revisión vigente");
      current.onclick = () => selectRecord(record.id, 0, returnToEvidence, selectedSTIXPage, citation);
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
    const details = element("dl", "", "http-details");
    for (const [label, value] of [["Captura", captureLabel(record.kind)], ["Método", item.method || "Sin método"],
      ["Estado", item.status || "Sin respuesta"], ["Tipo MIME", item.type || "Sin tipo"], ["Latencia", `${item.millis} ms`]]) {
      details.append(element("dt", label), element("dd", String(value)));
    }
    view.append(details);
    const signals = httpFindingPanel(record, citation?.http_rule);
    if (signals) view.append(signals);
  }
  if (record.code_review) view.append(codeReviewPanel(record.id, record.code_review, citation));
  if (record.dependencies) view.append(dependencyPanel(record.dependencies, citation));
  const binary = record.kind === "binario" && binaryPanel(record, citation?.binary, citation?.binaryWindow, citation?.binaryReferences);
  if (binary) view.append(binary);
  if (!record.code_review && !record.traffic && record.signals?.length) {
    const list = element("ul");
    for (const signal of record.signals) list.append(element("li", signal));
    view.append(list);
  }
  if (!record.code_review && !binary && record.details) view.append(element("pre", record.details));
  const linked = view.querySelector(".audit-cited");
  if (linked) {
    linked.focus({preventScroll: true});
    linked.scrollIntoView({block: "nearest"});
  }
}

function httpFindingPanel(record, citedRule) {
  const findings = record.http_findings || [];
  const shown = new Set(findings.map(({label}) => label));
  const previous = (record.signals || []).filter((label) => !shown.has(label));
  if (!findings.length && !previous.length) return null;
  const panel = element("div", "", "audit-panel");
  panel.append(element("h4", "Señales HTTP"));
  const listing = element("div", "", "audit-items");
  for (const finding of findings) {
    const row = element("div", "", "audit-item");
    row.dataset.httpRule = finding.rule;
    row.append(element("strong", finding.label), element("span", `${finding.header} · ${finding.rule}`, "type"),
      element("p", finding.observation));
    if (finding.rule === citedRule) {
      row.classList.add("audit-cited");
      row.tabIndex = -1;
    }
    listing.append(row);
  }
  panel.append(listing);
  if (previous.length) {
    const list = element("ul");
    list.append(...previous.map((label) => element("li", label)));
    panel.append(list);
  }
  return panel;
}

function binaryCitationURL({record_id, revision, kind, index}) {
  const query = new URLSearchParams({revision, tipo: kind, indice: index});
  return `/api/registro/${encodeURIComponent(record_id)}/cita-binaria?${query}`;
}

function download(content, filename) {
  const url = URL.createObjectURL(content);
  const link = element("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function binaryCitationButton(record, kind, index) {
  const button = element("button", "Exportar cita");
  button.onclick = async () => {
    button.disabled = true;
    try {
      const citation = await request(binaryCitationURL({record_id: record.id, revision: record.revision, kind, index}));
      download(new Blob([JSON.stringify(citation, null, 2) + "\n"], {type: "application/json"}), "PAVAROTTI-cita-binaria.json");
      byId("status").textContent = `Cita exportada · ${citation.offset} · rev. ${citation.revision}`;
    } catch (error) {
      byId("status").textContent = error.message;
    } finally {
      button.disabled = false;
    }
  };
  return button;
}

function markBinaryCitation(row, citation, kind, index) {
  if (citation?.kind === kind && citation.index === index) {
    row.classList.add("audit-cited");
    row.tabIndex = -1;
  }
}

function binaryPanel(record, citation, windowCitation, referenceReport) {
  let report;
  try {
    report = JSON.parse(record.details);
  } catch {
    return null;
  }
  if (report?.sha256 !== record.sha256 || !Number.isInteger(report?.size)) return null;
  const panel = element("div", "", "binary-panel");
  panel.append(element("p", `${report.format} · ${report.architecture || "Arquitectura sin identificar"} · ${report.size} bytes`));
  const fingerprint = element("button", "Consultar coincidencias SHA-256");
  fingerprint.onclick = () => selectAsset({type: "sha256", value: record.sha256});
  panel.append(fingerprint);

  const sections = Array.isArray(report.sections) ? report.sections : [];
  const images = Array.isArray(report.images) ? report.images : [];
  const count = report.section_count || sections.length;
  const names = element("details");
  const sectionTitle = element("summary");
  names.append(sectionTitle);
  names.open = citation?.kind === "seccion";
  const textHits = element("details");
  const hits = Array.isArray(report.strings) ? report.strings : [];
  const stringTitle = element("summary");
  textHits.append(stringTitle);
  textHits.open = citation?.kind === "cadena";
  const search = element("input");
  search.type = "search";
  search.placeholder = "Buscar texto o desplazamiento";
  search.setAttribute("aria-label", "Buscar cadenas ASCII");
  search.maxLength = 160;
  const scope = element("p");
  const reset = element("button", "Quitar filtro de sección");
  const strings = element("ol", "", "binary-list");
  let selectedSection;
  let selectedImage = 0;
  const imageInfo = element("p", "", "muted");
  function paintStrings() {
    const term = search.value.trim().toLowerCase();
    const range = selectedSection?.file || images[selectedImage - 1]?.file;
    const start = range ? Number.parseInt(range.offset, 16) : 0;
    const end = range ? start + range.size : report.size;
    const stored = hits.map((hit, index) => ({hit, index})).filter(({hit}) => {
      const offset = Number.parseInt(hit.offset, 16);
      return offset >= start && offset < end;
    });
    stringTitle.textContent = `Cadenas ASCII registradas · ${stored.length}`;
    const matching = stored.filter(({hit}) => hit.offset.toLowerCase().includes(term) || hit.text.toLowerCase().includes(term));
    scope.textContent = `${matching.length} ${matching.length === 1 ? "cadena" : "cadenas"}${selectedSection ? ` en ${selectedSection.name}` : ""}`;
    reset.hidden = !selectedSection;
    strings.replaceChildren(...matching.map(({hit, index}) => {
      const row = element("li");
      row.append(element("code", hit.offset, "type"), element("pre", hit.text), binaryCitationButton(record, "cadena", index));
      markBinaryCitation(row, citation, "cadena", index);
      return row;
    }));
  }
  reset.onclick = () => { selectedSection = undefined; paintStrings(); };
  search.oninput = paintStrings;
  textHits.append(search, reset, scope, strings);
  const sectionsList = element("ol", "", "binary-list");
  const noSections = element("p", "No hay secciones registradas.");
  const entries = binaryInstructionEntries(report.instructions, sections);
  const binaryWindow = ["ELF", "PE", "Mach-O", "Mach-O universal"].includes(report.format) ?
    binaryWindowPanel(report, record, windowCitation?.sha256 === record.sha256 ? windowCitation : undefined,
      referenceReport?.sha256 === record.sha256 ? referenceReport : undefined, inspectorRequest.signal, binaryReferenceIndex(entries),
      () => instructions.refreshIncoming?.()) : undefined;
  const instructions = binaryInstructionPanel(report, sections, images, {entries, citation,
    cite: (index) => binaryCitationButton(record, "instruccion", index), follow: binaryWindow?.followInstruction,
    incoming: binaryWindow?.incoming, openReference: binaryWindow?.openReference, exportReferences: binaryWindow?.exportReferences});
  const symbols = binarySymbolPanel(report, record, citation, images, binaryWindow?.openSymbol);
  function paintSections() {
    const rows = [];
    for (const [index, section] of sections.entries()) {
      if (selectedImage && section.image !== selectedImage) continue;
      const row = element("li");
      row.append(element("strong", section.name || "Sin nombre"), element("p",
        `${report.format === "PE" ? "RVA" : "Dirección"} ${section.address} · ${section.size} bytes`));
      if (section.image && !selectedImage) row.append(element("p", binaryImageLabel(images[section.image - 1]), "type"));
      if (section.file) {
        row.append(element("p", `Archivo ${section.file.offset} · ${section.file.size} bytes`));
        const pivot = element("button", "Cadenas de la sección");
        pivot.onclick = () => {
          selectedSection = section;
          search.value = "";
          textHits.open = true;
          paintStrings();
          search.focus();
        };
        const tools = element("div", "", "tools");
        if (instructions.hasSection(index)) {
          const listing = element("button", "Instrucciones de la sección");
          listing.onclick = () => instructions.showSection(index);
          tools.append(listing);
        }
        tools.append(pivot, binaryCitationButton(record, "seccion", index));
        row.append(tools);
      }
      markBinaryCitation(row, citation, "seccion", index);
      rows.push(row);
    }
    const total = selectedImage ? rows.length : count;
    sectionTitle.textContent = `Secciones · ${rows.length < total ? `${rows.length} de ${total}` : total}`;
    sectionsList.replaceChildren(...rows);
    sectionsList.hidden = !rows.length;
    noSections.hidden = !!rows.length;
  }
  function paintImage(index) {
    selectedImage = index;
    selectedSection = undefined;
    const image = images[index - 1];
    imageInfo.textContent = image ? `Archivo ${image.file.offset} · ${image.file.size} bytes` :
      `${images.length} ${images.length === 1 ? "imagen registrada" : "imágenes registradas"}`;
    paintSections();
    paintStrings();
    instructions.paintImage(index);
    binaryWindow?.paintImage(index);
    symbols.paint(index);
  }
  if (images.length) {
    const label = element("label", "Imagen Mach-O", "binary-image");
    const select = element("select");
    const all = element("option", "Todas las imágenes");
    all.value = "0";
    select.append(all);
    for (const [index, image] of images.entries()) {
      const option = element("option", binaryImageLabel(image));
      option.value = String(index + 1);
      select.append(option);
    }
    if (citation?.kind === "seccion") selectedImage = sections[citation.index]?.image || 0;
    if (citation?.kind === "simbolo") selectedImage = report.symbols?.[citation.index]?.image || 0;
    if (citation?.kind === "instruccion") selectedImage = sections[report.instructions?.[citation.index]?.section]?.image || 0;
    if (windowCitation?.image > 0 && windowCitation.image <= images.length) selectedImage = windowCitation.image;
    if (referenceReport?.image > 0 && referenceReport.image <= images.length) selectedImage = referenceReport.image;
    if (citation?.kind === "cadena") {
      const offset = Number.parseInt(hits[citation.index]?.offset, 16);
      selectedImage = images.findIndex(({file}) => {
        const start = Number.parseInt(file.offset, 16);
        return offset >= start && offset < start + file.size;
      }) + 1;
    }
    select.value = String(selectedImage);
    select.onchange = () => paintImage(Number(select.value));
    label.append(select);
    panel.append(label, imageInfo);
    if (report.unreadable_images) panel.append(element("p", `Imágenes ilegibles · ${report.unreadable_images}`));
  }
  names.append(sectionsList, noSections);
  paintImage(selectedImage);
  if (binaryWindow) panel.append(binaryWindow.details);
  panel.append(instructions.details, names, textHits, symbols.details);
  return panel;
}

function binaryImageLabel(image) {
  return image ? `${image.architecture} · subtipo ${image.subtype}` : "";
}

function binarySymbolPanel(report, record, citation, images, openWindow) {
  const symbols = Array.isArray(report.symbols) ? report.symbols : [];
  const details = element("details");
  const title = element("summary", `Símbolos · ${symbols.length}`);
  details.append(title);
  details.open = citation?.kind === "simbolo";
  if (report.symbols_limited) details.append(element("p", "La inspección alcanzó su límite de símbolos."));
  if (!symbols.length) {
    details.append(element("p", "Este registro no contiene símbolos guardados."));
    return {details, paint() {}};
  }
  const search = element("input");
  search.type = "search";
  search.placeholder = "Buscar nombre, ordinal o dirección";
  search.setAttribute("aria-label", "Buscar símbolos");
  search.maxLength = 256;
  const count = element("p");
  const list = element("ol", "", "binary-list");
  const more = element("button", "Mostrar más símbolos");
  let imageIndex = 0;
  let matching = [];
  let shown = 0;
  function appendRows() {
    const batch = matching.slice(shown, shown + 50);
    for (const {symbol, index} of batch) {
      const row = element("li");
      const address = report.format === "PE" ? `RVA ${symbol.address}` : symbol.address;
      const ordinal = Number.isInteger(symbol.ordinal) && `Ordinal ${symbol.ordinal}`;
      row.append(element("strong", symbol.name), element("p", [symbol.kind, ordinal, symbol.section, address].filter(Boolean).join(" · ")));
      if (symbol.image && !imageIndex) row.append(element("p", binaryImageLabel(images[symbol.image - 1]), "type"));
      if (symbol.forwarder) row.append(element("p", `Reenvío · ${symbol.forwarder}`));
      if (symbol.offset) row.append(element("p", `Archivo ${symbol.offset}`), binaryCitationButton(record, "simbolo", index));
      if (symbol.offset && !symbol.forwarder && openWindow) {
        const window = element("button", "Abrir ventana");
        window.onclick = () => openWindow(index);
        row.append(window);
      }
      markBinaryCitation(row, citation, "simbolo", index);
      list.append(row);
    }
    shown += batch.length;
    more.hidden = shown >= matching.length;
    count.textContent = `${shown} de ${matching.length} símbolos`;
  }
  function paint(index) {
    imageIndex = index;
    const term = search.value.trim().toLowerCase();
    const inImage = symbols.map((symbol, index) => ({symbol, index})).filter(({symbol}) => !imageIndex || symbol.image === imageIndex);
    title.textContent = `Símbolos · ${inImage.length}`;
    matching = inImage.filter(({symbol}) => [symbol.name, symbol.kind, symbol.section, symbol.address, symbol.offset, symbol.forwarder,
      Number.isInteger(symbol.ordinal) ? `Ordinal ${symbol.ordinal}` : undefined].some((field) => field?.toLowerCase().includes(term)));
    if (citation?.kind === "simbolo") {
      const target = matching.findIndex(({index}) => index === citation.index);
      if (target > 0) matching.unshift(...matching.splice(target, 1));
    }
    shown = 0;
    list.replaceChildren();
    appendRows();
  }
  search.oninput = () => paint(imageIndex);
  more.onclick = appendRows;
  details.append(search, count, list, more);
  return {details, paint};
}

function codeReviewPanel(id, review, citation) {
  const view = element("div", "", "audit-panel");
  const signals = review.signals || [];
  const count = review.total || signals.length;
  view.append(element("h4", "Revisión estática"), element("p", signals.length < count ?
    `${signals.length} de ${count} señales registradas` : `${count} ${count === 1 ? "señal" : "señales"}`));
  const list = element("div", "", "audit-items");
  const badges = new Map();
  for (const signal of signals) {
    const row = element("div", "", "audit-item");
    row.dataset.rule = signal.rule;
    row.dataset.line = signal.line;
    row.dataset.column = signal.column;
    row.tabIndex = -1;
    if (citation?.line === signal.line && citation.column === signal.column && citation.name === signal.rule) {
      row.classList.add("audit-cited");
    }
    row.append(element("strong", `Línea ${signal.line}, columna ${signal.column}`),
      element("span", signal.rule, "type"), element("p", signal.review));
    const tools = element("div", "", "triage-controls");
    const action = element("button", canWrite ? "Clasificar" : "Ver historial");
    action.setAttribute("aria-label", `${canWrite ? "Clasificar señal" : "Ver historial de señal"} ${signal.rule}, línea ${signal.line}, columna ${signal.column}`);
    const badge = element("span", "Pendiente", "muted");
    badges.set(findingKey(signal), badge);
    action.onclick = () => openCodeTriage(id, signal, badge);
    tools.append(action, badge);
    row.append(tools);
    list.append(row);
  }
  view.append(list);
  if (badges.size) loadCodeBadges(id, badges, inspectorRequest.signal);
  if (review.imports?.length) {
    const imports = element("details");
    imports.append(element("summary", `Importaciones Go · ${review.imports.length}`));
    const modules = element("ul");
    let offset = 0;
    const more = element("button", "Mostrar más importaciones");
    more.onclick = () => {
      const batch = review.imports.slice(offset, offset + 100);
      modules.append(...batch.map((name) => element("li", name)));
      offset += batch.length;
      more.hidden = offset >= review.imports.length;
    };
    imports.append(modules, more);
    imports.ontoggle = () => { if (imports.open && !offset) more.onclick(); };
    view.append(imports);
  }
  return view;
}

function triagePath(id) { return `/api/registro/${encodeURIComponent(id)}/triaje`; }

function updateTriageBadge(badge, entry) {
  if (badge && entry.revision >= Number(badge.dataset.revision || 0)) {
    badge.dataset.revision = entry.revision;
    badge.textContent = triageLabels[entry.status];
  }
}

async function loadCodeBadges(id, badges, signal) {
  try {
    const entries = await request(triagePath(id), {signal});
    for (const entry of entries) updateTriageBadge(badges.get(findingKey(entry)), entry);
  } catch (error) {
    if (!signal.aborted) byId("status").textContent = error.message;
  }
}

function paintTriageHistory(history) {
  const list = byId("triage-entries");
  const more = byId("triage-more");
  list.replaceChildren();
  if (!history.length) list.append(element("li", "Sin clasificaciones registradas."));
  let end = history.length;
  more.onclick = () => {
    const start = Math.max(0, end - 25);
    const entries = history.slice(start, end).reverse();
    for (const entry of entries) {
      const item = element("li");
      item.append(element("strong", `Rev. ${entry.revision} · ${triageLabels[entry.status]} · ${formatTime(entry.time)}`),
        element("p", entry.reason));
      list.append(item);
    }
    end = start;
    more.hidden = end === 0;
  };
  more.onclick();
}

async function openCodeTriage(id, signal, badge) {
  const dialog = byId("triage-panel");
  const errorText = byId("triage-error");
  const button = byId("triage-save");
  const action = {id, badge, key: {rule: signal.rule, line: signal.line, column: signal.column}};
  activeTriage = action;
  button.disabled = true;
  byId("triage-form").reset();
  byId("triage-title").textContent = canWrite ? "Clasificar señal" : "Historial de la señal";
  byId("triage-form").hidden = !canWrite;
  byId("triage-read-close").hidden = canWrite;
  byId("triage-history").open = !canWrite;
  byId("triage-location").textContent = `${signal.rule} · línea ${signal.line}, columna ${signal.column}`;
  errorText.textContent = "Consultando clasificación…";
  paintTriageHistory([]);
  dialog.showModal();
  const params = new URLSearchParams({regla: signal.rule, linea: signal.line, columna: signal.column});
  try {
    const history = await request(triagePath(id) + "?" + params);
    if (activeTriage !== action || !dialog.open) return;
    const last = history.at(-1);
    if (last) updateTriageBadge(badge, last);
    action.revision = last?.revision || 0;
    byId("triage-state").value = last?.status || "pendiente";
    paintTriageHistory(history);
    errorText.textContent = "";
    button.disabled = false;
  } catch (error) {
    if (activeTriage === action && dialog.open) errorText.textContent = error.message;
  }
}

byId("triage-close").onclick = () => byId("triage-panel").close();
byId("triage-form").onsubmit = async (event) => {
  event.preventDefault();
  const action = activeTriage;
  if (!canWrite || !Number.isInteger(action?.revision)) return;
  const button = byId("triage-save");
  button.disabled = true;
  byId("triage-error").textContent = "";
  try {
    const saved = await request(triagePath(action.id), {
      method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({
        ...action.key, revision: action.revision, status: byId("triage-state").value, reason: byId("triage-reason").value
      })
    });
    updateTriageBadge(action.badge, saved);
    if (activeTriage === action) byId("triage-panel").close();
    byId("status").textContent = "Clasificación guardada";
  } catch (error) {
    if (activeTriage === action) byId("triage-error").textContent = error.message;
  } finally {
    if (activeTriage === action) button.disabled = false;
  }
};

function dependencyPanel(inventory, citation) {
  const view = element("div", "", "audit-panel");
  const entries = inventory.entries || [];
  view.append(element("h4", "Inventario de dependencias"), element("p", `${entries.length} ${entries.length === 1 ? "entrada" : "entradas"}`));
  if (inventory.skipped) view.append(element("p", `Entradas fuera del esquema admitido · ${inventory.skipped}`));
  if (!entries.length) return view;
  const search = element("input");
  search.type = "search";
  search.placeholder = "Buscar dependencia";
  search.setAttribute("aria-label", "Buscar dependencia en el manifiesto");
  const list = element("div", "", "audit-items");
  const more = element("button", "Mostrar más dependencias");
  const all = element("button", "Ver todas las dependencias");
  let linked = citation && entries.find((entry) => entry.name === citation.name &&
    (citation.location ? entry.location === citation.location : entry.line === citation.line));
  let results = linked ? [linked] : entries;
  all.hidden = !linked;
  let offset = 0;
  const next = () => {
    for (const entry of results.slice(offset, offset + 50)) {
      const row = element("div", "", "audit-item");
      row.tabIndex = -1;
      row.dataset.name = entry.name;
      row.dataset.line = entry.line || "";
      row.dataset.location = entry.location || "";
      if (entry === linked) row.classList.add("audit-cited");
      row.append(element("strong", entry.version ? `${entry.name} · ${entry.version}` : entry.name), element("span", entry.scope, "type"));
      if (entry.line) row.append(element("p", "Línea " + entry.line));
      if (entry.location) row.append(element("p", entry.location));
      if (entry.installed_as) row.append(element("p", "Instalado como · " + entry.installed_as));
      if (entry.integrity) row.append(element("p", "Integridad declarada · " + entry.integrity));
      if (entry.replacement) {
        const r = entry.replacement;
        const label = r.local ? "Ruta local" : `${r.name} · ${r.version}`;
        row.append(element("p", `Reemplazo · ${label}${r.line ? ` · línea ${r.line}` : ""}`));
      }
      list.append(row);
    }
    offset += 50;
    more.hidden = offset >= results.length;
  };
  search.oninput = () => {
    linked = undefined;
    all.hidden = true;
    const query = search.value.trim().toLowerCase();
    results = entries.filter((entry) => [entry.name, entry.version, entry.installed_as, entry.replacement?.name,
      entry.replacement?.version].some((value) => value?.toLowerCase().includes(query)));
    offset = 0;
    list.replaceChildren();
    if (!results.length) list.append(element("p", "Sin dependencias para mostrar."));
    next();
  };
  more.onclick = next;
  all.onclick = () => {
    search.value = "";
    search.oninput();
    search.focus();
  };
  next();
  view.append(search, list, more, all);
  return view;
}

function selectRecord(id, revision = 0, back, stixPage, citation) {
  selectedAsset = undefined;
  selectedSTIXPage = stixPage;
  returnToEvidence = back;
  selectedKey = id;
  selectedRevision = revision;
  paintSelection();
  if (revision || back) byId("inspector-heading").focus({preventScroll: true});
  return loadRecord(id, true, citation);
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

async function loadRecord(id, scroll = false, citation) {
  const controller = beginInspection("Consultando evidencia…");
  if (scroll && (selectedRevision || window.matchMedia("(max-width: 970px)").matches)) {
    byId("inspector").scrollIntoView({block: "nearest"});
  }
  try {
    const query = selectedRevision ? "?revision=" + selectedRevision : "";
    const record = await request("/api/registro/" + encodeURIComponent(id) + query, {signal: controller.signal});
    if (!controller.signal.aborted) inspect(record, undefined, citation);
  } catch (error) {
    if (!controller.signal.aborted) inspect(undefined, error.message);
  }
}

function selectAsset(asset, after = "") {
  selectedKey = "";
  selectedRevision = 0;
  returnToEvidence = undefined;
  selectedAsset = {type: asset.type, value: asset.value, after, back: asset.back, networkAfter: asset.networkAfter};
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
    if (!controller.signal.aborted) inspectAsset(detail, asset, controller.signal);
  } catch (error) {
    if (!controller.signal.aborted) inspect(undefined, error.message);
  }
}

function assetEvidenceButton(reference, back, beforeSelect) {
  const button = element("button");
  const labels = [reference.kind, reference.role, `rev. ${reference.revision}`].filter(Boolean);
  button.append(element("strong", reference.title || reference.kind), element("span", labels.join(" · "), "type"));
  if (reference.network && reference.title !== "Red · " + reference.network) {
    button.append(element("span", reference.network, "muted"));
  }
  if (reference.time) button.append(element("span", formatTime(reference.time), "muted"));
  button.onclick = () => {
    beforeSelect?.();
    selectRecord(reference.id, reference.revision, back);
  };
  return button;
}

function inspectAsset(detail, asset, signal) {
  const list = element("div", "", "asset-sources");
  list.append(...detail.rows.map((reference) => assetEvidenceButton(reference, {
    label: "Volver al activo", open: () => selectAsset(asset, asset.after)
  })));
  const actions = element("div", "", "tools");
  const report = element("button", "Cobertura por periodo");
  report.onclick = () => openAssetCoverage(detail);
  actions.append(report);
  if (asset.back) {
    const back = element("button", asset.back.label);
    back.onclick = asset.back.open;
    actions.append(back);
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
    element("p", assetCount(detail)), actions, list, controls);
  if (detail.coverage) list.before(element("p", `Cobertura de red · ${detail.coverage}`));
  if (detail.type === "red") list.before(assetNetworkPanel({...asset, value: detail.value}, signal));
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
    row.append(element("span", `${traffic.method} ${traffic.status || "Sin respuesta"}`, "type"),
      element("strong", record.source || record.title));
    const details = [captureLabel(record.kind), formatTime(record.time), traffic.type || "Sin tipo MIME", traffic.millis + " ms"];
    if (record.signal_count) details.push(`${record.signal_count} ${record.signal_count === 1 ? "señal" : "señales"}`);
    row.append(element("span", details.join(" · "), "muted"));
  } else {
    row.append(element("span", record.kind, "type"), element("strong", record.title));
    const source = record.source || record.source_id;
    if (source) row.append(element("span", source, "muted"));
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
  const view = views[currentView];
  const type = view.kind ?? byId(view.filter).value;
  const params = new URLSearchParams({tipo: type, buscar: byId("query").value.trim()});
  if (currentView === "http") {
    for (const [id, name] of Object.entries(httpFilters)) {
      if (byId(id).value) params.set(name, byId(id).value);
    }
  }
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
for (const id of ["filter", "filter-asset", ...Object.keys(httpFilters)]) {
  byId(id).addEventListener("change", () => {
    clearTimeout(searchTimer);
    loadPage(0, [""]);
  });
}
function showView(view) {
  if (currentView === view) return;
  const query = byId("query");
  viewSearch.set(currentView, query.value);
  currentView = view;
  clearTimeout(searchTimer);
  for (const name of Object.keys(views)) {
    byId("view-" + name).setAttribute("aria-pressed", String(name === view));
  }
  byId("filter").hidden = view !== "records";
  byId("filter-asset").hidden = view !== "assets";
  byId("open-asset-coverage").hidden = view !== "assets";
  byId("open-binary-citation").hidden = view !== "binaries";
  byId("http-filters").hidden = view !== "http";
  query.placeholder = views[view].placeholder;
  query.maxLength = view === "assets" ? 253 : 256;
  query.value = viewSearch.get(view) || "";
  byId("records").replaceChildren();
  loadPage(0, [""]);
}
for (const view of Object.keys(views)) byId("view-" + view).onclick = () => showView(view);
byId("refresh").addEventListener("click", () => refresh());

byId("open-binary-citation").onclick = () => byId("binary-citation-file").click();
byId("binary-citation-file").onchange = async (event) => {
  const input = event.currentTarget;
  const file = input.files[0];
  if (!file) return;
  const button = byId("open-binary-citation");
  const status = byId("status");
  button.disabled = true;
  try {
    if (file.size > binaryReferenceReportBytes) throw new Error("El informe supera los 4 MiB");
    const citation = JSON.parse(await file.text());
    const referenceReport = citation?.schema === binaryReferenceReportSchema;
    if (!referenceReport && file.size > 4096) throw new Error("El archivo de cita supera los 4 KiB");
    if (typeof citation?.record_id !== "string" ||
      !/^[a-f0-9]{64}-[1-9][0-9]*$/.test(citation.record_id) || !Number.isSafeInteger(citation.revision) ||
      citation.revision < 1 || (!referenceReport && (!Number.isSafeInteger(citation.index) || citation.index < 0))) {
      throw new Error("El archivo no contiene una cita o un informe de binario válido");
    }
    if (referenceReport && (!Array.isArray(citation.origins) || !citation.origins.length ||
      !Number.isSafeInteger(citation.image) || citation.image < 0 || !/^[a-f0-9]{64}$/.test(citation.report_sha256))) {
      throw new Error("El archivo no contiene un informe de referencias válido");
    }
    if (referenceReport || (citation.schema === binaryWindowSchema && validBinaryWindowCitation(citation))) {
      const link = referenceReport ? {binaryReferences: citation} : {binaryWindow: citation};
      await selectRecord(citation.record_id, citation.revision, undefined, undefined, link);
      if (selectedRecord?.id !== citation.record_id || selectedRecord.revision !== citation.revision ||
        selectedRecord.kind !== "binario" || selectedRecord.sha256 !== citation.sha256) {
        throw new Error("La cita o el informe no coincide con una revisión de binario en este expediente.");
      }
      status.textContent = "";
      return;
    }
    if (citation.schema !== "pavarotti.binary-citation.v1" || !["seccion", "cadena", "simbolo", "instruccion"].includes(citation.kind)) {
      throw new Error("El archivo no contiene una cita de binario válida");
    }
    const verified = await request(binaryCitationURL(citation));
    if (Object.entries(verified).some(([key, value]) => citation[key] !== value)) {
      throw new Error("La cita no coincide con la huella, revisión o desplazamiento del expediente");
    }
    await selectRecord(verified.record_id, verified.revision, undefined, undefined, {binary: verified});
    status.textContent = `Cita verificada · ${verified.offset} · rev. ${verified.revision}`;
  } catch (error) {
    status.textContent = error instanceof SyntaxError ? "El archivo de cita contiene JSON inválido" : error.message;
  } finally {
    input.value = "";
    button.disabled = false;
  }
};

byId("directory-form").onsubmit = async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const status = byId("status");
  const resultView = byId("directory-result");
  const input = byId("directory-files");
  const payload = new FormData();
  let count = 0;
  let bytes = 0;
  resultView.hidden = true;
  for (const file of input.files) {
    const folders = file.webkitRelativePath.split("/").slice(1);
    if (!folders.length || folders.some((part) => [".git", "node_modules", "vendor"].includes(part.toLowerCase()))) continue;
    if (!/(?:\.go$|^(?:go\.mod|package-lock\.json)$)/i.test(file.name)) continue;
    payload.append(encodeURIComponent(folders.join("/")), file, file.name);
    count++;
    bytes += file.size;
  }
  if (!count || count > 200 || bytes > 32 * 1024 * 1024) {
    status.textContent = !count ? "La selección requiere archivos Go, go.mod o package-lock.json." : "Selecciona hasta 200 archivos compatibles y 32 MiB.";
    return;
  }
  button.disabled = true;
  status.textContent = "Revisando directorio…";
  try {
    const response = await fetch("/api/revision/directorio", {method: "POST", body: payload});
    if (!response.headers.get("Content-Type")?.startsWith("application/json")) await requireResponse(response);
    const result = await response.json();
    if (result.files?.length) {
      const rows = result.files.map((file) => element("li", `${file.path} · ${file.status}${file.reason ? " · " + file.reason : ""}`));
      byId("directory-items").replaceChildren(...rows);
      resultView.hidden = false;
      resultView.open = Boolean(result.rejected);
      if (response.ok) input.value = "";
      await refresh(result.message, true);
    } else {
      status.textContent = result.message;
    }
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

byId("export-stix").onclick = async (event) => {
  const button = event.currentTarget;
  const status = byId("status");
  button.disabled = true;
  status.textContent = "Preparando paquete STIX…";
  try {
    const response = await requireResponse(await fetch("/api/exportar/stix"));
    download(await response.blob(), "PAVAROTTI-STIX.json");
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
      {method: "POST", body: selected, headers: {
        "Content-Type": "application/octet-stream", "X-Pavarotti-Filename": encodeURIComponent(selected.name)
      }});
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
  ["code_findings", "Revisión estática"], ["dependencies", "Dependencias"],
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
        const location = item.location || item.http_rule;
        const position = item.line ? ` · línea ${item.line}${item.column ? `, columna ${item.column}` : ""}` : location ? ` · ${location}` : "";
        const label = (item.kind === "código" || item.kind === "dependencias") && item.source_id ? item.source_id : (item.title || item.kind);
        const action = element("button", `${label} · rev. ${item.revision}${position}`);
        action.title = `${item.id} · revisión ${item.revision}`;
        action.onclick = () => {
          byId("report-panel").close();
          selectRecord(item.id, item.revision, {
            label: "Volver al informe", open: () => byId("report-panel").showModal()
          }, undefined, position ? {...item, name: value} : undefined);
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

const activityLabels = {
  "evidencia.incorporada": "Evidencia incorporada", "nota.creada": "Nota registrada", "nota.editada": "Nota editada",
  "expediente.migrado": "Expediente migrado",
  "expediente.restaurado": "Expediente restaurado",
  "actividad.retencion": "Retención de actividad aplicada",
  "senal.clasificada": "Señal clasificada", "tarea.encolada": "Tarea encolada", "tarea.priorizada": "Prioridad cambiada",
  "tarea.iniciada": "Tarea iniciada", "tarea.finalizada": "Tarea finalizada", "tarea.cancelada": "Tarea cancelada"
};
let activityRequest;

function activityEntry(event) {
  const row = element("li", "", "activity-entry");
  const text = element("div");
  const details = event.details;
  const source = event.source === "sesion" ? "Sesión" : "Rol de PostgreSQL";
  text.append(element("strong", activityLabels[event.action] || event.action),
    element("p", `${formatTime(event.time)} · ${source} · ${event.actor}`));
  const context = [];
  if (details.count > 1 || (details.count && event.action === "expediente.migrado")) context.push(`${details.count} ${details.count === 1 ? "registro" : "registros"}`);
  if (details.note_revisions) context.push(`${details.note_revisions} ${details.note_revisions === 1 ? "revisión de nota" : "revisiones de notas"}`);
  if (details.triage_revisions) context.push(`${details.triage_revisions} ${details.triage_revisions === 1 ? "decisión" : "decisiones"} de triaje`);
  if (details.removed_events) context.push(`${details.removed_events} ${details.removed_events === 1 ? "evento retirado" : "eventos retirados"}`);
  if (details.retention_before) context.push(`Antes del ${details.retention_before.slice(0, 10)} UTC`);
  if (details.backup_sha256) context.push(`SHA-256 ${details.backup_sha256}`);
  if (details.finding) {
    const {rule, line, column} = details.finding;
    context.push(`${rule} · línea ${line}, columna ${column} · decisión ${details.revision}`);
  } else if (details.revision) context.push(`Revisión ${details.revision}`);
  if (details.status) context.push(jobLabels[details.status] || triageLabels[details.status] || details.status);
  if (details.priority !== undefined) context.push(`Prioridad ${priorityLabels[details.priority]}`);
  if (details.attempt) context.push(`Intento ${details.attempt}`);
  if (context.length) text.append(element("p", context.join(" · ")));
  row.append(text);
  if (!event.target) return row;
  const isQueue = event.action.startsWith("tarea.");
  const open = element("button", isQueue ? "Abrir tarea" : "Abrir evidencia");
  open.onclick = () => {
    byId("activity-panel").close();
    if (isQueue) {
      showAnalysisJob(event.target);
      return;
    }
    const finding = details.finding;
    const citation = finding && {name: finding.rule, line: finding.line, column: finding.column};
    selectRecord(event.target, finding ? 1 : details.revision || 1, undefined, undefined, citation);
  };
  row.append(open);
  return row;
}

async function loadActivity(before = 0) {
  activityRequest?.abort();
  const controller = new AbortController();
  activityRequest = controller;
  const status = byId("activity-status");
  const more = byId("activity-more");
  const list = byId("activity-list");
  if (!before) list.replaceChildren();
  status.textContent = "Consultando actividad…";
  more.disabled = true;
  try {
    const page = await request(`/api/actividad?antes=${before}`, {signal: controller.signal});
    if (controller.signal.aborted) return;
    list.append(...page.events.map(activityEntry));
    status.textContent = list.children.length ? "" : "Todavía no hay actividad registrada.";
    more.hidden = !page.next;
    more.onclick = () => loadActivity(page.next);
  } catch (error) {
    if (!controller.signal.aborted) status.textContent = error.message;
  } finally {
    if (activityRequest === controller) more.disabled = false;
  }
}

byId("open-activity").onclick = () => {
  byId("activity-more").hidden = true;
  byId("activity-panel").showModal();
  loadActivity();
};
byId("activity-panel").addEventListener("close", () => activityRequest?.abort());

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
  } else if (canWrite && (job.state === "queued" || job.state === "running")) {
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
byId("logout").onclick = async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await requireResponse(await fetch("/api/acceso/salir", {method: "POST"}));
    window.location.replace("/ingresar");
  } catch (error) {
    byId("status").textContent = error.message;
    button.disabled = false;
  }
};
Promise.all([request("/api/app"), request("/credits.json"), request("/api/http/reglas")]).then(([app, credits, rules]) => {
  const ruleFilter = byId("filter-http-rule");
  for (const rule of rules) {
    const option = element("option", rule.label);
    option.value = rule.rule;
    ruleFilter.append(option);
  }
  canWrite = !app.shared || app.account?.role === "analista";
  for (const id of ["evidence-tools", "analyze", "add-note", "edit-note", "analysis-priority-label"]) byId(id).hidden = !canWrite;
  if (app.case) byId("case-heading").textContent = app.case;
  if (app.shared) {
    byId("account").textContent = `${app.account.name} · ${app.account.role}`;
    byId("account").hidden = false;
    byId("logout").hidden = false;
  }
  analysisQueue = app.analysis_queue;
  byId("open-activity").hidden = !app.activity;
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
    const reference = element("a", "Referencia técnica");
    reference.href = credit.reference;
    reference.target = "_blank";
    reference.rel = "noopener noreferrer";
    reference.setAttribute("aria-label", `Referencia técnica de ${credit.name}`);
    row.append(link, element("p", credit.detail), reference);
    byId("references").append(row);
  }
  return refresh();
}).catch((error) => {
  byId("proxy-status").textContent = "No se pudo leer la configuración";
  byId("status").textContent = error.message;
});
