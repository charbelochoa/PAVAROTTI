"use strict";

const binarySectionComparisonTools = (() => {
  const dialog = byId("binary-section-comparison");
  const form = byId("binary-section-comparison-form");
  const status = byId("binary-section-comparison-status");
  const rows = byId("binary-section-comparison-rows");
  const totals = byId("binary-section-comparison-totals");
  const result = byId("binary-section-comparison-result");
  const differences = byId("binary-section-differences");
  const exportButton = byId("binary-section-comparison-export");
  const cancelButton = byId("binary-section-comparison-cancel");
  const pager = byId("binary-section-comparison-pager");
  const previous = byId("binary-section-comparison-previous");
  const next = byId("binary-section-comparison-next");
  const pageLabel = byId("binary-section-comparison-page");
  const submit = form.querySelector("button[type=submit]");
  const maxBytes = 32 * 1024 * 1024;
  const pageSize = 30;
  const states = {igual: "Igual", movida: "Movida", modificada: "Modificada",
    agregada: "Agregada", ausente: "Ausente del binario actual", ambigua: "Emparejamiento ambiguo"};
  const changes = {direccion: "Dirección", desplazamiento: "Desplazamiento",
    tamano_declarado: "Tamaño declarado", tamano_fisico: "Tamaño físico", respaldo_fisico: "Respaldo físico", contenido: "Contenido"};
  let baseline;
  let view;
  let pending;

  function finish(controller) {
    if (pending !== controller) return;
    pending = undefined;
    submit.disabled = false;
    cancelButton.hidden = true;
  }

  function stop(message) {
    if (!pending) return;
    const controller = pending;
    controller.abort();
    finish(controller);
    status.textContent = message;
  }

  function clearResult() {
    result.hidden = true;
    exportButton.hidden = true;
    status.textContent = "";
    rows.replaceChildren();
  }

  function show(snapshot) {
    if (view !== snapshot) {
      stop("");
      view = snapshot;
      form.reset();
      clearResult();
      byId("binary-section-base").textContent = snapshot.baseline.name;
      byId("binary-section-current").textContent = snapshot.current.name;
      differences.checked = snapshot.differences;
      if (snapshot.report) render();
    }
    if (!dialog.open) dialog.showModal();
  }

  function sideEntries(entries, source, title, snapshot, name) {
    const side = element("div");
    side.append(element("strong", title));
    if (!entries.length) side.append(element("p", "Sin sección con esta identidad.", "muted"));
    for (const entry of entries) {
      const item = element("article");
      item.append(element("p", `Dirección ${entry.address} · ${entry.size} bytes declarados`));
      if (entry.file) {
        item.append(element("p", `Archivo ${entry.file.offset} · ${entry.file.size} bytes`), element("code", `SHA-256 ${entry.sha256}`, "muted"));
      } else {
        item.append(element("p", "Sin intervalo de archivo verificado.", "muted"));
      }
      const open = element("button", `Abrir sección ${title.toLowerCase()}`);
      open.setAttribute("aria-label", `Abrir sección ${title.toLowerCase()} ${name} en ${entry.address}`);
      open.onclick = () => {
        dialog.close();
        const back = {label: "Volver a comparar secciones", open: () => {
          show(snapshot);
          if (open.isConnected) open.focus();
        }};
        const binary = entry.citation || {kind: "seccion", index: entry.index};
        selectRecord(source.record_id, source.revision, back, undefined, {binary});
      };
      const tools = element("div", "", "tools");
      tools.append(open);
      item.append(tools);
      side.append(item);
    }
    return side;
  }

  function render() {
    const snapshot = view;
    const {report} = snapshot;
    const counts = {igual: 0, movida: 0, modificada: 0, agregada: 0, ausente: 0, ambigua: 0};
    for (const row of report.rows) counts[row.state]++;
    totals.textContent = `Iguales ${counts.igual} · Movidas ${counts.movida} · Modificadas ${counts.modificada} · Agregadas ${counts.agregada} · Ausentes ${counts.ausente} · Ambiguas ${counts.ambigua}`;
    const visible = snapshot.differences ? report.rows.filter((row) => row.state !== "igual") : report.rows;
    const pages = Math.max(1, Math.ceil(visible.length / pageSize));
    snapshot.page = Math.min(snapshot.page, pages - 1);
    const start = snapshot.page * pageSize;
    rows.replaceChildren(...visible.slice(start, start + pageSize).map((row) => {
      const item = element("li");
      const name = row.name || "Sin nombre";
      const architecture = row.subtype ? `${row.architecture} · subtipo ${row.subtype}` : row.architecture;
      item.append(element("span", states[row.state], "type"), element("p", name), element("p", architecture, "muted"));
      if (row.changes?.length) item.append(element("p", row.changes.map((change) => changes[change]).join(" · ")));
      const sides = element("div", "", "binary-section-sides");
      sides.append(sideEntries(row.baseline, report.baseline, "Base", snapshot, name),
        sideEntries(row.current, report.current, "Actual", snapshot, name));
      item.append(sides);
      return item;
    }));
    if (!visible.length) rows.append(element("li", snapshot.differences ? "Sin diferencias registradas." : "Sin secciones registradas."));
    pager.hidden = pages <= 1;
    previous.disabled = snapshot.page === 0;
    next.disabled = snapshot.page + 1 >= pages;
    pageLabel.textContent = `Página ${snapshot.page + 1} de ${pages}`;
    status.textContent = "Archivos originales verificados";
    result.hidden = false;
    exportButton.hidden = false;
  }

  form.onchange = () => {
    stop("");
    view.report = undefined;
    clearResult();
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    stop("");
    clearResult();
    const snapshot = view;
    snapshot.report = undefined;
    snapshot.page = 0;
    const original = form.elements.archivo_base.files[0];
    const current = form.elements.archivo_actual.files[0];
    if (!original || !current) return;
    if (original.size > maxBytes || current.size > maxBytes) {
      status.textContent = "Cada archivo admite hasta 32 MiB.";
      return;
    }
    const body = new FormData();
    body.append("seleccion", JSON.stringify({baseline: snapshot.baseline.target, current: snapshot.current.target}));
    body.append("archivo_base", original);
    body.append("archivo_actual", current);
    const controller = new AbortController();
    pending = controller;
    const {signal} = controller;
    submit.disabled = true;
    cancelButton.hidden = false;
    status.textContent = "Verificando ambos archivos y sus secciones…";
    try {
      const report = await request("/api/secciones-binarias/comparar", {method: "POST", body, signal});
      if (!signal.aborted) {
        snapshot.report = report;
        render();
      }
    } catch (error) {
      if (!signal.aborted) status.textContent = error.message;
    } finally {
      finish(controller);
    }
  };
  differences.onchange = () => {
    view.differences = differences.checked;
    view.page = 0;
    render();
  };
  previous.onclick = () => { view.page--; render(); };
  next.onclick = () => { view.page++; render(); };
  cancelButton.onclick = () => {
    stop("Verificación cancelada.");
    submit.focus();
  };
  exportButton.onclick = () => {
    const data = JSON.stringify(view.report, null, 2) + "\n";
    download(new Blob([data], {type: "application/json"}), "PAVAROTTI-comparacion-secciones.json");
  };
  dialog.addEventListener("close", () => { if (!dialog.open) stop(""); });

  return (record) => {
    const candidate = {target: {record_id: record.id, revision: record.revision}, name: record.source_id || record.title};
    const controls = element("div");
    const actions = element("div", "", "tools");
    const choose = element("button");
    const compare = element("button", "Comparar secciones");
    const selected = element("p", "", "muted");
    const isBase = () => baseline?.target.record_id === record.id && baseline.target.revision === record.revision;
    function update() {
      choose.textContent = isBase() ? "Quitar base de comparación" : "Usar como base";
      compare.disabled = !baseline || isBase();
      selected.textContent = baseline ? `Base de comparación · ${baseline.name}` : "";
    }
    choose.onclick = () => {
      baseline = isBase() ? undefined : candidate;
      update();
    };
    compare.onclick = () => show({baseline, current: candidate, differences: true, page: 0});
    update();
    actions.append(choose, compare);
    controls.append(actions, selected);
    return controls;
  };
})();
