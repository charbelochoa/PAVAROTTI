"use strict";

{
  const dialog = byId("binary-reference-comparison");
  const form = byId("binary-reference-comparison-form");
  const run = byId("binary-reference-comparison-run");
  const cancel = byId("binary-reference-comparison-cancel");
  const status = byId("binary-reference-comparison-status");
  const result = byId("binary-reference-comparison-result");
  const destination = byId("binary-reference-comparison-destination");
  const totals = byId("binary-reference-comparison-totals");
  const filter = byId("binary-reference-comparison-filter");
  const list = byId("binary-reference-comparison-rows");
  const pager = byId("binary-reference-comparison-pager");
  const previous = byId("binary-reference-comparison-previous");
  const next = byId("binary-reference-comparison-next");
  const pageLabel = byId("binary-reference-comparison-page");
  const exportButton = byId("binary-reference-comparison-export");
  const pageSize = 30;
  const labels = {comun: "Común", agregado: "Agregado", ausente: "Ausente del informe actual"};
  let pending;
  let verified;
  let page = 0;

  byId("open-binary-reference-comparison").onclick = () => dialog.showModal();

  function finish(controller) {
    if (pending !== controller) return;
    pending = undefined;
    run.disabled = false;
    cancel.hidden = true;
  }

  function stop(message) {
    if (!pending) return;
    const controller = pending;
    controller.abort();
    finish(controller);
    status.textContent = message;
  }

  cancel.onclick = () => {
    stop("Verificación cancelada.");
    run.focus();
  };
  dialog.addEventListener("close", () => {
    if (!dialog.open) stop("");
  });

  function invalidate() {
    stop("");
    verified = undefined;
    result.hidden = true;
    exportButton.hidden = true;
    list.replaceChildren();
    status.textContent = "";
  }

  form.onchange = invalidate;

  function openOrigin(row, kind, button) {
    const {comparison, sample} = verified;
    const side = comparison[kind];
    dialog.close();
    const back = {label: "Volver a la comparación", open: () => {
      if (!dialog.open) dialog.showModal();
      if (button.isConnected) button.focus();
    }};
    selectRecord(side.record_id, side.revision, back, undefined, {binaryReferenceOrigin: {
      sha256: comparison.sha256, revision: side.revision, inspectionHash: side.inspection_sha256,
      image: comparison.image, location: row[kind], instruction: row.instruction, sample
    }});
  }

  function renderRows() {
    const {rows} = verified.comparison;
    const visible = filter.value ? rows.filter((row) => row.state === filter.value) : rows;
    const pages = Math.ceil(visible.length / pageSize);
    list.replaceChildren(...visible.slice(page * pageSize, (page + 1) * pageSize).map((row) => {
      const item = element("li");
      const {address, offset, text} = row.instruction;
      const tools = element("div", "", "tools");
      for (const [kind, label] of [["current", "actual"], ["baseline", "base"]]) {
        if (!row[kind]) continue;
        const button = element("button", `Abrir origen ${label}`);
        button.setAttribute("aria-label", `Abrir origen ${label} en ${address}`);
        button.onclick = () => openOrigin(row, kind, button);
        tools.append(button);
      }
      item.append(element("span", labels[row.state], "type"), element("p", `Dirección ${address} · Archivo ${offset}`),
        element("pre", text), tools);
      return item;
    }));
    if (!visible.length) list.append(element("li", "Sin orígenes con este estado."));
    pager.hidden = pages <= 1;
    previous.disabled = page === 0;
    next.disabled = page + 1 >= pages;
    pageLabel.textContent = `Página ${page + 1} de ${pages}`;
  }

  filter.onchange = () => {
    page = 0;
    renderRows();
  };
  previous.onclick = () => { page--; renderRows(); };
  next.onclick = () => { page++; renderRows(); };
  exportButton.onclick = () => {
    const json = JSON.stringify(verified.comparison, null, 2) + "\n";
    download(new Blob([json], {type: "application/json"}), "PAVAROTTI-comparacion-referencias.json");
  };

  form.onsubmit = async (event) => {
    event.preventDefault();
    invalidate();
    const body = new FormData(form);
    const sample = body.get("archivo");
    if (body.get("base").size > binaryReferenceReportBytes || body.get("actual").size > binaryReferenceReportBytes) {
      status.textContent = "Cada informe admite hasta 4 MiB.";
      return;
    }
    if (sample.size > 32 * 1024 * 1024) {
      status.textContent = "El archivo supera los 32 MiB.";
      return;
    }
    const controller = new AbortController();
    pending = controller;
    const {signal} = controller;
    run.disabled = true;
    cancel.hidden = false;
    status.textContent = "Verificando los informes y el archivo original…";
    try {
      const comparison = await request("/api/referencias-binarias/comparar", {method: "POST", body, signal});
      if (signal.aborted) return;
      verified = {comparison, sample};
      const {image, architecture, destination_address, destination_offset, shared, added, absent} = comparison;
      const imageLabel = image ? ` · Imagen ${image}` : "";
      destination.textContent = `Destino ${destination_address} · Archivo ${destination_offset} · ${architecture}${imageLabel}`;
      totals.textContent = `Comunes ${shared} · Agregados ${added} · Ausentes del informe actual ${absent}`;
      page = 0;
      filter.value = "";
      renderRows();
      status.textContent = "Informes verificados";
      result.hidden = false;
      exportButton.hidden = false;
    } catch (error) {
      if (!signal.aborted) status.textContent = error.message;
    } finally {
      finish(controller);
    }
  };
}
