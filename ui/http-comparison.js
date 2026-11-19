"use strict";

{
  const dialog = byId("http-comparison");
  const form = byId("http-comparison-form");
  const file = byId("http-compare-file");
  const status = byId("http-compare-status");
  const result = byId("http-compare-result");
  const run = byId("http-compare-run");
  const saved = byId("http-compare-export");
  const limits = new Map([["pavarotti.http-comparison.v1", 10000], ["pavarotti.http-comparison.v2", 50000]]);
  const captures = ["", "archivo HAR", "tráfico"];
  const metrics = {
    observations: "Observaciones",
    responses: "Respuestas HTTP",
    transport_failures: "Fallos del proxy",
    assessed: "Con evaluación confirmada"
  };
  const ruleCode = /^[a-z0-9-]{1,64}$/;
  let active;
  let comparison;
  let initialized = false;

  const count = (value, maximum) => Number.isSafeInteger(value) && value >= 0 && value <= maximum;
  const bounded = (value, length) => typeof value === "string" && value.length <= length;
  const isoDate = (value) => {
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value) || value.startsWith("0000")) return false;
    const date = new Date(value + "T00:00:00Z");
    return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
  };
  const validWindow = (value) => value && bounded(value.origin, 768) && captures.includes(value.capture) &&
    isoDate(value.from) && isoDate(value.to) && value.from <= value.to;
  const validStats = (stats, maximum) => stats && Object.keys(metrics).every((metric) => count(stats[metric], maximum)) &&
    stats.responses + stats.transport_failures <= stats.observations && stats.assessed <= stats.responses;
  const validRef = (ref, row) => ref && typeof ref.id === "string" && /^[a-f0-9]{64}-[1-9][0-9]*$/.test(ref.id) &&
    Number.isSafeInteger(ref.revision) && ref.revision >= 1 && bounded(ref.title, 160) &&
    bounded(ref.kind, 64) && bounded(ref.time, 48) && bounded(ref.origin ?? "", 768) &&
    (row.kind === "rule" ? ref.http_rule === row.code : ref.http_rule === undefined);
  const validTally = (tally, row, maximum) => {
    if (!tally || !count(tally.count, maximum)) return false;
    const refs = tally.evidence ?? [];
    return Array.isArray(refs) && refs.length === Math.min(5, tally.count) && refs.every((ref) => validRef(ref, row));
  };
  const validRow = (row, report) => row && ["status", "transport", "unknown", "rule", "legacy"].includes(row.kind) &&
    bounded(row.label, 180) && bounded(row.code, 180) &&
    (row.kind !== "rule" || ruleCode.test(row.code)) &&
    validTally(row.baseline, row, report.baseline.observations) && validTally(row.current, row, report.current.observations);
  const validReport = (report) => {
    const maximum = limits.get(report?.schema);
    return maximum && typeof report.input_sha256 === "string" && /^[a-f0-9]{64}$/.test(report.input_sha256) &&
      validWindow(report.criteria?.baseline) && validWindow(report.criteria?.current) &&
      validStats(report.baseline, maximum) && validStats(report.current, maximum) && Array.isArray(report.rows) && report.rows.length <= 100 &&
      Number.isSafeInteger(report.omitted_rows) && report.omitted_rows >= 0 && report.rows.every((row) => validRow(row, report));
  };

  function fill(side, window) {
    const values = {origen: window.origin, captura: window.capture, desde: window.from, hasta: window.to};
    for (const [name, value] of Object.entries(values)) form.elements.namedItem(name + "_" + side).value = value;
  }

  function show() {
    if (!initialized) {
      const dayUTC = (daysAgo) => new Date(Date.now() - daysAgo * 86400000).toISOString().slice(0, 10);
      const capture = byId("filter-capture").value;
      fill("a", {origin: "", capture, from: dayUTC(13), to: dayUTC(7)});
      fill("b", {origin: "", capture, from: byId("filter-from").value || dayUTC(6), to: byId("filter-to").value || dayUTC(0)});
      initialized = true;
    }
    dialog.showModal();
  }

  function summary(label, window, stats) {
    const card = element("article");
    card.append(element("strong", `${label} · ${window.from} a ${window.to} UTC`),
      element("p", `${window.origin || "Todos los orígenes"} · ${captureLabel(window.capture) || "Todas las capturas"}`, "comparison-source"));
    const counts = element("dl");
    for (const [key, name] of Object.entries(metrics)) counts.append(element("dt", name), element("dd", String(stats[key])));
    card.append(counts);
    return card;
  }

  function citation(ref) {
    const button = element("button");
    button.append(element("strong", `${ref.title} · rev. ${ref.revision}`),
      element("span", `${captureLabel(ref.kind)} · ${ref.time}`, "type"));
    if (ref.origin) button.append(element("span", ref.origin, "muted"));
    button.onclick = () => {
      dialog.close();
      selectRecord(ref.id, ref.revision, {label: "Volver a la comparación", open: show}, undefined, ref);
      byId("inspector").scrollIntoView({block: "nearest"});
    };
    return button;
  }

  function table(rows) {
    const view = element("table", "", "comparison-table");
    view.setAttribute("aria-label", "Comparación de estados y señales");
    const columns = element("colgroup");
    for (let index = 0; index < 4; index++) columns.append(element("col"));
    view.append(columns);
    const heading = view.createTHead().insertRow();
    for (const label of ["Indicador", "A", "B", "B − A"]) {
      const column = element("th", label);
      column.scope = "col";
      heading.append(column);
    }
    const body = view.createTBody();
    rows.forEach((row, index) => {
      const line = body.insertRow();
      const name = element("th", row.label);
      name.scope = "row";
      if (row.kind === "rule") name.append(element("div", row.code, "type"));
      if (row.kind === "legacy") name.append(element("div", "Etiqueta histórica", "type"));
      line.append(name);

      const citations = element("tr", "", "comparison-citations");
      citations.id = "http-compare-citations-" + index;
      citations.hidden = true;
      const holder = citations.insertCell();
      holder.colSpan = 4;
      const controls = [];
      for (const [label, tally] of [["A", row.baseline], ["B", row.current]]) {
        const cell = line.insertCell();
        cell.append(String(tally.count));
        if (!tally.evidence?.length) continue;
        const toggle = element("button", "Citas", "comparison-cite");
        toggle.setAttribute("aria-label", `Citas de ${row.label} en el periodo ${label}`);
        toggle.setAttribute("aria-controls", citations.id);
        toggle.setAttribute("aria-expanded", "false");
        controls.push(toggle);
        toggle.onclick = () => {
          const wasExpanded = toggle.getAttribute("aria-expanded") === "true";
          for (const control of controls) control.setAttribute("aria-expanded", "false");
          citations.hidden = wasExpanded;
          if (wasExpanded) return;
          toggle.setAttribute("aria-expanded", "true");
          const list = element("div", "", "asset-sources");
          list.append(...tally.evidence.map(citation));
          const labelText = `Periodo ${label} · ${tally.evidence.length} de ${tally.count} citas`;
          holder.replaceChildren(element("p", labelText), list);
        };
        cell.append(toggle);
      }
      const change = row.current.count - row.baseline.count;
      line.insertCell().append(change > 0 ? "+" + change : String(change));
      body.append(citations);
    });
    return view;
  }

  function render(report) {
    comparison = report;
    const summaries = element("div", "", "comparison-summary");
    summaries.append(summary("Periodo A", report.criteria.baseline, report.baseline),
      summary("Periodo B", report.criteria.current, report.current));
    result.replaceChildren(summaries);
    result.append(report.rows.length ? table(report.rows) : element("p", "No hay observaciones que coincidan con estos periodos."));
    if (report.omitted_rows) result.append(element("p", `Filas adicionales omitidas · ${report.omitted_rows}`));
    result.append(element("p", `Huella de entrada SHA-256 · ${report.input_sha256}`, "comparison-hash"));
    result.hidden = false;
    saved.hidden = false;
  }

  function begin(message) {
    active?.abort();
    active = new AbortController();
    status.textContent = message;
    run.disabled = true;
    return active.signal;
  }

  function end(signal) {
    if (signal.aborted) return;
    active = undefined;
    run.disabled = false;
  }

  byId("open-http-comparison").onclick = show;
  dialog.addEventListener("close", () => {
    if (dialog.open || !active) return;
    active.abort();
    active = undefined;
    run.disabled = false;
    status.textContent = "";
  });
  form.onsubmit = async (event) => {
    event.preventDefault();
    const signal = begin("Comparando el historial del expediente…");
    try {
      const query = new URLSearchParams(new FormData(form));
      for (const [name, value] of [...query]) if (!value) query.delete(name);
      const report = await request("/api/http/comparar?" + query, {signal});
      if (signal.aborted) return;
      render(report);
      status.textContent = "Comparación generada.";
    } catch (error) {
      if (!signal.aborted) status.textContent = error.message;
    } finally {
      end(signal);
    }
  };
  byId("http-compare-open").onclick = () => file.click();
  file.onchange = async () => {
    const selected = file.files[0];
    file.value = "";
    if (!selected) return;
    const signal = begin("Abriendo informe guardado…");
    try {
      if (selected.size > (4 << 20)) throw new Error("El informe supera 4 MiB.");
      const report = JSON.parse(await selected.text());
      if (signal.aborted) return;
      if (!validReport(report)) throw new Error("Informe de comparación inválido.");
      fill("a", report.criteria.baseline);
      fill("b", report.criteria.current);
      render(report);
      status.textContent = "Informe guardado cargado.";
    } catch (error) {
      if (!signal.aborted) status.textContent = error instanceof SyntaxError ? "Informe de comparación inválido." : error.message;
    } finally {
      end(signal);
    }
  };
  saved.onclick = () => {
    const blob = new Blob([JSON.stringify(comparison, null, 2) + "\n"], {type: "application/json"});
    download(blob, `pavarotti-http-${comparison.input_sha256.slice(0, 12)}.json`);
  };
}
