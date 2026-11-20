"use strict";

function networkMemberNode(member, open, back, beforeEvidence) {
  const row = element("article", "", "network-member");
  const address = element("button", member.value);
  address.onclick = open;
  const observations = member.count === 1 ? "1 observación" : `${member.count} observaciones`;
  const evidence = element("details");
  const refs = element("div", "", "asset-sources");
  refs.append(...member.evidence.map((ref) => assetEvidenceButton(ref, back, beforeEvidence)));
  evidence.append(element("summary", `Citas · ${member.evidence.length} de ${member.count}`), refs);
  row.append(address, element("p", observations), evidence);
  return row;
}

function assetNetworkPanel(asset, signal) {
  const panel = element("details", "", "network-observations");
  const title = element("summary", "IP observadas");
  const status = element("p");
  const rows = element("div");
  const controls = element("div", "", "tools");
  status.setAttribute("role", "status");
  panel.append(title, status, rows, controls);
  let loaded = false;

  async function load(after = "") {
    loaded = true;
    status.textContent = "Consultando observaciones…";
    controls.replaceChildren();
    rows.replaceChildren();
    try {
      const params = new URLSearchParams({valor: asset.value, despues: after, limite: "25"});
      const page = await request("/api/activos/red?" + params, {signal});
      if (signal.aborted) return;
      title.textContent = `IP observadas · ${page.addresses}`;
      status.textContent = page.rows.length ? `${page.records} ${page.records === 1 ? "registro DNS o HTTP" : "registros DNS o HTTP"}` :
        "Sin direcciones observadas para mostrar.";
      const back = {label: "Volver a la red", open: () => selectAsset({...asset, networkAfter: after})};
      rows.append(...page.rows.map((member) => networkMemberNode(member, () => selectAsset({...member, back}), back)));
      if (after) {
        const first = element("button", "Primeras IP observadas");
        first.onclick = () => load();
        controls.append(first);
      }
      if (page.next) {
        const next = element("button", "Más IP observadas");
        next.onclick = () => load(page.next);
        controls.append(next);
      }
    } catch (error) {
      if (!signal.aborted) {
        status.textContent = error.message;
        loaded = false;
      }
    }
  }

  panel.ontoggle = () => { if (panel.open && !loaded) load(); };
  if (asset.networkAfter !== undefined) {
    panel.open = true;
    load(asset.networkAfter);
  }
  return panel;
}

const openAssetCoverage = (() => {
  const dialog = byId("asset-coverage");
  const form = byId("asset-coverage-form");
  const input = byId("asset-coverage-file");
  const status = byId("asset-coverage-status");
  const results = byId("asset-coverage-result");
  const run = byId("asset-coverage-run");
  const saved = byId("asset-coverage-export");
  const schema = "pavarotti.asset-coverage.v1";
  const fields = {type: "tipo", value: "valor", from: "desde", to: "hasta"};
  let report;
  let operation;

  function fill(criteria) {
    for (const [key, name] of Object.entries(fields)) {
      if (criteria[key] !== undefined) form.elements.namedItem(name).value = criteria[key];
    }
  }

  function open(asset) {
    const day = (ago) => new Date(Date.now() - ago * 86400000).toISOString().slice(0, 10);
    if (!form.elements.namedItem(fields.from).value) fill({from: day(6), to: day(0)});
    if (asset) fill(asset);
    dialog.showModal();
  }

  function begin(message) {
    operation?.abort();
    operation = new AbortController();
    run.disabled = true;
    status.textContent = message;
    return operation.signal;
  }

  function end(signal) {
    if (signal.aborted) return;
    operation = undefined;
    run.disabled = false;
  }

  dialog.addEventListener("close", () => {
    if (dialog.open || !operation) return;
    operation.abort();
    operation = undefined;
    run.disabled = false;
    status.textContent = "";
  });

  const bounded = (value, limit) => typeof value === "string" && value.length <= limit;
  const count = (value, limit = 10000) => Number.isSafeInteger(value) && value >= 0 && value <= limit;
  const validRef = (ref) => ref && typeof ref.id === "string" && /^[a-f0-9]{64}-[1-9][0-9]*$/.test(ref.id) &&
    Number.isSafeInteger(ref.revision) && ref.revision > 0 && bounded(ref.title, 160) &&
    bounded(ref.kind, 64) && bounded(ref.time, 48) && bounded(ref.role ?? "", 32) && bounded(ref.network ?? "", 85);
  const validDate = (value) => {
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value) || value.startsWith("0000")) return false;
    const date = new Date(value + "T00:00:00Z");
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
  };
  const validRow = (member, observations) => member && ["ipv4", "ipv6"].includes(member.type) && bounded(member.value, 45) &&
    count(member.count, observations) && member.count > 0 && Array.isArray(member.evidence) &&
    member.evidence.length === Math.min(member.count, 5) && member.evidence.every(validRef);

  function validReport(value) {
    const criteria = value?.criteria;
    return value?.schema === schema && criteria && Object.hasOwn(assetKinds, criteria.type) && bounded(criteria.value, 254) &&
      criteria.value.length > 0 && validDate(criteria.from) && validDate(criteria.to) && criteria.from <= criteria.to &&
      typeof value.input_sha256 === "string" && /^[a-f0-9]{64}$/.test(value.input_sha256) &&
      count(value.direct) && count(value.indicators, value.direct) && count(value.coverage, 10000 - value.direct) &&
      count(value.addresses, 320000) && count(value.observations) &&
      Array.isArray(value.sources) && value.sources.length <= 100 && value.sources.every(validRef) &&
      count(value.omitted_sources) && value.omitted_sources + value.sources.length === value.direct + value.coverage &&
      Array.isArray(value.members) && value.members.length <= 100 && value.members.every((member) => validRow(member, value.observations)) &&
      count(value.omitted_members, 320000) && value.omitted_members + value.members.length === value.addresses;
  }

  function render(value) {
    report = value;
    const {criteria} = value;
    const counts = element("dl", "", "coverage-counts");
    const metrics = [["Registros directos", value.direct], ["Indicadores", value.indicators]];
    if (["ipv4", "ipv6"].includes(criteria.type)) metrics.push(["Rangos que cubren la IP", value.coverage]);
    if (criteria.type === "red") metrics.push(["IP observadas", value.addresses], ["Registros DNS o HTTP", value.observations]);
    for (const [label, number] of metrics) counts.append(element("dt", label), element("dd", String(number)));
    results.replaceChildren(element("h3", `${assetKinds[criteria.type]} · ${criteria.value}`),
      element("p", `${criteria.from} a ${criteria.to} UTC`), counts);

    const beforeSelect = () => dialog.close();
    const back = {label: "Volver al informe de cobertura", open: () => open()};
    const sources = element("details", "", "coverage-section");
    sources.append(element("summary", `Fuentes citadas · ${value.sources.length}`));
    if (value.sources.length) {
      const sourceList = element("div", "", "asset-sources");
      sourceList.append(...value.sources.map((ref) => assetEvidenceButton(ref, back, beforeSelect)));
      sources.append(sourceList);
      sources.open = true;
    } else {
      sources.append(element("p", "Sin fuentes para este periodo."));
    }
    if (value.omitted_sources) sources.append(element("p", `${value.omitted_sources} fuentes adicionales`));
    results.append(sources);

    if (criteria.type === "red") {
      const addresses = element("details", "", "coverage-section");
      addresses.append(element("summary", `IP observadas · ${value.addresses}`));
      for (const member of value.members) {
        addresses.append(networkMemberNode(member, () => {
          beforeSelect();
          selectAsset({...member, back});
        }, back, beforeSelect));
      }
      if (!value.members.length) addresses.append(element("p", "Sin IP observadas en este periodo."));
      if (value.omitted_members) addresses.append(element("p", `${value.omitted_members} direcciones adicionales`));
      results.append(addresses);
    }
    results.append(element("p", `Huella de entrada SHA-256 · ${value.input_sha256}`, "comparison-hash"));
    results.hidden = false;
    saved.hidden = false;
  }

  form.onsubmit = async (event) => {
    event.preventDefault();
    const signal = begin("Consultando evidencia del periodo…");
    try {
      const query = new URLSearchParams(new FormData(form));
      const value = await request("/api/activos/cobertura?" + query, {signal});
      if (signal.aborted) return;
      render(value);
      status.textContent = "Informe generado.";
    } catch (error) {
      if (!signal.aborted) status.textContent = error.message;
    } finally {
      end(signal);
    }
  };
  byId("open-asset-coverage").onclick = () => open(selectedAsset);
  byId("asset-coverage-open-file").onclick = () => input.click();
  input.onchange = async () => {
    const file = input.files[0];
    input.value = "";
    if (!file) return;
    const signal = begin("Abriendo informe guardado…");
    try {
      if (file.size > (2 << 20)) throw new Error("El informe supera 2 MiB.");
      const value = JSON.parse(await file.text());
      if (signal.aborted) return;
      if (!validReport(value)) throw new Error("Informe de cobertura inválido.");
      fill(value.criteria);
      render(value);
      status.textContent = "Informe guardado cargado.";
    } catch (error) {
      if (!signal.aborted) status.textContent = error instanceof SyntaxError ? "Informe de cobertura inválido." : error.message;
    } finally {
      end(signal);
    }
  };
  saved.onclick = () => {
    const blob = new Blob([JSON.stringify(report, null, 2) + "\n"], {type: "application/json"});
    download(blob, `pavarotti-cobertura-${report.input_sha256.slice(0, 12)}.json`);
  };
  return open;
})();
