"use strict";

const openAssetRelations = (() => {
  const dialog = byId("asset-relations");
  const form = byId("asset-relations-form");
  const anchor = byId("asset-relations-anchor");
  const status = byId("asset-relations-status");
  const rows = byId("asset-relations-rows");
  const submit = form.querySelector("button[type=submit]");
  const save = byId("asset-relations-export");
  const labels = {
    "dns-a": "Respuesta DNS A", "dns-aaaa": "Respuesta DNS AAAA",
    "dns-cname": "Alias DNS CNAME", "dns-ns": "Servidor DNS NS",
    "dns-ptr": "Respuesta DNS PTR", "dns-mx": "Servidor DNS MX", "dns-srv": "Servicio DNS SRV",
    "rdap-ns": "Servidor de nombre RDAP", "rdap-cobertura": "Cobertura por rango RDAP",
    "stix-cobertura": "Cobertura por prefijo STIX", "ip-observada": "IP observada dentro de la red",
    "stix-huella": "Huellas de un mismo archivo STIX"
  };
  const directions = {entrante: "Entrante", saliente: "Saliente", compartida: "Compartida"};
  let view;
  let pending;

  function cancel() {
    pending?.abort();
    pending = undefined;
    submit.disabled = false;
  }

  function show(snapshot) {
    cancel();
    view = snapshot;
    anchor.textContent = `${assetKinds[view.asset.type]} · ${view.asset.value}`;
    form.elements.desde.value = view.from;
    form.elements.hasta.value = view.to;
    if (!dialog.open) dialog.showModal();
    if (view.report) render();
    else query();
  }

  function relationRow(relation, snapshot) {
    const item = element("li");
    const title = element("strong", relation.value);
    const count = `${relation.count} ${relation.count === 1 ? "registro" : "registros"}`;
    item.append(element("p", assetKinds[relation.type], "type"), title,
      element("p", `${labels[relation.kind] || relation.kind} · ${directions[relation.direction]} · ${count}`));
    if (relation.first) {
      const period = relation.first === relation.last ? relation.first : `${relation.first} a ${relation.last}`;
      item.append(element("p", period, "muted"));
    }
    const back = {label: "Volver a relaciones", open: () => show(snapshot)};
    const tools = element("div", "", "tools");
    const open = element("button", "Abrir activo relacionado");
    open.setAttribute("aria-label", `Abrir activo relacionado ${relation.value}`);
    open.onclick = () => {
      dialog.close();
      selectAsset({type: relation.type, value: relation.value, back});
    };
    tools.append(open);
    const evidence = element("details");
    evidence.append(element("summary", `Citas · ${relation.sources.length} de ${relation.count}`));
    const list = element("div", "", "asset-sources");
    list.append(...relation.sources.map((ref) => assetEvidenceButton(ref, back, () => dialog.close())));
    evidence.append(list);
    item.append(tools, evidence);
    return item;
  }

  function render() {
    const {report} = view;
    rows.replaceChildren(...report.rows.map((relation) => relationRow(relation, view)));
    const total = report.rows.length + report.omitted_rows;
    status.textContent = total ?
      `${total} ${total === 1 ? "relación" : "relaciones"} · ${report.records} ${report.records === 1 ? "registro" : "registros"}` :
      "Sin relaciones en la evidencia consultada.";
    if (report.omitted_rows) status.textContent += ` · Se muestran ${report.rows.length}`;
    save.hidden = false;
  }

  async function query() {
    cancel();
    save.hidden = true;
    rows.replaceChildren();
    const snapshot = view;
    const {asset, from, to} = snapshot;
    if (Boolean(from) !== Boolean(to)) {
      status.textContent = "Indica las dos fechas o deja ambas vacías.";
      return;
    }
    const controller = new AbortController();
    pending = controller;
    submit.disabled = true;
    status.textContent = "Buscando relaciones en el expediente…";
    const params = new URLSearchParams({tipo: asset.type, valor: asset.value, desde: from, hasta: to});
    try {
      const report = await request("/api/activos/relaciones?" + params, {signal: controller.signal});
      if (controller.signal.aborted) return;
      snapshot.report = report;
      render();
    } catch (error) {
      if (!controller.signal.aborted) status.textContent = error.message;
    } finally {
      if (pending === controller) cancel();
    }
  }

  function readDates() {
    view = {asset: view.asset, from: form.elements.desde.value, to: form.elements.hasta.value};
  }

  form.oninput = () => {
    cancel();
    readDates();
    rows.replaceChildren();
    save.hidden = true;
    status.textContent = "Consulta el periodo seleccionado.";
  };
  form.onsubmit = (event) => {
    event.preventDefault();
    readDates();
    query();
  };
  dialog.addEventListener("close", () => { if (!dialog.open) cancel(); });
  save.onclick = () => {
    const data = JSON.stringify(view.report, null, 2) + "\n";
    download(new Blob([data], {type: "application/json"}), "PAVAROTTI-relaciones-activo.json");
  };
  return (asset) => show({asset: {type: asset.type, value: asset.value}, from: "", to: ""});
})();
