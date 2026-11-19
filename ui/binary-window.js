"use strict";

const binaryWindowSchema = "pavarotti.binary-window-citation.v1";
const binaryWindowPathLimit = 32;

function validBinaryWindowCitation(citation) {
  const digest = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
  const location = (value) => typeof value === "string" && /^0x[a-f0-9]{1,16}$/.test(value);
  const steps = typeof citation.path === "string" ? citation.path.split(".") : [];
  const validPath = citation.path === undefined || (steps.length > 0 && steps.length <= binaryWindowPathLimit &&
    steps.every((step) => /^(0|[1-9][0-9]?)$/.test(step) && Number(step) < 64));
  return ["entrada", "simbolo", "instruccion"].includes(citation.kind) && validPath && Number.isSafeInteger(citation.image) && citation.image >= 0 &&
    digest(citation.sha256) && digest(citation.inspection_sha256) && digest(citation.window_sha256) &&
    location(citation.address) && location(citation.offset);
}

function binaryWindowPanel(report, record, citation, signal) {
  const details = element("details", "", "binary-window");
  details.append(element("summary", "Ventana de instrucciones"));
  const label = element("label", "Archivo binario original", "binary-image");
  const input = element("input");
  input.type = "file";
  label.append(input);
  const entry = element("button", "Abrir punto de entrada");
  const status = element("p");
  status.setAttribute("role", "status");
  const result = element("div");
  details.append(label, entry, status, result);
  let image;
  let anchor = citation;
  let expected = citation;
  let pending;
  if (expected) {
    details.open = true;
    status.textContent = `Selecciona el archivo original para verificar la cita en ${expected.offset}.`;
    requestAnimationFrame(() => { if (!signal.aborted) input.focus(); });
  }

  async function load({preserve = false, focus} = {}) {
    pending?.abort();
    if (!preserve) result.replaceChildren();
    const file = input.files[0];
    if (!file) {
      status.textContent = "Selecciona el archivo binario original.";
      input.focus();
      return;
    }
    if (file.size > 32 * 1024 * 1024) {
      status.textContent = "El archivo supera los 32 MiB.";
      return;
    }
    const controller = new AbortController();
    pending = controller;
    const current = AbortSignal.any([signal, controller.signal]);
    status.textContent = "Verificando el archivo y abriendo la ventana…";
    const query = new URLSearchParams({revision: record.revision, tipo: anchor.kind, indice: anchor.index});
    if (anchor.path) query.set("pasos", anchor.path);
    try {
      const data = await request(`/api/registro/${encodeURIComponent(record.id)}/ventana-binaria?${query}`,
        {method: "POST", body: file, signal: current});
      if (current.aborted) return;
      if (expected && Object.entries(data.citation).some(([key, value]) => expected[key] !== value)) {
        throw new Error("La ventana no coincide con la cita guardada.");
      }
      status.textContent = expected ? `Cita de ventana verificada · ${data.citation.offset}` :
        `Archivo verificado · ${data.citation.offset}`;
      const location = report.format === "PE" ? "RVA" : "Dirección";
      const {window} = data;
      const steps = data.citation.path?.split(".") || [];
      const title = element("p", `${data.name} · ${window.section || "Sin nombre"} · ${window.architecture}`);
      const address = element("p", `${location} ${data.citation.address} · Archivo ${data.citation.offset}`);
      const tools = element("div", "", "tools");
      const save = element("button", "Exportar cita de ventana");
      save.onclick = () => {
        const body = JSON.stringify(data.citation, null, 2) + "\n";
        download(new Blob([body], {type: "application/json"}), "PAVAROTTI-cita-ventana.json");
      };
      tools.append(save);
      let origin;
      if (window.origin && steps.length) {
        origin = element("p", `Origen del salto ${window.origin.address} · Archivo ${window.origin.offset}`);
        const back = element("button", `Volver a ${window.origin.address}`);
        back.onclick = () => open({kind: data.citation.kind, index: data.citation.index, path: steps.slice(0, -1).join(".")},
          {preserve: true, focus: Number(steps.at(-1))});
        tools.append(back);
      }
      const follow = steps.length < binaryWindowPathLimit ? (index) => {
        open({kind: data.citation.kind, index: data.citation.index, path: [...steps, index].join(".")}, {preserve: true, focus: 0});
      } : undefined;
      const listing = binaryInstructionPanel({format: report.format, instructions: window.instructions,
        instructions_limited: window.limited}, [{name: window.section}], [], undefined, undefined, follow);
      listing.paintImage(0);
      result.replaceChildren(title, address);
      if (origin) result.append(origin);
      if (steps.length === binaryWindowPathLimit) result.append(element("p", "Se alcanzó el límite de 32 saltos en el recorrido."));
      result.append(tools, listing.details);
      if (focus !== undefined) listing.focusIndex(focus);
    } catch (error) {
      if (!current.aborted) status.textContent = error.message;
    }
  }

  function open(location, options) {
    expected = undefined;
    anchor = location;
    details.open = true;
    details.scrollIntoView({block: "nearest"});
    load(options);
  }
  input.onchange = () => {
    if (anchor) load();
    else status.textContent = "Elige un símbolo o abre el punto de entrada.";
  };
  entry.onclick = () => open({kind: "entrada", index: image});
  return {details, openSymbol(index) { open({kind: "simbolo", index}); },
    followInstruction(index) { open({kind: "instruccion", index, path: "0"}, {focus: 0}); }, paintImage(index) {
    if (image !== undefined && image !== index) {
      pending?.abort();
      anchor = undefined;
      expected = undefined;
      result.replaceChildren();
      status.textContent = "";
    }
    image = index;
    entry.disabled = !!report.images?.length && image === 0;
    if (entry.disabled && !anchor) status.textContent = "Selecciona una imagen Mach-O para abrir su punto de entrada.";
  }};
}
