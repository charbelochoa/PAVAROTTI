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

function binaryWindowPanel(report, record, citation, restoredReport, signal, references, updateReferences, verifiedOrigin) {
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
  let anchor = verifiedOrigin?.location || citation;
  let expected = citation;
  let pending;
  let focusOnFile = verifiedOrigin?.location.row;
  let expectedOrigin = verifiedOrigin?.instruction;
  let expectedHash = verifiedOrigin?.location.window_sha256;
  let expectedContext = verifiedOrigin && {image: verifiedOrigin.image, inspection_sha256: verifiedOrigin.inspectionHash};
  let showReferencesOnFile = false;
  let referenceAction = restoredReport ? {mode: "verificar", report: restoredReport} : undefined;
  if (verifiedOrigin) {
    details.open = true;
    const attached = new DataTransfer();
    attached.items.add(verifiedOrigin.sample);
    input.files = attached.files;
    requestAnimationFrame(() => { if (!signal.aborted && anchor === verifiedOrigin.location) load({focus: focusOnFile}); });
  } else if (expected || referenceAction) {
    details.open = true;
    status.textContent = expected ? `Selecciona el archivo original para verificar la cita en ${expected.offset}.` :
      "Selecciona el archivo original para verificar el informe de referencias.";
    requestAnimationFrame(() => { if (!signal.aborted) input.focus(); });
  }

  const images = Array.isArray(report.images) ? report.images : [];
  function incoming({instruction, section}) {
    return references.incoming(section.image || 0, instruction.address, instruction.offset);
  }
  function openReference(ref) {
    const location = ref.citation || ref.anchor || {kind: "instruccion", index: ref.index};
    open(location, {expected: ref.citation, preserve: true, focus: ref.citation || ref.anchor ? ref.index : 0,
      origin: ref.instruction, windowHash: ref.windowHash});
  }

  function exportReferences(destination, rows, windowCitation) {
    referenceAction = {mode: "exportar", report: {schema: binaryReferenceReportSchema,
      record_id: record.id, revision: record.revision, sha256: record.sha256, image: destination.section.image || 0,
      destination: binaryReferenceLocation({...destination, citation: windowCitation}),
      origins: rows.map(binaryReferenceLocation)}};
    details.open = true;
    load({preserve: true});
  }

  async function reviewReferences(action, file, current) {
    status.textContent = "Verificando el informe de referencias…";
    const body = new FormData();
    body.append("informe", JSON.stringify(action.report));
    body.append("archivo", file);
    const review = await request(`/api/registro/${encodeURIComponent(record.id)}/referencias-binarias?modo=${action.mode}`,
      {method: "POST", body, signal: current});
    if (current.aborted) return;
    const count = review.report.origins.length;
    const summary = `${count} ${count === 1 ? "referencia" : "referencias"}`;
    if (action.mode === "exportar") {
      const output = JSON.stringify(review.report, null, 2) + "\n";
      download(new Blob([output], {type: "application/json"}), "PAVAROTTI-informe-referencias.json");
      referenceAction = undefined;
      status.textContent = `Informe exportado · ${summary}`;
      return;
    }
    references.restore(review.report, review.origins);
    status.textContent = `Informe verificado · ${summary}`;
    renderWindow(review.destination, review.report.destination.row);
  }

  async function load({preserve = false, focus, showReferences = false} = {}) {
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
    try {
      if (referenceAction) {
        await reviewReferences(referenceAction, file, current);
        return;
      }
      status.textContent = "Verificando el archivo y abriendo la ventana…";
      const query = new URLSearchParams({revision: record.revision, tipo: anchor.kind, indice: anchor.index});
      if (anchor.path) query.set("pasos", anchor.path);
      const data = await request(`/api/registro/${encodeURIComponent(record.id)}/ventana-binaria?${query}`,
        {method: "POST", body: file, signal: current});
      if (current.aborted) return;
      if (expected && Object.entries(data.citation).some(([key, value]) => expected[key] !== value)) {
        throw new Error("La ventana no coincide con la cita guardada.");
      }
      if (expectedHash && expectedHash !== data.citation.window_sha256) throw new Error("La ventana no coincide con el informe guardado.");
      if (expectedContext && Object.entries(expectedContext).some(([key, value]) => data.citation[key] !== value)) {
        throw new Error("El análisis o la imagen no coinciden con el informe guardado.");
      }
      if (showReferences && data.entry_ambiguous) throw new Error("El símbolo tiene más de una ubicación ejecutable para esa dirección.");
      if (showReferences && !data.window.instructions[0]?.text) throw new Error("No se pudo decodificar la instrucción de entrada del símbolo.");
      if (expectedOrigin) {
        const actual = data.window.instructions[focus];
        const fields = ["address", "offset", "bytes", "target"];
        if (!actual || fields.some((key) => actual[key] !== expectedOrigin[key])) {
          throw new Error("La instrucción verificada difiere del origen de la referencia.");
        }
      }
      status.textContent = expectedOrigin ? `Origen verificado · ${expectedOrigin.offset}` :
        expected ? `Cita de ventana verificada · ${data.citation.offset}` : `Archivo verificado · ${data.citation.offset}`;
      renderWindow(data, focus, showReferences);
    } catch (error) {
      if (!current.aborted) status.textContent = error.message;
    }
  }

  function renderWindow(data, focus, showReferences = false) {
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
    let verifiedParent;
    if (window.origin && steps.length) {
      origin = element("p", `Origen del salto ${window.origin.address} · Archivo ${window.origin.offset}`);
      const parent = {kind: data.citation.kind, index: data.citation.index, path: steps.slice(0, -1).join(".")};
      const position = Number(steps.at(-1));
      verifiedParent = {instruction: window.origin, section: {image: window.image}, index: position, anchor: parent};
      const back = element("button", `Volver a ${window.origin.address}`);
      back.onclick = () => open(parent, {preserve: true, focus: position});
      tools.append(back);
    }
    const follow = steps.length < binaryWindowPathLimit ? (index) => {
      open({kind: data.citation.kind, index: data.citation.index, path: [...steps, index].join(".")}, {preserve: true, focus: 0});
    } : undefined;
    const sections = [{name: window.section, image: window.image}];
    const entries = binaryInstructionEntries(window.instructions, sections);
    references.observe(data.citation, verifiedParent ? [...entries, verifiedParent] : entries);
    updateReferences();
    const listing = binaryInstructionPanel({format: report.format, instructions_limited: window.limited}, sections, images,
      {entries, follow, incoming, openReference, exportReferences: (destination, rows) => exportReferences(destination, rows, data.citation)});
    listing.paintImage(window.image);
    result.replaceChildren(title, address);
    if (origin) result.append(origin);
    if (steps.length === binaryWindowPathLimit) result.append(element("p", "Se alcanzó el límite de 32 saltos en el recorrido."));
    result.append(tools, listing.details);
    if (focus !== undefined) listing.focusIndex(focus, showReferences);
  }

  function open(location, options) {
    expected = options?.expected;
    focusOnFile = options?.focus;
    expectedOrigin = options?.origin;
    expectedHash = options?.windowHash;
    expectedContext = undefined;
    showReferencesOnFile = !!options?.showReferences;
    referenceAction = undefined;
    anchor = location;
    details.open = true;
    details.scrollIntoView({block: "nearest"});
    load(options);
  }
  input.onchange = () => {
    if (anchor || referenceAction) load({focus: focusOnFile, showReferences: showReferencesOnFile, preserve: referenceAction?.mode === "exportar"});
    else status.textContent = "Elige un símbolo o abre el punto de entrada.";
  };
  entry.onclick = () => open({kind: "entrada", index: image});
  return {details, incoming, openReference, exportReferences, symbolReferences: references.forSymbol,
    openSymbol(index) { open({kind: "simbolo", index}); },
    openSymbolReferences(index) { open({kind: "simbolo", index}, {focus: 0, showReferences: true}); },
    followInstruction(index) { open({kind: "instruccion", index, path: "0"}, {focus: 0}); }, paintImage(index) {
    if (image !== undefined && image !== index) {
      pending?.abort();
      anchor = undefined;
      expected = undefined;
      focusOnFile = undefined;
      expectedOrigin = undefined;
      expectedHash = undefined;
      expectedContext = undefined;
      showReferencesOnFile = false;
      referenceAction = undefined;
      result.replaceChildren();
      status.textContent = "";
    }
    image = index;
    entry.disabled = !!report.images?.length && image === 0;
    if (entry.disabled && !anchor && !referenceAction) status.textContent = "Selecciona una imagen Mach-O para abrir su punto de entrada.";
  }};
}
