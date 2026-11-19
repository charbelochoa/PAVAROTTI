"use strict";

function binaryInstructionPanel(report, record, citation, sections, images) {
  const details = element("details", "", "binary-instructions");
  const title = element("summary", "Instrucciones");
  const code = Array.isArray(report.instructions) ? report.instructions : [];
  const entries = [];
  for (const [index, instruction] of code.entries()) {
    const section = Number.isInteger(instruction?.section) && sections[instruction.section];
    if (!section || ![instruction.address, instruction.offset, instruction.bytes, instruction.text].every((value) => typeof value === "string") ||
      (instruction.target !== undefined && typeof instruction.target !== "string")) continue;
    entries.push({instruction, index, section, bytes: instruction.bytes.match(/.{1,2}/g)?.join(" ")});
  }
  details.append(title);
  if (!entries.length) {
    details.append(element("p", "Este análisis no contiene instrucciones guardadas."));
    return {details, paintImage() {}, hasSection() { return false; }};
  }
  const linked = citation?.kind === "instruccion" ? citation.index : -1;
  details.open = linked >= 0;
  if (report.instructions_limited) details.append(element("p", "Listado parcial de las secciones ejecutables."));
  const byAddress = new Map();
  const withCode = new Set();
  const lookup = (section, address) => `${section.image || 0}:${address}`;
  for (const entry of entries) {
    withCode.add(entry.instruction.section);
    const key = lookup(entry.section, entry.instruction.address);
    byAddress.set(key, byAddress.has(key) || !entry.instruction.text ? undefined : entry);
  }
  const label = element("label", "Sección", "binary-image");
  const sectionFilter = element("select");
  sectionFilter.setAttribute("aria-label", "Sección de instrucciones");
  label.append(sectionFilter);
  const search = element("input");
  search.type = "search";
  search.placeholder = "Buscar dirección, bytes o instrucción";
  search.setAttribute("aria-label", "Buscar instrucciones");
  search.maxLength = 128;
  const actions = element("div", "", "tools instruction-actions");
  const wrapper = element("div", "", "instruction-table");
  const table = element("table");
  table.setAttribute("aria-label", "Listado de instrucciones");
  const headers = element("tr");
  for (const text of [report.format === "PE" ? "RVA / archivo" : "Dirección / archivo", "Bytes", "Instrucción"]) {
    const cell = element("th", text);
    cell.scope = "col";
    headers.append(cell);
  }
  const head = element("thead");
  head.append(headers);
  const body = element("tbody");
  table.append(head, body);
  wrapper.append(table);
  const pager = element("div", "", "pager");
  const previous = element("button", "Anterior");
  const next = element("button", "Siguiente");
  const count = element("output");
  count.setAttribute("aria-live", "polite");
  pager.append(previous, count, next);
  details.append(label, search, actions, wrapper, pager);

  const pageSize = 20;
  let image = 0;
  let page = 0;
  let selected = -1;
  let origin;
  function matching() {
    const query = search.value.trim().toLowerCase();
    return entries.filter(({instruction, section, bytes}) => {
      return (!image || section.image === image) && (!sectionFilter.value || String(instruction.section) === sectionFilter.value) &&
        (!query || [instruction.address, instruction.offset, instruction.bytes, bytes, instruction.text, instruction.target]
          .some((value) => value?.toLowerCase().includes(query)));
    });
  }
  function reveal(entry, focus) {
    details.open = true;
    sectionFilter.value = String(entry.instruction.section);
    search.value = "";
    page = Math.floor(matching().indexOf(entry) / pageSize);
    selected = entry.index;
    render(focus);
  }
  function render(focus = false) {
    const rows = matching();
    const start = page * pageSize;
    const visible = rows.slice(start, start + pageSize);
    let focusButton;
    body.replaceChildren(...visible.map((entry) => {
      const {instruction, index, section} = entry;
      const row = element("tr");
      const location = element("td");
      const pick = element("button", instruction.address, "instruction-address");
      pick.setAttribute("aria-pressed", String(index === selected));
      pick.onclick = () => { selected = index; render(true); };
      location.append(pick, element("small", instruction.offset));
      if (section.image && !image) location.append(element("small", images[section.image - 1]?.architecture));
      const bytes = element("td", entry.bytes);
      const mnemonic = element("td", instruction.text || "Sin decodificar");
      if (instruction.target) {
        const destination = byAddress.get(lookup(section, instruction.target));
        if (destination) {
          const jump = element("button", `Ir a ${instruction.target}`, "instruction-target");
          jump.onclick = () => { origin = entry; reveal(destination, true); };
          mnemonic.append(jump);
        } else {
          mnemonic.append(element("small", `Destino ${instruction.target} · fuera del listado`));
        }
      }
      row.append(location, bytes, mnemonic);
      markBinaryCitation(row, citation, "instruccion", index);
      if (index === selected) focusButton = pick;
      return row;
    }));
    const controls = [];
    if (focusButton) controls.push(binaryCitationButton(record, "instruccion", selected));
    if (origin) {
      const back = element("button", "Volver al salto");
      back.onclick = () => {
        const entry = origin;
        origin = undefined;
        reveal(entry, true);
      };
      controls.push(back);
    }
    actions.replaceChildren(...controls);
    actions.hidden = !controls.length;
    wrapper.hidden = !visible.length;
    count.textContent = visible.length ? `${start + 1}–${start + visible.length} de ${rows.length}` : "Sin coincidencias";
    previous.disabled = start === 0;
    next.disabled = start + pageSize >= rows.length;
    if (focus && focusButton) focusButton.focus();
  }
  function resetList() {
    page = 0;
    selected = -1;
    origin = undefined;
    render();
  }
  sectionFilter.onchange = resetList;
  search.oninput = resetList;
  previous.onclick = () => { page--; render(); };
  next.onclick = () => { page++; render(); };
  let initialized = false;
  function paintImage(index) {
    image = index;
    const options = [element("option", "Todas las secciones")];
    options[0].value = "";
    for (const sectionIndex of withCode) {
      const section = sections[sectionIndex];
      if (image && section.image !== image) continue;
      const item = element("option", [section.name || "Sin nombre", !image && images[section.image - 1]?.architecture].filter(Boolean).join(" · "));
      item.value = String(sectionIndex);
      options.push(item);
    }
    sectionFilter.replaceChildren(...options);
    const initial = !initialized && entries.find((entry) => entry.index === linked);
    initialized = true;
    search.value = "";
    if (initial) reveal(initial, false);
    else resetList();
  }
  return {details, paintImage,
    hasSection(index) { return withCode.has(index); },
    showSection(index) { reveal(entries.find(({instruction}) => instruction.section === index), true); }};
}
