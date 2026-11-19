"use strict";

const openWatchlists = (() => {
  const dialog = byId("watchlists");
  const selector = byId("watchlist-select");
  const create = byId("watchlist-create");
  const add = byId("watchlist-add");
  const refresh = byId("watchlist-refresh");
  const removeList = byId("watchlist-delete");
  const status = byId("watchlist-status");
  const rows = byId("watchlist-rows");
  const root = "/api/seguimiento";
  let working = false;

  function controls() {
    const selected = Boolean(selector.value);
    create.hidden = !canWrite;
    add.hidden = !canWrite || !selected;
    removeList.hidden = !canWrite || !selected;
    selector.disabled = working || !selected;
    refresh.disabled = working;
    removeList.disabled = working;
    for (const control of dialog.querySelectorAll("#watchlist-create input, #watchlist-create button, #watchlist-add input, #watchlist-add select, #watchlist-add button, #watchlist-rows button")) {
      control.disabled = working;
    }
  }

  async function run(task) {
    if (working) return;
    working = true;
    controls();
    status.textContent = "Consultando el expediente…";
    try {
      await task();
    } catch (error) {
      status.textContent = error.message;
    } finally {
      working = false;
      controls();
    }
  }

  function listPath() {
    return root + "/" + encodeURIComponent(selector.value);
  }

  function assetChange(method, item) {
    return request(listPath() + "/activo", {
      method, headers: {"Content-Type": "application/json"}, body: JSON.stringify({type: item.type, value: item.value})
    });
  }

  function open(item, latest = false) {
    dialog.close();
    const back = {label: "Volver al seguimiento", open: () => openWatchlists()};
    if (latest) {
      selectRecord(item.latest.id, item.latest.revision, back);
    } else {
      selectAsset({type: item.type, value: item.value, watched: true, back});
    }
  }

  function reviewRow(item) {
    const row = element("li");
    const counts = item.latest ? [
      assetCount(item), item.coverage ? `Cobertura de red · ${item.coverage}` : ""
    ].filter(Boolean).join(" · ") : "Sin evidencia en el expediente";
    row.append(element("span", assetKinds[item.type], "type"), element("p", item.value), element("p", counts, "muted"));
    const actions = element("div", "", "tools");
    const card = element("button", "Abrir ficha");
    card.setAttribute("aria-label", `Abrir ficha de ${item.value}`);
    card.onclick = () => open(item);
    actions.append(card);
    if (item.latest) {
      const last = item.latest;
      row.append(element("p", `${formatTime(last.time)} · ${last.title || last.kind} · rev. ${last.revision}`));
      const citation = element("button", "Abrir última evidencia");
      citation.setAttribute("aria-label", `Abrir última evidencia de ${item.value}`);
      citation.onclick = () => open(item, true);
      actions.append(citation);
    }
    if (canWrite) {
      const remove = element("button", "Quitar");
      remove.setAttribute("aria-label", `Quitar ${item.value} del seguimiento`);
      remove.onclick = () => run(async () => {
        await assetChange("DELETE", item);
        await loadLists(selector.value);
        status.textContent = "Activo retirado de la lista";
      });
      actions.append(remove);
    }
    row.append(actions);
    return row;
  }

  async function loadReview() {
    rows.replaceChildren();
    if (!selector.value) {
      status.textContent = "Sin listas de seguimiento";
      return;
    }
    const review = await request(listPath());
    rows.replaceChildren(...review.rows.map(reviewRow));
    const count = review.rows.length;
    const matched = review.rows.filter((item) => item.latest).length;
    status.textContent = count ? `${count} ${count === 1 ? "activo" : "activos"} · ${matched} con evidencia` : "Lista vacía";
  }

  async function loadLists(preferred) {
    const lists = await request(root);
    selector.replaceChildren(...lists.map((list) => {
      const option = element("option", `${list.name} · ${list.count}`);
      option.value = list.name;
      return option;
    }));
    if (lists.some((list) => list.name === preferred)) selector.value = preferred;
    await loadReview();
  }

  selector.onchange = () => run(loadReview);
  refresh.onclick = () => run(() => loadLists(selector.value));
  create.onsubmit = (event) => {
    event.preventDefault();
    const name = create.elements.nombre.value.trim();
    if (!name) {
      status.textContent = "Introduce un nombre para la lista.";
      return;
    }
    run(async () => {
      await request(root + "/" + encodeURIComponent(name), {method: "PUT"});
      create.reset();
      await loadLists(name);
    });
  };
  add.onsubmit = (event) => {
    event.preventDefault();
    run(async () => {
      const item = {type: add.elements.tipo.value, value: add.elements.valor.value};
      const response = await assetChange("PUT", item);
      add.elements.valor.value = "";
      await loadLists(selector.value);
      status.textContent = response.changed ? "Activo agregado al seguimiento" : "El activo ya está en la lista";
    });
  };
  removeList.onclick = () => {
    const name = selector.value;
    if (!name || !window.confirm(`¿Eliminar la lista «${name}»?`)) return;
    run(async () => {
      await request(listPath(), {method: "DELETE"});
      await loadLists();
    });
  };
  const show = (asset) => {
    if (asset) {
      add.elements.tipo.value = asset.type;
      add.elements.valor.value = asset.value;
    }
    if (!dialog.open) dialog.showModal();
    run(() => loadLists(selector.value));
  };
  byId("open-watchlists").onclick = () => show();
  return show;
})();
