/* Service-routing views. Loaded after console.js; all unrelated pages stay unchanged. */
"use strict";
(() => {
  const legacyHandle = handle;
  const exitNames = { primary: "Основной", reserve: "Резервный", direct: "Напрямую", custom: "Особый маршрут", unknown: "Нет данных" };
  const modeNames = { follow: "Общий маршрут", pinned: "Свой маршрут", direct: "Напрямую", unmanaged: "Вне управления" };
  let displayed = null, submitting = false;
  const exitName = id => exitNames[id] || id;
  const busy = () => submitting || state.routing?.pending || (state.jobs || []).some(j => j.action?.startsWith("routes.") && ["queued", "running"].includes(j.state));
  const disabled = () => busy() ? "disabled" : "";
  const services = () => state.routing?.policy?.services || [];
  const snapshot = () => JSON.parse(JSON.stringify(state.routing));
  const frozen = s => s.actual_exit === "direct" ? { mode: "direct" } : { mode: "pinned", exit: s.actual_exit };
  const label = (id, r = state.routing) => id === "direct" ? "Входной сервер" : r?.exits?.find(e => e.id === id)?.host || exitName(id);
  const cancel = '<button type="button" data-action="route-close">Отмена</button>';

  function draw() {
    const board = document.querySelector(".network-board");
    if (!board) return;
    const svg = board.querySelector("svg"), box = board.getBoundingClientRect();
    svg.setAttribute("viewBox", `0 0 ${box.width} ${box.height}`);
    svg.replaceChildren();
    for (const source of board.querySelectorAll("[data-service-node]")) {
      const dest = [...board.querySelectorAll("[data-exit-node]")].find(node => node.dataset.exitNode === source.dataset.route);
      if (!dest) continue;
      const a = source.getBoundingClientRect(), b = dest.getBoundingClientRect();
      const x1 = a.right - box.left, y1 = a.top + a.height / 2 - box.top;
      const x2 = b.left - box.left, y2 = b.top + b.height / 2 - box.top, bend = (x2 - x1) * .5;
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", `M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`);
      path.setAttribute("class", `wire ${source.dataset.serviceNode === "trusttunnel" ? "wire-blue" : ""}`);
      svg.append(path);
    }

  }
  window.addEventListener("resize", () => requestAnimationFrame(draw));

  function map() {
    const r = state.routing, p = r?.policy;
    if (!p || r.error) return '<section class="card"><h2>Карта сети</h2><p class="error">Состояние маршрутов недоступно. Переключение запрещено.</p></section>';
    requestAnimationFrame(draw);
    return `<section class="card network-card"><div class="network-title"><div><div class="eyebrow">ТОПОЛОГИЯ / ВЫХОДЯЩИЙ ТРАФИК</div><h2>Маршруты вашей сети</h2></div><span class="route-group">Общий выход: ${esc(exitName(p.group_exit))}</span></div>
      <p class="subtitle" id="route-help">Нажмите на выход, чтобы переключить выбранные сервисы. На сервис, чтобы назначить ему свой маршрут.</p>
      ${busy() ? '<div class="note">Переключение или восстановление не завершено. Дождитесь результата в журнале.</div>' : ""}
      <div class="network-board"><svg class="route-wires" aria-hidden="true"></svg><div class="service-nodes"><div class="ingress-label"><span class="host-dot"></span> onixus-rf <small>Входной узел</small></div>
      ${p.services.map(s => `<button type="button" class="service-node ${s.id === "trusttunnel" ? "service-blue" : ""}" data-action="route-service" data-service-node="${esc(s.id)}" data-route="${esc(s.actual_exit)}" data-service="${esc(s.id)}" ${!s.configurable || busy() ? "disabled" : ""} aria-label="Настроить маршрут ${esc(s.title)}"><span class="node-kicker">${s.id === "hysteria" ? "01 / QUIC" : "02 / HTTP2 + QUIC"}</span><strong>${esc(s.title)}</strong><span class="service-route">${esc(exitName(s.actual_exit))} <span aria-hidden="true">→</span></span><small>${esc(modeNames[s.mode])}${s.drift ? " · отличается от политики" : ""}</small>${!s.configurable ? `<small class="route-reason">${esc(s.reason)}</small>` : ""}</button>`).join("")}</div>
      <div class="exit-nodes">${[...(r.exits || []), { id: "direct", host: "Входной сервер", via: "Без выходного узла" }].map(e => {
        const assigned = p.services.filter(s => s.actual_exit === e.id);
        return `<button type="button" class="exit-node ${assigned.length ? "exit-used" : ""}" data-action="route-exit" data-exit-node="${esc(e.id)}" data-exit="${esc(e.id)}" ${disabled()} aria-describedby="route-help"><span class="node-kicker">${esc(exitName(e.id))}${e.id === p.group_exit ? " · ОБЩИЙ" : ""}</span><strong>${esc(e.host)}</strong><small>${esc(e.via)}</small><span class="exit-members">${assigned.map(s => `<span class="route-tag ${s.id === "trusttunnel" ? "tag-blue" : ""}">${s.id === "hysteria" ? "Hysteria" : "TrustTunnel"}</span>`).join("") || '<span class="muted">Выбрать этот выход →</span>'}</span></button>`;
      }).join("")}</div></div><div class="network-foot"><span><span class="legend-dot"></span> Hysteria <span class="legend-dot blue"></span> TrustTunnel / R-TrustTunnel</span><span>SSH, панель и трафик сервера: напрямую</span></div><p class="route-disclaimer">Линии показывают прочитанную конфигурацию, не онлайн-доступность. Реальное подключение проверяется при применении. Исключения Hysteria и локальный DNS сохраняются.</p></section>`;
  }

  overview = function () {
    const h = Array.isArray(state.hysteria_users) ? state.hysteria_users : [];
    return heading("Вся сеть. Ваши маршруты.", "Общий выход или отдельный путь для каждого VPN. Изменения только после подтверждения.", btn("Настроить сервисы", "navigate", 'data-target="routing"')) +
      `<div class="stats"><div class="stat"><label>УЧЁТНЫЕ ЗАПИСИ</label><strong>${(state.users || []).length + h.length + (Array.isArray(state.amnezia_users) ? state.amnezia_users.length : 0)}</strong><small>TrustTunnel, Hysteria и AmneziaWG</small></div><div class="stat"><label>ВЫХОДНЫЕ УЗЛЫ</label><strong>${state.routing?.exits?.length ?? "?"}</strong><small>Плюс прямой выход</small></div><div class="stat"><label>ОБЩИЙ МАРШРУТ</label><strong class="stat-word">${esc(exitName(state.routing?.policy?.group_exit || "unknown"))}</strong><small>${services().filter(s => s.mode === "follow").length} сервис(а) следует группе</small></div><div class="stat"><label>АКТИВНЫЕ КЛЮЧИ</label><strong>${(state.keys || []).filter(k => !k.revoked_at).length}</strong><small>TrustTunnel / R-TrustTunnel</small></div></div>` + map() +
      `<div class="routing-bottom"><section class="card"><h2>Состояние сервисов</h2>${[["Hysteria 2", "hysteria"], ["TrustTunnel", "trusttunnel"], ["AmneziaWG 3.1", "amnezia"]].map(([name, id]) => `<div class="service"><strong>${name}</strong>${servicePill(id)}</div>`).join("")}<div class="service"><strong>Обновления R-TrustTunnel</strong>${pill("running", "seq " + (state.updates?.active_sequence ?? "?"))}</div></section><section class="card"><h2>Каналы доставки</h2><div class="service"><strong>Telegram</strong>${pill(state.telegram?.running ? "active" : "unknown", state.telegram?.running ? "Работает" : "Нет связи")}</div><div class="service"><strong>E-mail</strong>${pill(state.smtp ? "active" : "unknown", state.smtp ? "Настроен" : "Не настроен")}</div><p class="subtitle">Управляющие сервисы не участвуют в переключении VPN-выходов.</p></section></div><h2>Последние операции</h2>${jobsTable((state.jobs || []).slice(0, 5))}`;
  };

  function controls(r) {
    return `<label class="field">Общий маршрут<select id="group-exit">${r.exits.map(e => `<option value="${esc(e.id)}" ${r.policy.group_exit === e.id ? "selected" : ""}>${esc(exitName(e.id))} · ${esc(e.host)}</option>`).join("")}</select></label><div class="policy-services">${r.policy.services.map(s => `<div class="policy-service" data-policy-service="${esc(s.id)}"><div><strong>${esc(s.title)}</strong><small>Сейчас: ${esc(exitName(s.actual_exit))}${s.drift ? " · есть расхождение" : ""}</small></div><label class="field">Участие в переключении<select class="service-mode" aria-label="Режим ${esc(s.title)}" ${!s.configurable ? "disabled" : ""}>${Object.entries(modeNames).filter(([k]) => k !== "unmanaged" || s.mode === k).map(([k, name]) => `<option value="${k}" ${s.mode === k ? "selected" : ""}>${esc(name)}</option>`).join("")}</select></label><label class="field pinned-field" ${s.mode !== "pinned" ? "hidden" : ""}>Свой выход<select class="service-exit" aria-label="Выход ${esc(s.title)}" ${!s.configurable ? "disabled" : ""}>${r.exits.filter(e => s.available_exits.includes(e.id)).map(e => `<option value="${esc(e.id)}" ${s.exit === e.id ? "selected" : ""}>${esc(exitName(e.id))} · ${esc(e.host)}</option>`).join("")}</select></label>${!s.configurable ? `<p class="route-reason">${esc(s.reason)}</p>` : ""}</div>`).join("")}</div>`;
  }

  routing = function () {
    const r = state.routing;
    displayed = r?.policy ? snapshot() : null;
    if (!displayed) return heading("Маршрутизация", "Состояние агента недоступно") + map();
    const names = Object.fromEntries(r.exits.map(e => [e.name, e.id]));
    const rows = r.rules.slice(3, -1).filter(v => !["local(all, udp/53, 127.0.0.1)", "local(all, tcp/53, 127.0.0.1)"].includes(v)).map(v => {
      const m = v.match(/^([a-zA-Z0-9_-]+)\((suffix:|geoip:)?([^()]+)\)$/);
      return m ? routeRow(names[m[1]] || m[1], m[2]?.slice(0, -1) || "cidr", m[3]) : `<p class="error">Неподдерживаемое правило: ${esc(v)}</p>`;
    }).join("");
    return heading("Каждому сервису свой путь.", "Общий маршрут переключает только участников группы. Закреплённые и прямые сервисы остаются на месте.") + map() +
      `<div class="routing-bottom"><section class="card"><h2>Политика сервисов</h2>${controls(r)}<div class="note">R-TrustTunnel использует тот же endpoint, что и TrustTunnel. Это один маршрут, а не отдельный сервис.</div><div class="actions">${btn("Проверить изменения", "route-settings", disabled(), "primary")}</div></section><section class="card"><h2>Безопасное применение</h2><p>До применения вы увидите маршрут каждого затронутого сервиса и список тех, которые останутся без изменений.</p><p>Проверка выхода, резервная копия и контрольный запрос через VPN обязательны. При ошибке выполняется откат; неподтверждённое восстановление блокирует следующие изменения.</p><div class="note">Перезапускаются только сервисы, чей выход действительно меняется. Их клиенты кратко переподключатся.</div><h2>Локальная фильтрация DNS</h2>${pill(state.adblock?.running && state.adblock?.dns_interception ? "active" : "unknown", state.adblock?.running && state.adblock?.dns_interception ? "Работает" : "Не подтверждено")}<p class="subtitle">Доменов: ${esc(state.adblock?.domains ?? "?")}; ru/su: ${esc(state.adblock?.ru_su_domains ?? "?")}. Последнее обновление: ${esc(state.adblock?.last_success ?? "нет данных")}</p>${btn("Обновить списки", "refresh-adblock")}<p class="subtitle">Внешний DoH/DoT и прямой обход VPN могут обходить локальные фильтры.</p></section></div><section class="card"><h2>Исключения Hysteria</h2><p class="subtitle">Применяются до выхода ${esc(exitName(r.selected))}. Карта не удаляет и не переставляет исключения.</p>${["primary", "reserve"].includes(r.selected) ? `<div id="route-rules">${rows}</div>${btn("+ Правило", "add-rule")}<div class="actions">${btn("Проверить исключения", "route-exceptions", disabled())}</div>` : '<p class="note">На прямом или нестандартном выходе старый редактор исключений недоступен. Карта сохраняет исключения; для их редактирования сначала выберите основной или резервный выход.</p>'}<details><summary>Все текущие правила</summary><pre>${esc(r.rules.join("\n"))}</pre></details></section>`;
  };

  function request(r, values, group = r.policy.group_exit) {
    return { revision: r.policy.revision, group_exit: group, services: values };
  }
  async function preview(data, form) {
    const button = form.querySelector('[type="submit"]');
    button.disabled = true;
    try {
      const plan = await api("routing/preview", data);
      if (!form.isConnected || !document.querySelector("#modal").open) return;
      confirmation(data, plan);
    } catch (e) {
      if (!form.isConnected || !document.querySelector("#modal").open) return;
      form.querySelector(".route-error").textContent = e.message;
      button.disabled = false;
    }
  }
  function confirmation(data, plan) {
    const key = crypto.randomUUID();
    modal("Подтвердить маршруты", `<p>Общий выход: <strong>${esc(exitName(data.group_exit))}</strong></p>${table(["Сервис", "Сейчас", "После подтверждения"], plan.changes.map(c => `<tr><td>${esc(c.title)}</td><td>${esc(exitName(c.before))}<small>${esc(modeNames[c.mode_before])}</small></td><td>${esc(exitName(c.after))}<small>${esc(modeNames[c.mode_after])} · ${c.restart ? "с переподключением" : "без перезапуска"}</small></td></tr>`))}<div class="note"><strong>Без изменений</strong><p>${plan.untouched.map(s => `${esc(s.title)}: ${esc(exitName(s.exit))}`).join("<br>") || "Все выбранные VPN-сервисы указаны выше."}</p>SSH, панель и системные маршруты остаются прямыми. Исключения Hysteria сохраняются.</div><p class="route-error" role="alert"></p><div class="actions">${cancel}<button type="button" class="primary" id="confirm-service-routes">Подтвердить переключение</button></div>`);
    const button = document.querySelector("#confirm-service-routes"), error = document.querySelector("#modal-body .route-error");
    button.onclick = async () => {
      if (submitting) return;
      submitting = true; button.disabled = true;
      try {
        const result = await api("routing/jobs", { data, confirm: true, request_id: key });
        document.querySelector("#modal").close();
        routeDirty = false;
        notice("Переключение в очереди. Текущий маршрут изменится на карте после проверки.");
        await refresh();
        pollJob(result.id);
      } catch (e) {
        error.textContent = e.message + " Повтор отправит тот же запрос без создания второй операции.";
        button.disabled = false;
      } finally { submitting = false; }
    };
  }

  function chooseExit(id) {
    const r = snapshot();
    if (!["direct", ...r.exits.map(e => e.id)].includes(id)) return;
    modal("Выход: " + exitName(id), `<p>${esc(label(id, r))}</p><p>Отметьте сервисы для переключения. Снятые с выбора участники общего маршрута сохранят текущий выход и будут закреплены за ним.</p><form id="map-route-form">${r.policy.services.map(s => `<label class="route-choice"><input type="checkbox" name="service" value="${esc(s.id)}" ${s.mode === "follow" && s.configurable ? "checked" : ""} ${!s.configurable || !s.available_exits.includes(id) ? "disabled" : ""}><span><strong>${esc(s.title)}</strong><small>${esc(exitName(s.actual_exit))} · ${esc(modeNames[s.mode])}</small>${!s.configurable ? `<small class="route-reason">${esc(s.reason)}</small>` : ""}</span></label>`).join("")}<p class="route-error" role="alert"></p><div class="actions">${cancel}<button type="submit" class="primary">Проверить изменения</button></div></form>`);
    const form = document.querySelector("#map-route-form");
    form.onsubmit = e => {
      e.preventDefault();
      const selected = new Set(new FormData(form).getAll("service"));
      if (!selected.size) { form.querySelector(".route-error").textContent = "Выберите хотя бы один сервис."; return; }
      const values = {};
      for (const s of r.policy.services) {
        if (selected.has(s.id)) values[s.id] = { mode: id === "direct" ? "direct" : "follow" };
        else if (s.mode === "follow" && s.configurable) values[s.id] = frozen(s);
      }
      preview(request(r, values, id === "direct" ? r.policy.group_exit : id), form);
    };
  }
  function chooseService(id) {
    const r = snapshot(), s = r.policy.services.find(v => v.id === id);
    if (!s?.configurable) return;
    modal(s.title + " · маршрут", `<form id="service-route-form">${controls({ ...r, policy: { ...r.policy, services: [s] } })}<p class="note">Изменится только настройка этого сервиса. Общий выход и остальные сервисы останутся без изменений.</p><p class="route-error" role="alert"></p><div class="actions">${cancel}<button type="submit" class="primary">Проверить изменения</button></div></form>`);
    const form = document.querySelector("#service-route-form");
    form.querySelector("#group-exit").closest("label").hidden = true;
    form.onsubmit = e => { e.preventDefault(); preview(request(r, { [id]: readMode(form) }), form); };
  }
  function readMode(root) {
    const value = root.querySelector(".service-mode").value;
    return value === "pinned" ? { mode: value, exit: root.querySelector(".service-exit").value } : { mode: value };
  }
  document.addEventListener("change", e => {
    if (e.target.matches(".service-mode")) e.target.closest(".policy-service").querySelector(".pinned-field").hidden = e.target.value !== "pinned";
  });
  handle = async function (button) {
    const action = button.dataset.action;
    if (action === "route-close") { document.querySelector("#modal").close(); return; }
    if (!action.startsWith("route-")) return legacyHandle(button);
    if (button.disabled || busy()) return;
    if (!state.routing?.policy) throw Error("Обновите состояние агента.");
    if ((action === "route-exit" || action === "route-service") && routeDirty) throw Error("Сначала примените настройки формы или обновите страницу после отмены изменений.");
    if (action === "route-exit") return chooseExit(button.dataset.exit);
    if (action === "route-service") return chooseService(button.dataset.service);
    if (action === "route-settings") {
      const values = {};
      for (const row of document.querySelectorAll("#content [data-policy-service]")) {
        const s = displayed.policy.services.find(v => v.id === row.dataset.policyService);
        if (s.configurable) {
          const proposed = readMode(row);
          const saved = s.mode === "pinned" ? { mode: s.mode, exit: s.exit } : { mode: s.mode };
          if (JSON.stringify(proposed) !== JSON.stringify(saved)) values[s.id] = proposed;
        }
      }
      const data = request(displayed, values, document.querySelector("#group-exit").value);
      const plan = await api("routing/preview", data);
      return confirmation(data, plan);
    }
    if (action === "route-exceptions") {
      if (document.querySelector("#route-rules .error")) throw Error("Нестандартные правила: применение через редактор запрещено.");
      const rules = [...document.querySelectorAll("#route-rules .route-row")].map(r => ({ target: r.children[0].value, kind: r.children[1].value, value: r.children[2].value }));
      const data = { exit: displayed.selected, rules, revision: displayed.revision };
      confirmJob("Применить исключения Hysteria", "Общий выход и TrustTunnel не меняются. Защищённые правила сохраняются; Hysteria кратко перезапустится.", "routes.apply", data);
      document.querySelector("#confirm-action").onclick = async () => {
        const submit = document.querySelector("#confirm-action");
        submit.disabled = true;
        const wasDirty = routeDirty;
        try {
          routeDirty = false;
          await job("routes.apply", data);
        } catch (error) {
          routeDirty = wasDirty;
          notice(error.message, true);
          document.querySelector("#modal").close();
        }
      };
      return;
    }
  };
  // Initial fetch may have completed before this deferred entrypoint was evaluated.
  if (state.routing) render();
})();
