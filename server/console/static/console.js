"use strict";
const $ = (s) => document.querySelector(s),
  esc = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
let state = {},
  page = "overview",
  personId = null,
  loading = false,
  routeDirty = false;
const titles = {
  overview: "Обзор сети",
  users: "Пользователи",
  person: "Пользователи",
  keys: "Ключи и устройства",
  routing: "Маршрутизация",
  protocols: "Протоколы",
  updates: "Обновления",
  campaigns: "Рассылки",
  telegram: "Telegram",
  audit: "Журнал операций",
};
const labels = {
  queued: "В очереди",
  running: "Выполняется",
  success: "Выполнено",
  failed: "Ошибка",
  unknown: "Не подтверждено",
  active: "Активен",
  blocked: "Заблокирован",
  draft: "Черновик",
  accepted: "Принято провайдером",
  partial: "Частично",
  pending: "Ожидает",
  skipped: "Пропущено",
  sending: "Отправляется",
};
const pill = (s, t) =>
  `<span class="pill ${["failed", "blocked", "unknown"].includes(s) ? "red" : ["queued", "draft", "partial"].includes(s) ? "warn" : ["running", "pending"].includes(s) ? "blue" : ""}">${esc(t || labels[s] || s)}</span>`;
const heading = (title, sub, buttons = "") =>
  `<div class="heading"><div><div class="eyebrow">ONIXUS / CONTROL PLANE</div><h1>${title}</h1><p class="subtitle">${sub}</p></div>${buttons}</div>`;
const table = (heads, rows, { className = "", label = "" } = {}) =>
  `<div class="table-wrap${className ? " " + esc(className) : ""}"${label ? ` role="region" aria-label="${esc(label)}" tabindex="0"` : ""}><table><thead><tr>${heads.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("") || `<tr><td colspan="${heads.length}" class="empty">Пока нет данных</td></tr>`}</tbody></table></div>`;
const btn = (label, action, extra = "", cls = "") =>
  `<button class="${cls}" data-action="${action}" ${extra}>${label}</button>`;
const bytes = (n) =>
  n >= 1073741824
    ? (n / 1073741824).toFixed(1) + " GB"
    : (n / 1048576).toFixed(1) + " MB";
function notice(text, error = false) {
  $("#notice").textContent = text;
  $("#notice").classList.toggle("error", error);
  // The page notice sits behind an open dialog: repeat errors inside it.
  if ($("#modal").open) {
    $("#modal-error").textContent = error ? text : "";
    $("#modal-error").hidden = !error;
  }
}
async function api(path, data) {
  const r = await fetch("/console/api/" + path, {
    method: data === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": $("meta[name=csrf-token]").content,
    },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  let value;
  try {
    value = await r.json();
  } catch {
    throw Error("Сервис недоступен. Обновите состояние перед повтором.");
  }
  if (!r.ok) throw Error(value.detail || "Ошибка запроса");
  return value;
}
async function refresh(renderPage = true) {
  if (loading) return;
  loading = true;
  try {
    state = await api("state");
    $("#freshness").textContent =
      "Снимок · " + new Date(state.observed_at).toLocaleTimeString("ru");
    if (renderPage) render();
    if (state.error) notice(state.error, true);
  } catch (e) {
    notice(e.message, true);
    $("#freshness").textContent = "Нет связи";
  } finally {
    loading = false;
  }
}
function modal(title, html) {
  $("#modal-title").textContent = title;
  $("#modal-error").hidden = true;
  $("#modal-error").textContent = "";
  $("#modal-body").innerHTML = html;
  $("#modal").showModal();
}
async function job(action, data) {
  const result = await api("jobs", {
    action,
    data,
    confirm: true,
    request_id: crypto.randomUUID(),
  });
  $("#modal").close();
  notice("Операция поставлена в очередь. Результат появится в журнале.");
  await refresh();
  pollJob(result.id);
}
async function pollJob(id) {
  for (let i = 0; i < 100; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    await refresh(false);
    const j = state.jobs?.find((j) => j.id === id);
    if (j && !["queued", "running"].includes(j.state)) {
      let result = {};
      try {
        result = JSON.parse(j.result || "{}");
      } catch {}
      notice(result.message || labels[j.state], j.state !== "success");
      // A freshly created user opens straight into their card.
      if (j.action === "person.create" && result.id) {
        personId = result.id;
        page = "person";
      }
      if (!routeDirty) render();
      return;
    }
  }
  notice("Операция ещё выполняется. Проверьте журнал позже.");
}
function confirmJob(title, description, action, data) {
  modal(
    title,
    `<p>${esc(description)}</p><div class="note">Изменение будет записано в журнал операций.</div><div class="actions"><button id="confirm-action" class="primary">Подтвердить</button></div>`,
  );
  $("#confirm-action").onclick = async () => {
    const b = $("#confirm-action");
    b.disabled = true;
    try {
      await job(action, data);
    } catch (e) {
      notice(e.message, true);
      b.disabled = false;
    }
  };
}
function serviceState(k) {
  return (
    state.services?.[k] ||
    (state.protocols?.items || []).find((p) => p.id === k)?.state
  );
}
function servicePill(k) {
  const s = serviceState(k);
  // A protocol that was never installed is not a failure.
  return s === "absent"
    ? '<span class="pill gray">Не установлен</span>'
    : pill(["active", "running"].includes(s) ? "active" : "unknown", s || "Нет данных");
}
function overview() {
  const h = Array.isArray(state.hysteria_users) ? state.hysteria_users : [],
    u = state.users || [],
    awg = Array.isArray(state.amnezia_users) ? state.amnezia_users : [],
    cdn = Array.isArray(state.cdn_users) ? state.cdn_users : [],
    r = state.routing || {},
    services = state.services || {};
  return (
    heading(
      "Вся сеть. Один пульт.",
      "Пользователи, доступ и выходные узлы вашей VPN-инфраструктуры.",
      pill("active", "ONIXUS-RF"),
    ) +
    `<div class="stats"><div class="stat"><label>УЧЁТНЫЕ ЗАПИСИ</label><strong>${u.length + h.length + awg.length + cdn.length}</strong><small>${u.length} TrustTunnel · ${h.length} Hysteria · ${awg.length} AmneziaWG · ${cdn.length} CDN</small></div><div class="stat"><label>КЛЮЧИ TRUSTTUNNEL</label><strong>${(state.keys || []).filter((k) => !k.revoked_at).length}</strong><small>Действующие учётные данные</small></div><div class="stat"><label>ВЫХОДЫ HYSTERIA</label><strong>${r.exits?.length ?? "—"}</strong><small>Выбран: ${esc(r.selected || "неизвестно")}</small></div><div class="stat"><label>УСТРОЙСТВА ПОРТАЛА</label><strong>${(state.devices || []).filter((d) => !d.revoked_at).length}</strong><small>Регистрации клиентов</small></div></div><div class="grid"><div class="card"><h2>Карта выходных узлов</h2><p class="subtitle">Текущая политика Hysteria 2</p><div class="topology"><div class="node current"><strong>onixus-rf</strong><small>Входящий VPN</small>${pill("active", "INGRESS")}</div><div class="flow">→</div><div class="exit-stack">${(r.exits || []).map((e) => `<div class="node ${e.id === r.selected ? "current" : ""}"><strong>${esc(e.host)}</strong><small>${esc(e.via)}</small>${pill(e.id === r.selected ? "active" : "queued", e.id === r.selected ? "ВЫБРАН" : "ДОСТУПЕН ДЛЯ ВЫБОРА")}</div>`).join("") || '<p class="error">Нет данных агента</p>'}</div></div><div class="note">TrustTunnel и сам сервер выходят напрямую. Исключения Hysteria обрабатываются раньше общего маршрута. Доступность выходов проверяется отдельно.</div>${btn("Управлять маршрутами →", "navigate", 'data-target="routing"', "subtle")}</div><div class="stack"><div class="card"><h2>Сервисы</h2>${[
      ["Hysteria 2", "hysteria", "QUIC / UDP · 443"],
      ["TrustTunnel", "trusttunnel", "HTTP/2 + QUIC · 8443"],
      ["AmneziaWG 3.1", "amnezia", "WireGuard с маскировкой · UDP"],
      ["VLESS через CDN", "cdn", "Xray · WebSocket/XHTTP · TCP"],
    ]
      .map(
        ([n, k, d]) =>
          `<div class="service"><div><strong>${n}</strong><small>${d}</small></div>${servicePill(k)}</div>`,
      )
      .join(
        "",
      )}<div class="service"><div><strong>R-TrustTunnel</strong><small>Клиенты и подписанные обновления</small></div>${pill("running", "seq " + (state.updates?.active_sequence ?? "—"))}</div></div><div class="card"><h2>Каналы доставки</h2><div class="service"><div><strong>Telegram</strong><small>Существующий приватный бот</small></div>${pill(state.telegram?.running ? "active" : "unknown", state.telegram?.running ? "Работает" : "Нет связи")}</div><div class="service"><div><strong>E-mail</strong><small>SMTP из настроек TrustTunnel</small></div>${pill(state.smtp ? "active" : "unknown", state.smtp ? "Настроен" : "Не настроен")}</div></div></div></div><div class="heading"><h2>Последние операции</h2></div>${jobsTable((state.jobs || []).slice(0, 5))}`
  );
}
const list = (v) => (Array.isArray(v) ? v : []);
const SOURCES = ["trusttunnel", "hysteria", "amnezia", "cdn"];
const SOURCE_NAMES = { trusttunnel: "TrustTunnel", hysteria: "Hysteria", amnezia: "AmneziaWG", cdn: "VLESS · CDN" };
const accounts = (source) => (source === "trusttunnel" ? state.users || [] : list(state[source + "_users"]));
const account = (source, id) => accounts(source).find((u) => u.id === id);
const accountName = (source, u) => (source === "trusttunnel" ? u?.email : u?.username) || "#" + (u?.id ?? "?");
const blocked = (source, u) => (source === "trusttunnel" ? u.status === "blocked" : !!u.deleted);
const personOf = (source, id) => (state.people || []).find((p) => p.accounts[source] === id);
// A protocol whose account list cannot be read is not installed or not reachable.
const available = (source) => source === "trusttunnel" || Array.isArray(state[source + "_users"]);
const loginsFor = (nick, email) => ({
  trusttunnel: email || `${nick}@${state.user_domain || "домен"}`,
  hysteria: nick.length >= 6 ? nick : nick + "-vpn",
  amnezia: nick,
  cdn: nick,
});
function accountButtons(source, u, linked) {
  const d = `data-source="${source}" data-id="${u.id}"`,
    off = blocked(source, u);
  const own =
    source === "trusttunnel"
      ? (linked ? "" : btn("Ключ", "user-key", `data-id="${u.id}"`)) + btn("Пароль", "password", `data-id="${u.id}"`)
      : btn(source === "amnezia" ? "Конфиг" : source === "cdn" ? "Ссылка" : "Ключ", "export", d) +
        btn("QR-код", "export-qr", d) +
        btn("Сменить ключ", "rotate", d) +
        (source === "hysteria" ? btn("Лимиты", "hysteria-limits", `data-id="${u.id}"`) : "");
  return (
    own +
    btn("Отправить", "send-config", d) +
    (linked ? "" : btn("Контакт", "contact", d) + btn("Привязать", "link-account", d)) +
    btn(off ? "Включить" : "Блокировать", "status", `${d} data-block="${!off}"`) +
    btn("Удалить", "delete-account", d, "danger")
  );
}
function accountUsage(source, u) {
  if (source === "hysteria") return `${bytes(u.download + u.upload)}<small>До ${new Date(u.expire_time).toLocaleDateString("ru")}</small>`;
  if (source === "amnezia")
    return `${bytes(u.download + u.upload)}<small>${esc(u.address)} · ${u.handshake ? "связь " + new Date(u.handshake * 1000).toLocaleString("ru") : "ещё не подключался"}</small>`;
  if (source === "cdn") return `<small>с ${esc(u.created)}</small>`;
  return `<small>Ключей: ${(state.keys || []).filter((k) => k.user_id === u.id && !k.revoked_at).length}</small>`;
}
function users() {
  const people = state.people || [];
  const loose = SOURCES.flatMap((source) => accounts(source).filter((u) => !personOf(source, u.id)).map((u) => [source, u]));
  return (
    heading(
      "Пользователи",
      "Один пользователь — один ник. Учётки протоколов, ключи и устройства создаются и управляются в его карточке.",
      btn("+ Новый пользователь", "new-user", "", "primary"),
    ) +
    `<div class="toolbar"><input id="user-search" placeholder="Поиск по нику, e-mail или логину" aria-label="Поиск пользователей"></div>` +
    table(
      ["Пользователь", "Протоколы", "Устройства", "Управление"],
      people.map((p) => {
        const linked = SOURCES.filter((s) => p.accounts[s] !== undefined),
          tt = p.accounts.trusttunnel,
          devices = (state.devices || []).filter((d) => d.user_id === tt && !d.revoked_at).length,
          names = linked.map((s) => accountName(s, account(s, p.accounts[s]))).join(" ");
        return `<tr data-search="${esc([p.nick, p.email, names].join(" ").toLowerCase())}"><td><button class="link" data-action="person-open" data-id="${p.id}">${esc(p.nick)}</button><small>${esc(p.email || "")}${p.chat_id ? " · tg " + esc(p.chat_id) : ""}</small></td><td>${
          linked
            .map((s) => {
              const u = account(s, p.accounts[s]);
              return u ? pill(blocked(s, u) ? "blocked" : "active", SOURCE_NAMES[s]) : '<span class="pill gray">' + SOURCE_NAMES[s] + " · нет данных</span>";
            })
            .join(" ") || '<span class="muted">Нет учёток</span>'
        }</td><td>${tt !== undefined ? devices : "—"}</td><td>${btn("Открыть", "person-open", `data-id="${p.id}"`, "primary")}</td></tr>`;
      }),
    ) +
    (loose.length
      ? `<h2>Учётки без пользователя</h2><p class="subtitle">Созданы до появления карточек или вне консоли. Привяжите их к пользователю, чтобы управлять в одном месте.</p>` +
        table(
          ["Учётка", "Протокол", "Доступ", "Использование", "Управление"],
          loose.map(
            ([source, u]) =>
              `<tr data-search="${esc(accountName(source, u).toLowerCase())}"><td>${esc(accountName(source, u))}<small>#${u.id}</small></td><td>${pill("running", SOURCE_NAMES[source])}</td><td>${pill(blocked(source, u) ? "blocked" : "active")}</td><td>${accountUsage(source, u)}</td><td>${accountButtons(source, u, false)}</td></tr>`,
          ),
        )
      : "") +
    (state.hysteria_users?.error ? '<p class="note">Hysteria временно недоступна.</p>' : "")
  );
}
function personPage() {
  const p = (state.people || []).find((p) => p.id === personId);
  if (!p) return heading("Пользователь не найден", "Возможно, он удалён.", btn("← К списку", "navigate", 'data-target="users"'));
  const tt = p.accounts.trusttunnel;
  const sections = SOURCES.map((source) => {
    const id = p.accounts[source];
    if (id === undefined)
      return `<div class="card account-card"><div class="service"><div><strong>${SOURCE_NAMES[source]}</strong><small>Учётки нет · логин будет ${esc(loginsFor(p.nick, p.email)[source])}</small></div>${available(source) ? btn("+ Создать учётку", "person-add", `data-id="${p.id}" data-source="${source}"`, "primary") : '<span class="pill gray">Не установлен</span>'}</div></div>`;
    const u = account(source, id);
    if (!u)
      return `<div class="card account-card"><div class="service"><div><strong>${SOURCE_NAMES[source]}</strong><small>#${id} · нет данных от сервиса</small></div>${btn("Отвязать", "unlink-account", `data-source="${source}" data-id="${id}"`)}</div></div>`;
    let extra = "";
    if (source === "trusttunnel") {
      const keys = (state.keys || []).filter((k) => k.user_id === id),
        devices = (state.devices || []).filter((d) => d.user_id === id);
      extra =
        `<h3>Ключи</h3>` +
        table(
          ["Ключ", "Статус", "Действия"],
          keys.map(
            (k) =>
              `<tr><td>${esc(k.label || "Без названия")}<small>${esc(k.tt_username)}${k.device_id ? " · устройство" : ""}</small></td><td>${pill(k.revoked_at ? "blocked" : "active", k.revoked_at ? "Отозван" : "Действует")}</td><td>${
                (!k.revoked_at
                  ? btn("Показать", "export", `data-source="trusttunnel" data-id="${k.id}"`) +
                    btn("QR-код", "export-qr", `data-source="trusttunnel" data-id="${k.id}"`) +
                    (k.device_id ? "" : btn("Ротация", "rotate", `data-source="trusttunnel" data-id="${k.id}"`) + btn("Отозвать", "revoke", `data-id="${k.id}"`))
                  : "") + (k.device_id ? "" : btn("Удалить", "key-delete", `data-id="${k.id}"`, "danger"))
              }</td></tr>`,
          ),
        ) +
        `<div class="actions">${btn("+ Ключ", "user-key", `data-id="${id}"`)}</div><h3>Устройства R-TrustTunnel</h3>` +
        table(
          ["Устройство", "Платформа", "Активность", "Статус", "Действия"],
          devices.map(
            (d) =>
              `<tr><td>${esc(d.name)}</td><td>${esc(d.platform)}</td><td>${esc(d.last_seen_at || "—")}</td><td>${pill(d.revoked_at ? "blocked" : "active", d.revoked_at ? "Отозвано" : "Активно")}</td><td>${(d.revoked_at ? "" : btn("Отозвать", "device-revoke", `data-id="${d.id}"`)) + btn("Удалить", "device-delete", `data-id="${d.id}"`, "danger")}</td></tr>`,
          ),
        ) +
        `<div class="actions">${btn("+ Привязать устройство", "device-enroll", `data-id="${id}"`, "primary")}</div>`;
    }
    return `<div class="card account-card"><div class="service"><div><strong>${SOURCE_NAMES[source]}</strong><small>${esc(accountName(source, u))} · #${u.id}</small></div>${pill(blocked(source, u) ? "blocked" : "active")}</div><p class="subtitle">${accountUsage(source, u)}</p><div class="actions wrap">${accountButtons(source, u, true)}${btn("Отвязать", "unlink-account", `data-source="${source}" data-id="${id}"`, "subtle")}</div>${extra}</div>`;
  });
  return (
    heading(
      esc(p.nick),
      `Создан ${esc(p.created)}. Все учётки, ключи и устройства пользователя.`,
      `<div class="actions">${btn("← К списку", "navigate", 'data-target="users"', "subtle")}${btn("Блокировать всё", "person-status", `data-id="${p.id}" data-block="true"`)}${btn("Включить всё", "person-status", `data-id="${p.id}" data-block="false"`)}${btn("Удалить пользователя", "person-delete", `data-id="${p.id}"`, "danger")}</div>`,
    ) +
    `<div class="card"><h2>Контакты</h2><div class="service"><div><strong>E-mail</strong><small>${esc(p.email || "не задан")}</small></div><div><strong>Telegram</strong><small>${esc(p.chat_id || "не задан")}</small></div>${pill(p.consent ? "active" : "unknown", p.consent ? "Согласие получено" : "Нет согласия")}${btn("Изменить", "person-contact", `data-id="${p.id}"`)}</div></div>` +
    `<div class="stack">${sections.join("")}</div>` +
    (tt === undefined ? '<p class="note">Привязка устройств R-TrustTunnel доступна после создания учётки TrustTunnel.</p>' : "")
  );
}
function keys() {
  return (
    heading(
      "Ключи и устройства",
      "Секреты раскрываются только по отдельному запросу. Отзыв VPN-ключа прекращает доступ.",
    ) +
    table(
      ["Владелец / ключ", "Протокол", "Статус", "Действия"],
      (state.keys || []).map(
        (k) =>
          `<tr><td>${esc(k.email)}<small>${esc(k.tt_username)} · ${esc(k.label)}</small></td><td>TrustTunnel</td><td>${pill(k.revoked_at ? "blocked" : "active", k.revoked_at ? "Отозван" : "Действует")}</td><td>${!k.revoked_at ? btn("Показать / скачать", "export", `data-source="trusttunnel" data-id="${k.id}"`) + btn("QR-код", "export-qr", `data-source="trusttunnel" data-id="${k.id}"`) + btn("Ротация", "rotate", `data-source="trusttunnel" data-id="${k.id}"`) + btn("Отозвать", "revoke", `data-id="${k.id}"`) : ""}${!k.device_id ? btn("Удалить", "key-delete", `data-id="${k.id}"`, "danger") : ""}</td></tr>`,
      ),
    ) +
    `<div class="note">Новые ключи и привязка устройств — в карточке пользователя (раздел «Пользователи»). API-регистрация устройства и VPN-ключ имеют отдельные сроки и отзыв.</div><h2>Регистрации R-TrustTunnel</h2>` +
    table(
      ["Устройство", "Владелец", "Платформа", "Последняя активность", "Статус"],
      (state.devices || []).map(
        (d) =>
          `<tr><td>${esc(d.name)}</td><td>${esc((state.users || []).find((u) => u.id === d.user_id)?.email || "#" + d.user_id)}</td><td>${esc(d.platform)}</td><td>${esc(d.last_seen_at || "—")}</td><td>${pill(d.revoked_at ? "blocked" : "active")}${!d.revoked_at ? btn("Отозвать", "device-revoke", `data-id="${d.id}"`) : ""}${btn("Удалить", "device-delete", `data-id="${d.id}"`, "danger")}</td></tr>`,
      ),
    )
  );
}
function routeRow(target = "local", kind = "suffix", value = "") {
  const targets = ["local", "primary", "reserve", "clean", "reject"].filter((t) => t !== "clean" || target === "clean" || (state.routing?.exits || []).some((e) => e.id === "clean"));
  return `<div class="route-row"><select aria-label="Выход">${targets.map((t) => `<option value="${t}" ${t === target ? "selected" : ""}>${{ local: "Напрямую", primary: "Основной", reserve: "Резервный", clean: "Чистый IP", reject: "Блокировать" }[t]}</option>`).join("")}</select><select aria-label="Тип правила">${["suffix", "geoip", "cidr"].map((k) => `<option ${k === kind ? "selected" : ""}>${k}</option>`).join("")}</select><input aria-label="Домен или сеть" value="${esc(value)}" placeholder="example.com"><button data-action="remove-rule" aria-label="Удалить правило">×</button></div>`;
}
function routing() {
  const r = state.routing;
  if (!r || r.error)
    return (
      heading("Маршрутизация", "Управление выходами") +
      '<div class="empty">Агент маршрутизации недоступен</div>'
    );
  const names = Object.fromEntries(r.exits.map((e) => [e.name, e.id]));
  const rules = r.rules
    .slice(3, -1)
    .filter((v) => !["local(all, udp/53, 127.0.0.1)", "local(all, tcp/53, 127.0.0.1)"].includes(v))
    .map((v) => {
      const m = v.match(/^([a-zA-Z0-9_-]+)\((suffix:|geoip:)?([^()]+)\)$/);
      return m
        ? routeRow(names[m[1]] || m[1], m[2]?.slice(0, -1) || "cidr", m[3])
        : `<p class="error">Неподдерживаемое правило: ${esc(v)}</p>`;
    })
    .join("");
  return (
    heading(
      "Маршрутизация",
      "Приоритет сверху вниз. Сначала исключения, затем общий выход.",
      btn("Проверить оба выхода", "check-routes"),
    ) +
    `<div class="grid"><div class="card"><h2>Hysteria · общий выход</h2><label class="field">Весь трафик, не попавший под исключения<select id="route-exit">${r.exits.filter((e) => e.id !== "clean").map((e) => `<option value="${esc(e.id)}" ${e.id === r.selected ? "selected" : ""}>${esc(e.id)} · ${esc(e.host)}</option>`).join("")}</select></label><h2>Исключения</h2><div id="route-rules">${rules}</div>${btn("+ Правило", "add-rule")}<div class="actions">${btn("Проверить изменения", "preview-routes", "", "primary")}</div></div><div class="stack"><div class="card"><h2>Область действия</h2><div class="service"><strong>Hysteria 2</strong>${pill("active", r.selected)}</div><div class="service"><strong>TrustTunnel</strong>${pill("running", "Напрямую")}</div><div class="service"><strong>Трафик сервера</strong>${pill("running", "Напрямую")}</div><div class="note">Правила Hysteria не меняют egress TrustTunnel или системную таблицу маршрутов.</div></div><div class="card"><h2>Локальная фильтрация рекламы</h2>${(state.adblock?.running && state.adblock?.dns_interception) ? pill("active", "Работает") : pill("unknown", "Не подтверждено")}<p class="subtitle">Доменов: ${esc(state.adblock?.domains ?? "—")}; ru/su: ${esc(state.adblock?.ru_su_domains ?? "—")}. Ежедневное обновление из нескольких источников.</p><p class="subtitle">Последний успех: ${esc(state.adblock?.last_success ?? "—")}</p><p class="subtitle">Следующее обновление: ${esc(state.adblock?.next_update ?? "—")}</p>${state.adblock?.last_error ? `<p class="error">${esc(state.adblock.last_error)}</p>` : ""}<ul>${(state.adblock?.sources || []).map((s) => `<li>${esc(s.id)}: ${esc(s.domains)}</li>`).join("")}</ul>${btn("Обновить списки", "refresh-adblock")}<p class="subtitle">Hysteria и TrustTunnel/Rust: обычный DNS внутри VPN фильтруется на сервере. Внешний DoH/DoT в профиле нужно отключить для применения локальных списков. Собственный DoH браузера и прямой обход VPN могут обходить фильтры. Зоны ru/su целиком не заблокированы.</p><h2>Защита применения</h2><p class="subtitle">Перед применением проверяется выход. После — реальный запрос через Hysteria. При сбое восстанавливается предыдущая конфигурация.</p><p class="subtitle">Доступ к панелям, блокировка приватных сетей и перенаправление DNS в локальный фильтр сохраняются. Переключение кратко переподключит клиентов.</p><details><summary>Текущие правила</summary><pre>${esc(r.rules.join("\n"))}</pre></details></div></div></div>`
  );
}
const versionKey = (v) => String(v || "").split(".").map(Number);
const newerVersion = (a, b) => {
  const x = versionKey(a), y = versionKey(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0);
  return false;
};
// Whole days still left, rounded up; a past timestamp is negative.
const daysLeft = (ts) => (ts * 1000 <= Date.now() ? -1 : Math.ceil((ts * 1000 - Date.now()) / 86400000));
function updates() {
  const u = state.updates || {},
    up = u.upstream || {},
    published = (u.releases || []).filter((r) => r.version).reduce((m, r) => (!m || newerVersion(r.version, m) ? r.version : m), null),
    latest = (up.releases || [])[0],
    activeLeft = u.active_expires ? daysLeft(u.active_expires) : null;
  let alerts = "";
  if (latest && (!published || newerVersion(latest.version, published)))
    alerts += `<div class="note warn">На GitHub вышел R-TrustTunnel <b>${esc(latest.version)}</b> (${esc(latest.published)}), а на сервере самый новый — ${esc(published || "нет")}. Нажмите «Выложить» в таблице релизов GitHub ниже, затем «Опубликовать» в канале Windows. <a href="${esc(latest.url)}" target="_blank" rel="noopener noreferrer">Релиз ${esc(latest.tag)} ↗</a></div>`;
  if (up.signing)
    alerts += `<div class="note warn">Выкладка недоступна: ${esc(up.signing)}. Положите PKCS#8-ключ подписи обновлений на сервер в этот файл (владелец root, права 0600).</div>`;
  if (activeLeft !== null && activeLeft < 7)
    alerts += `<div class="note error">${activeLeft < 0 ? "Манифест активного канала Windows истёк" : `Манифест активного канала Windows истекает через ${activeLeft} дн.`} (${new Date(u.active_expires * 1000).toLocaleDateString("ru")}). Клиенты не примут обновление из истёкшего канала: опубликуйте новый подписанный релиз.</div>`;
  if (up.error) alerts += `<p class="error">${esc(up.error)}</p>`;
  return (
    heading(
      "Обновления",
      "Подписанные клиентские релизы и подготовленные пакеты серверов.",
      btn("Проверить GitHub", "check-client-releases"),
    ) +
    alerts +
    `<div class="note">Публикация канала не устанавливает обновление на устройства. Клиент проверяет подпись, срок, хеш и защиту от понижения версии. Подписанный манифест действует не дольше 31 дня.</div><h2>R-TrustTunnel · Windows</h2>` +
    table(
      ["Релиз", "Цель", "Проверка", "Действует до", "Канал", "Действие"],
      (u.releases || []).map((r) => {
        const left = r.expires ? daysLeft(r.expires) : null;
        return `<tr><td>${esc(r.version || r.id)}<small>sequence ${esc(r.sequence || r.id)}</small></td><td>${esc(r.target || "windows-x86_64")}</td><td>${pill(r.valid ? "active" : "unknown", r.valid ? "Подпись и срок ОК" : r.reason || "Недействителен")}</td><td>${r.expires ? esc(new Date(r.expires * 1000).toLocaleDateString("ru")) + `<small>${left < 0 ? "истёк" : "осталось " + left + " дн."}</small>` : "—"}</td><td>${r.active ? pill("active", "Текущий") : "Архив / кандидат"}</td><td>${r.valid && !r.active && r.sequence >= (u.active_sequence || 0) ? btn("Опубликовать", "promote", `data-sequence="${r.sequence}"`) : "—"}</td></tr>`;
      }),
    ) +
    `<h2>Релизы на GitHub</h2><p class="subtitle">${up.checked ? "Проверено " + esc(new Date(up.checked).toLocaleString("ru")) + ". " : "Ещё не проверялось. "}Стабильные релизы с установщиком Windows и опубликованным SHA-256 из <a href="${esc(up.repo || "https://github.com/onixus/Rust-trustvpn")}" target="_blank" rel="noopener noreferrer">onixus/Rust-trustvpn ↗</a>. Проверка идёт автоматически раз в 6 часов.</p>` +
    table(
      ["Версия", "Опубликован", "Сборка", "На сервере", "Действие"],
      (up.releases || []).map((r) => {
        const staged = (u.releases || []).some((x) => x.sequence === r.sequence || x.version === r.version),
          fetching = (state.jobs || []).some((j) => j.action === "updates.fetch" && ["queued", "running"].includes(j.state)),
          build = r.build_error
            ? `<span class="error">${esc(r.build_error)}</span>`
            : r.root_ok === false
              ? '<span class="error">Другой корень обновлений</span>'
              : `sequence ${esc(r.sequence)}<small>IPC ${esc(r.ipc)} · ${esc((r.size / 1048576).toFixed(1))} MB</small>`,
          action =
            staged || r.build_error || r.root_ok === false
              ? "—"
              : btn("Выложить", "client-fetch", `data-version="${esc(r.version)}" data-sequence="${esc(r.sequence)}" ${up.signing || fetching ? "disabled" : ""}`, "primary");
        return `<tr><td><a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.version)} ↗</a></td><td>${esc(r.published)}</td><td>${build}</td><td>${staged ? pill("active", "Выложен") : pill("queued", "Не выложен")}</td><td>${action}</td></tr>`;
      }),
    ) +
    `<div class="note">Полный хеш установщика проверяется перед публикацией. Истёкшие манифесты не публикуются повторно.</div><h2>Серверные пакеты</h2>` +
    table(
      ["Компонент", "Версия", "Действие"],
      (u.server_packages || []).map(
        (p) =>
          `<tr><td>${esc(p.component)}</td><td>${esc(p.version)}</td><td>${btn("Установить", "server-update", `data-package="${esc(p.id)}"`)}</td></tr>`,
      ),
    ) +
    `<p class="note">Пакеты предварительно готовятся оператором на сервере. Произвольные файлы и команды из браузера не исполняются. Linux-клиенты получают обновления через существующий Flatpak-репозиторий.</p><a href="/rtrust/releases/linux-candidate/R-TrustTunnel.flatpakref">Скачать Flatpakref ↗</a>`
  );
}
function campaigns() {
  return (
    heading(
      "Рассылки",
      "Черновик → проверка получателей → подтверждённая отправка.",
      btn("+ Новая рассылка", "new-campaign", "", "primary"),
    ) +
    table(
      ["Тема", "Канал", "Статус", "Создана", "Действие"],
      (state.campaigns || []).map(
        (c) =>
          `<tr><td>${esc(c.subject)}</td><td>${esc(c.channel)}</td><td>${pill(c.state)}</td><td>${esc(c.created)}</td><td>${btn("Открыть", "campaign-detail", `data-id="${c.id}"`)}</td></tr>`,
      ),
    ) +
    `<div class="note">Получатели добавляются через «Контакт» в разделе пользователей с явным согласием. Доставка каждого адресата фиксируется отдельно; после неоднозначного сбоя автоматического повтора нет.</div>`
  );
}
function telegram() {
  const t = state.telegram || {};
  return (
    heading("Telegram", "Интеграция с существующим приватным ботом.") +
    `<div class="grid"><div class="card"><h2>Бот управления</h2><div class="service"><strong>Сервис</strong>${pill(t.running ? "active" : "unknown", t.running ? "Работает" : "Нет данных")}</div><div class="service"><strong>Токен</strong>${pill(t.configured ? "active" : "unknown", t.configured ? "На сервере" : "Не настроен")}</div><div class="service"><strong>Владелец</strong><code>${esc(t.owner || "—")}</code></div><div class="note">Токен не передаётся в браузер. Управляющие команды бота доступны только владельцу в личном чате.</div></div><div class="card"><h2>Доставка пользователям</h2><p class="subtitle">Укажите Telegram user ID в контакте пользователя и зафиксируйте согласие. Получатель должен сначала открыть существующего бота и нажать Start.</p><p class="subtitle">Для отправки создайте рассылку в канале Telegram, проверьте адресатов и подтвердите.</p>${btn("Открыть рассылки →", "navigate", 'data-target="campaigns"')}</div></div><h2>Контакты Telegram</h2>` +
    table(
      ["Учётная запись", "Telegram ID", "Согласие"],
      (state.contacts || [])
        .filter((c) => c.chat_id)
        .map(
          (c) =>
            `<tr><td>${esc(c.source)} #${c.user_id}</td><td>${c.chat_id}</td><td>${pill(c.consent ? "active" : "blocked", c.consent ? "Получено" : "Нет")}</td></tr>`,
        ),
    )
  );
}
function jobsTable(jobs) {
  return table(
    ["Операция", "Статус", "Результат", "Время"],
    jobs.map((j) => {
      let r = {};
      try {
        r = JSON.parse(j.result || "{}");
      } catch {}
      return `<tr><td><code>${esc(j.action)}</code></td><td>${pill(j.state)}</td><td class="wrap">${esc(r.message || "—")}</td><td>${esc(j.updated)}</td></tr>`;
    }),
  );
}
function journal() {
  return (
    heading(
      "Журнал операций",
      "Результаты применения и действия администраторов.",
    ) +
    jobsTable(state.jobs || []) +
    `<div class="note">Не подтверждено — операция была прервана. Сначала проверьте фактическое состояние; повтор может создать дубликат.</div>` +
    table(
      ["Администратор", "Действие", "Результат", "Время"],
      (state.audit || []).map(
        (a) =>
          `<tr><td>#${a.actor}</td><td><code>${esc(a.action)}</code></td><td>${esc(a.detail)}</td><td>${esc(a.at)}</td></tr>`,
      ),
    )
  );
}
function render() {
  const map = {
    overview,
    users,
    person: personPage,
    keys,
    routing,
    protocols: () => protocolsPage(),
    updates,
    campaigns,
    telegram,
    audit: journal,
  };
  // A deleted user's card falls back to the list.
  if (page === "person" && !(state.people || []).some((p) => p.id === personId)) page = "users";
  $("#content").innerHTML = map[page]();
  document.querySelectorAll("#content .primary").forEach((button, index) => {
    if (index > 0) button.classList.remove("primary");
  });
  $("#breadcrumb").textContent = titles[page];
  document
    .querySelectorAll("nav button")
    .forEach((b) => b.classList.toggle("selected", b.dataset.page === (page === "person" ? "users" : page)));
  if (page === "users")
    $("#user-search").oninput = () =>
      document
        .querySelectorAll("tr[data-search]")
        .forEach((r) => (r.hidden = !r.dataset.search.includes($("#user-search").value.toLowerCase())));
  if (page === "routing") {
    $("#content").oninput = () => (routeDirty = true);
  } else {
    $("#content").oninput = null;
    routeDirty = false;
  }
}
function navigate(target) {
  page = target;
  routeDirty = false;
  render();
}
function formSubmit(id, callback) {
  $("#" + id).onsubmit = async (e) => {
    e.preventDefault();
    const b = e.target.querySelector("[type=submit]");
    if (b) b.disabled = true;
    try {
      await callback(new FormData(e.target));
    } catch (err) {
      notice(err.message, true);
    } finally {
      if (b) b.disabled = false;
    }
  };
}
async function handle(b) {
  const a = b.dataset.action,
    id = Number(b.dataset.id),
    source = b.dataset.source;
  if (a === "navigate") return navigate(b.dataset.target);
  if (a === "new-user") {
    modal(
      "Новый пользователь",
      `<form id="user-form"><label class="field">Ник<input name="nick" required minlength="3" maxlength="32" pattern="[a-z0-9][a-z0-9_\\-]{2,31}" autocomplete="off" placeholder="ivan"><small class="muted">Латиница в нижнем регистре, цифры, «-», «_». Из ника строятся логины всех протоколов.</small></label><label class="field">E-mail (необязательно)<input type="email" name="email" maxlength="200" placeholder="ivan@example.com"><small class="muted">Станет логином TrustTunnel и адресом для отправки конфигов. Без него логин — ник@${esc(state.user_domain || "домен")}.</small></label><label class="field">Telegram user ID (необязательно)<input name="chat" inputmode="numeric"></label><label><input type="checkbox" name="consent"> Получено согласие на уведомления</label><h3>Протоколы</h3><div class="contact-list">${SOURCES.map(
        (s) =>
          `<label><input type="checkbox" name="protocol" value="${s}" ${available(s) ? "checked" : "disabled"}> ${SOURCE_NAMES[s]} <small class="muted" data-login="${s}"></small>${available(s) ? "" : ' <small class="muted">(не установлен)</small>'}</label>`,
      ).join("")}</div><div class="note">Учётки, ключи и конфиги создаются автоматически: TrustTunnel — учётка и основной ключ; Hysteria — ключ на 365 дней, до 3 устройств; AmneziaWG — ключи и адрес; CDN — UUID VLESS. Устройства R-TrustTunnel привязываются потом из карточки.</div><div class="actions"><button type="submit" class="primary">Создать</button></div></form>`,
    );
    const form = $("#user-form"),
      preview = () => {
        const names = loginsFor(form.nick.value.trim().toLowerCase() || "ник", form.email.value.trim().toLowerCase());
        form.querySelectorAll("[data-login]").forEach((el) => (el.textContent = "· " + names[el.dataset.login]));
      };
    form.oninput = preview;
    preview();
    formSubmit("user-form", async (f) => {
      const protocols = f.getAll("protocol");
      if (!protocols.length) throw Error("Выберите хотя бы один протокол");
      await job("person.create", {
        nick: f.get("nick").trim().toLowerCase(),
        email: f.get("email").trim(),
        chat_id: f.get("chat") ? Number(f.get("chat")) : null,
        consent: f.get("consent") === "on",
        protocols,
      });
    });
  }
  if (a === "person-open") {
    personId = id;
    return navigate("person");
  }
  if (a === "person-add")
    confirmJob(
      "Создать учётку " + SOURCE_NAMES[source],
      "Учётка и ключи будут созданы автоматически, логин строится из ника пользователя.",
      "person.add",
      { id, source },
    );
  if (a === "person-status")
    confirmJob(
      "Изменить доступ",
      b.dataset.block === "true" ? "Заблокировать все учётки пользователя?" : "Включить все учётки пользователя?",
      b.dataset.block === "true" ? "person.block" : "person.unblock",
      { id },
    );
  if (a === "person-delete")
    confirmJob(
      "Удалить пользователя",
      "Будут безвозвратно удалены все его учётки, ключи и устройства во всех протоколах. Уже выданные конфиги перестанут работать.",
      "person.delete",
      { id },
    );
  if (a === "delete-account")
    confirmJob(
      "Удалить учётку " + SOURCE_NAMES[source],
      "Учётка и её ключи будут безвозвратно удалены, доступ прекратится. Это нельзя отменить.",
      source + ".delete",
      { id },
    );
  if (a === "key-delete")
    confirmJob("Удалить ключ", "Ключ будет удалён безвозвратно, доступ по нему прекратится.", "trusttunnel.key-delete", { id });
  if (a === "device-delete")
    confirmJob(
      "Удалить устройство",
      "Устройство будет отозвано (если ещё нет) и удалено вместе с его ключами.",
      "trusttunnel.device-delete",
      { id },
    );
  if (a === "unlink-account") {
    await api("people/unlink", { source, user_id: id });
    notice("Учётка отвязана. Доступ не изменён.");
    await refresh();
  }
  if (a === "link-account") {
    const u = account(source, id),
      suggestion = accountName(source, u).split("@")[0].toLowerCase().replace(/[^a-z0-9_-]/g, "").slice(0, 32);
    modal(
      "Привязать учётку",
      `<form id="link-form"><p>${SOURCE_NAMES[source]} · ${esc(accountName(source, u))}</p><label class="field">Пользователь<select name="person"><option value="">Новый пользователь…</option>${(state.people || [])
        .filter((p) => p.accounts[source] === undefined)
        .map((p) => `<option value="${p.id}">${esc(p.nick)}</option>`)
        .join("")}</select></label><label class="field">Ник нового пользователя<input name="nick" value="${esc(suggestion)}" maxlength="32"></label><div class="note">Доступ и ключи не меняются. Контакт учётки станет контактом пользователя.</div><div class="actions"><button type="submit" class="primary">Привязать</button></div></form>`,
    );
    formSubmit("link-form", async (f) => {
      const r = await api("people/link", f.get("person") ? { source, user_id: id, person: Number(f.get("person")) } : { source, user_id: id, nick: f.get("nick") });
      $("#modal").close();
      notice("Учётка привязана");
      personId = r.id;
      await refresh(false);
      navigate("person");
    });
  }
  if (a === "person-contact") {
    const p = (state.people || []).find((p) => p.id === id);
    modal(
      "Контакты · " + p.nick,
      `<form id="contact-form"><label class="field">E-mail<input type="email" name="email" value="${esc(p.email)}"></label><label class="field">Telegram user ID<input name="chat" inputmode="numeric" value="${esc(p.chat_id)}"></label><label><input type="checkbox" name="consent" ${p.consent ? "checked" : ""}> Получено согласие на уведомления</label><div class="note">Контакт применяется ко всем учёткам пользователя. Логин TrustTunnel не меняется.</div><div class="actions"><button type="submit" class="primary">Сохранить</button></div></form>`,
    );
    formSubmit("contact-form", async (f) => {
      await api("people/contact", { id, email: f.get("email"), chat_id: f.get("chat") ? Number(f.get("chat")) : null, consent: f.get("consent") === "on" });
      $("#modal").close();
      notice("Контакт сохранён");
      await refresh();
    });
  }
  if (a === "device-enroll") {
    const r = await api("enroll", { id });
    modal(
      "Привязать устройство",
      `<p>Откройте R-TrustTunnel на устройстве и отсканируйте QR-код или откройте ссылку на нём. Код одноразовый и действует <b id="enroll-left">${r.expires_in}</b> с.</p>${r.qr_data_url ? `<img class="qr" src="${r.qr_data_url}" alt="QR-код привязки устройства">` : `<p class="error">${esc(r.qr_error)}</p>`}<label class="field">Ссылка<input readonly value="${esc(r.content)}"></label><label class="field">Ссылка для приложения на этом же устройстве<input readonly value="${esc(r.app_link)}"></label><div class="note">После привязки устройство появится в карточке пользователя и получит собственный ключ VPN.</div>`,
    );
    const until = Date.now() + r.expires_in * 1000,
      timer = setInterval(() => {
        const left = Math.max(0, Math.round((until - Date.now()) / 1000));
        if (!$("#enroll-left")) return clearInterval(timer);
        $("#enroll-left").textContent = left;
        if (!left) {
          clearInterval(timer);
          notice("Код истёк. Создайте новый.", true);
        }
      }, 1000);
  }
  if (a === "status")
    confirmJob(
      "Изменить доступ",
      b.dataset.block === "true"
        ? "Заблокировать пользователя и отключить его VPN-доступ?"
        : "Восстановить доступ пользователя?",
      source + (b.dataset.block === "true" ? ".block" : ".unblock"),
      { id },
    );
  if (a === "user-key")
    confirmJob(
      "Новый ключ TrustTunnel",
      "Выпустить ключ? Endpoint кратко перезапустится для применения.",
      "trusttunnel.key",
      { id },
    );
  if (a === "rotate")
    confirmJob(
      "Ротация ключа",
      "Старый ключ перестанет работать. Потребуется передать новый профиль пользователю. Клиенты могут переподключиться.",
      source + ".rotate",
      { id },
    );
  if (a === "revoke")
    confirmJob(
      "Отозвать ключ",
      "VPN-доступ по этому ключу будет прекращён. Endpoint кратко перезапустится.",
      "trusttunnel.revoke",
      { id },
    );
  if (a === "device-revoke")
    confirmJob(
      "Отозвать устройство",
      "Будут отозваны API-регистрация и привязанные VPN-ключи устройства.",
      "trusttunnel.device-revoke",
      { id },
    );
  if (a === "hysteria-limits") {
    const u = list(state.hysteria_users).find((u) => u.id === id);
    modal(
      "Срок и лимиты Hysteria",
      `<form id="limits-form"><label class="field">Продлить от сегодня, дней<input type="number" name="days" min="1" max="3650" value="365" required></label><label class="field">Одновременные устройства<input type="number" name="devices" min="1" max="100" value="${u.device_no || 3}" required></label><label class="field">Общая квота GB (-1 = без лимита)<input type="number" name="quota" min="-1" max="100000" value="${u.quota < 0 ? -1 : Math.ceil(u.quota / 1073741824)}" required></label><button type="submit" class="primary">Применить</button></form>`,
    );
    formSubmit("limits-form", (f) =>
      job("hysteria.update", {
        id,
        days: Number(f.get("days")),
        devices: Number(f.get("devices")),
        quota_gb: Number(f.get("quota")),
      }),
    );
  }
  if (a === "password") {
    modal(
      "Пароль пользователя",
      `<form id="password-form"><label class="field">Новый пароль<input type="password" name="password" minlength="12" maxlength="128" required autocomplete="new-password"></label><button type="submit" class="primary">Сохранить</button></form>`,
    );
    formSubmit("password-form", async (f) => {
      await api("password", { id, password: f.get("password") });
      $("#modal").close();
      notice("Пароль изменён");
    });
  }
  if (a === "export" || a === "export-qr") {
    showConfigExport(source, id, a === "export-qr");
  }
  if (a === "send-config") {
    const c =
        (state.contacts || []).find(
          (c) => c.source === source && c.user_id === id,
        ) || {},
      user = account(source, id),
      email = c.email || (source === "trusttunnel" ? user?.email : ""),
      chat = c.chat_id,
      option = (value, label, address, extra = "") =>
        `<label><input type="checkbox" name="channel" value="${value}" ${address ? "checked" : "disabled"}> ${label}: ${address ? esc(address) : "не задан"}${extra}</label>`;
    modal(
      "Отправить конфигурацию",
      `<form id="send-config-form"><p>${esc({ hysteria: "Hysteria", amnezia: "AmneziaWG", cdn: "VLESS через CDN" }[source] || "TrustTunnel")} · ${esc(user?.email || user?.username || "#" + id)}</p>${option("email", "E-mail", email, state.smtp ? "" : " <small>(SMTP не настроен)</small>")}${option("telegram", "Telegram", chat)}<div class="note">Будут отправлены ссылка, QR-код и файл конфигурации со всеми данными доступа${source === "trusttunnel" ? " для каждого действующего ключа" : ""}. Получатель Telegram должен заранее открыть бота и нажать Start (бот сообщит его ID). Адреса меняются кнопкой «Контакт».</div><div class="actions"><button type="submit" class="primary">Отправить</button></div></form>`,
    );
    formSubmit("send-config-form", async (f) => {
      const channels = f.getAll("channel");
      if (!channels.length) throw new Error("Выберите хотя бы один канал");
      await job("config.send", { source, id, channels });
    });
  }
  if (a === "contact") {
    const c =
      (state.contacts || []).find(
        (c) => c.source === source && c.user_id === id,
      ) || {};
    modal(
      "Контакт пользователя",
      `<form id="contact-form"><label class="field">E-mail<input type="email" name="email" value="${esc(c.email)}"></label><label class="field">Telegram user ID<input name="chat" inputmode="numeric" value="${esc(c.chat_id)}"></label><label><input type="checkbox" name="consent" ${c.consent ? "checked" : ""}> Получено согласие на уведомления</label><div class="actions"><button type="submit" class="primary">Сохранить</button></div></form>`,
    );
    formSubmit("contact-form", async (f) => {
      await api("contacts", {
        source,
        id,
        email: f.get("email"),
        chat_id: f.get("chat") ? Number(f.get("chat")) : null,
        consent: f.get("consent") === "on",
      });
      $("#modal").close();
      notice("Контакт сохранён");
      await refresh();
    });
  }
  if (a === "add-rule") {
    $("#route-rules").insertAdjacentHTML("beforeend", routeRow());
    routeDirty = true;
  }
  if (a === "remove-rule") {
    b.closest(".route-row").remove();
    routeDirty = true;
  }
  if (a === "refresh-adblock") confirmJob("Обновить локальные списки", "Загрузить списки из настроенных источников? При ошибке останется последняя рабочая версия.", "adblock.refresh", {});
  if (a === "check-routes") await job("routes.check", {});
  if (a === "check-client-releases") await job("protocols.check", {});
  if (a === "client-fetch")
    confirmJob(
      "Выложить R-TrustTunnel " + b.dataset.version,
      `Сервер скачает установщик с GitHub, сверит SHA-256, подпишет манифест (sequence ${b.dataset.sequence}, действует 30 дней) и положит его в канал. Клиенты получат обновление только после «Опубликовать».`,
      "updates.fetch",
      { version: b.dataset.version },
    );
  if (a === "preview-routes") {
    if ($("#route-rules .error"))
      throw Error("Есть неподдерживаемые правила. Применение запрещено.");
    const rules = [...document.querySelectorAll(".route-row")].map((r) => ({
      target: r.children[0].value,
      kind: r.children[1].value,
      value: r.children[2].value,
    }));
    const data = {
      exit: $("#route-exit").value,
      rules,
      revision: state.routing.revision,
    };
    confirmJob(
      "Применить маршруты",
      `Выход: ${data.exit}. Исключений: ${rules.length}. Защищённые правила сохраняются. Hysteria кратко перезапустится; при ошибке проверки сработает откат.`,
      "routes.apply",
      data,
    );
    routeDirty = false;
  }
  if (a === "promote")
    confirmJob(
      "Опубликовать обновление",
      "Переключить канал Windows на sequence " + b.dataset.sequence + "?",
      "updates.promote",
      { sequence: Number(b.dataset.sequence) },
    );
  if (a === "server-update")
    confirmJob(
      "Обновить серверный компонент",
      "Установить подготовленный пакет? Возможен краткий перерыв VPN.",
      "updates.server",
      { package: b.dataset.package },
    );
  if (a === "new-campaign") {
    modal(
      "Новая рассылка",
      `<form id="campaign-form"><label class="field">Канал<select name="channel"><option value="email">E-mail</option><option value="telegram">Telegram</option></select></label><label class="field">Тема<input name="subject" required maxlength="160"></label><label class="field">Текст<textarea name="body" maxlength="3300" required></textarea></label><h3>Получатели с согласием</h3><div class="contact-list">${
        (state.contacts || [])
          .filter((c) => c.consent)
          .map(
            (c) =>
              `<label><input type="checkbox" name="recipient" value="${esc(c.source)}:${c.user_id}">${esc(c.source)} #${c.user_id} · ${esc(c.email || c.chat_id)}</label>`,
          )
          .join("") || '<p class="muted">Добавьте контакты пользователей.</p>'
      }</div><button type="submit" class="primary">Сохранить черновик</button></form>`,
    );
    formSubmit("campaign-form", async (f) => {
      const r = await api("campaigns", {
        channel: f.get("channel"),
        subject: f.get("subject"),
        body: f.get("body"),
        recipients: f.getAll("recipient").map((v) => {
          const [source, id] = v.split(":");
          return { source, id: Number(id) };
        }),
      });
      $("#modal").close();
      notice("Черновик сохранён. Сообщения не отправлены.");
      await refresh();
      await showCampaign(r.id);
    });
  }
  if (a === "campaign-detail") await showCampaign(b.dataset.id);
}
async function showCampaign(id) {
  const c = await api("campaigns/" + id);
  modal(
    "Рассылка · " + c.subject,
    `<p>${pill(c.state)} · ${esc(c.channel)}</p><pre>${esc(c.body)}</pre>${table(
      ["Получатель", "Статус"],
      c.deliveries.map(
        (d) =>
          `<tr><td>${esc(d.recipient)}</td><td>${pill(d.state)}<small>${esc(d.error || "")}</small></td></tr>`,
      ),
    )}${c.state === "draft" ? '<div class="actions"><button id="send-campaign" class="primary">Подтвердить отправку всем указанным получателям</button></div>' : ""}`,
  );
  if ($("#send-campaign"))
    $("#send-campaign").onclick = async () => {
      try {
        $("#send-campaign").disabled = true;
        await job("campaign.send", { id });
      } catch (e) {
        notice(e.message, true);
        $("#modal").close();
      }
    };
}
document.addEventListener("click", (e) => {
  const nav = e.target.closest("[data-page]");
  if (nav) navigate(nav.dataset.page);
  const b = e.target.closest("[data-action]");
  if (b) handle(b).catch((e) => notice(e.message, true));
});
$("#refresh").onclick = () => {
  if (routeDirty) {
    notice(
      "Сначала примените изменения маршрутов или перейдите в другой раздел.",
    );
    return;
  }
  refresh();
};
$("#modal").addEventListener("close", () => {
  if (!$("#modal").open) $("#modal-body").replaceChildren();
});
refresh();
