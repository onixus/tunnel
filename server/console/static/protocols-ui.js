/* Protocol lifecycle and container monitoring. Loaded after console.js and routing-ui.js. */
"use strict";
(() => {
  const previousHandle = handle;
  const good = ["running", "active", "healthy"],
    bad = ["exited", "dead", "failed", "unhealthy", "restarting"];
  const names = {
    running: "Работает", active: "Работает", healthy: "Исправен", exited: "Остановлен", inactive: "Остановлен",
    dead: "Сбой", failed: "Сбой", unhealthy: "Неисправен", restarting: "Перезапускается", created: "Создан",
    paused: "Приостановлен", starting: "Запускается", activating: "Запускается", absent: "Не установлен", unknown: "Нет данных",
  };
  const gray = (text) => `<span class="pill gray">${esc(text)}</span>`;
  const status = (s) =>
    good.includes(s) ? pill("active", names[s]) : bad.includes(s) ? pill("failed", names[s]) : ["absent", "inactive", "unknown", ""].includes(s) ? gray(names[s] || "Нет данных") : pill("queued", names[s] || s);
  const busy = () => (state.jobs || []).some((j) => j.action?.startsWith("protocols.") && ["queued", "running"].includes(j.state));
  const item = (id) => (state.protocols?.items || []).find((p) => p.id === id);
  const newer = (p) => {
    const key = (v) => v.split(".").map(Number);
    const after = (a, b) => { const x = key(a), y = key(b); for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); return false; };
    return (p.releases || []).filter((r) => !p.version || after(r.version, p.version));
  };

  function card(p) {
    const off = busy() ? "disabled" : "";
    const action = !p.installed
      ? `<button class="primary" data-action="protocol-install" data-id="${esc(p.id)}" ${off}>Установить${p.latest ? " " + esc(p.latest) : ""}</button>`
      : p.update
        ? `<button class="primary" data-action="protocol-update" data-id="${esc(p.id)}" ${off}>Обновить до ${esc(p.latest)}</button>`
        : `<span class="muted">${p.latest ? "Установлена актуальная версия" : "Версии ещё не проверялись"}</span>`;
    return `<section class="card protocol-card" data-protocol-card="${esc(p.id)}"><div class="service"><div><strong>${esc(p.title)}</strong><small>${esc(p.runtime)}${p.port ? " · UDP " + esc(p.port) : ""}</small></div>${p.installed ? status(p.state) : gray("Не установлен")}</div>
      <dl><dt>Установлена</dt><dd>${esc(p.version || (p.installed ? "версия не определена" : "—"))}</dd><dt>В репозитории</dt><dd>${p.latest ? esc(p.latest) + (p.releases[0].published ? ` <small>от ${esc(p.releases[0].published)}</small>` : "") : "—"}</dd><dt>Источник</dt><dd><a href="${esc(p.repo)}" target="_blank" rel="noopener noreferrer">${esc(p.repo.replace("https://github.com/", ""))} ↗</a></dd></dl>
      ${p.error ? `<p class="error">${esc(p.error)}</p>` : ""}<div class="actions">${action}</div></section>`;
  }

  window.protocolsPage = function () {
    const p = state.protocols;
    const top = heading("Протоколы", "Установка, обновление из репозиториев разработчиков и состояние контейнеров.", `<button data-action="protocol-check" ${busy() ? "disabled" : ""}>Проверить обновления</button>`);
    if (!p || p.error) return top + `<div class="empty">${esc(p?.error || "Агент недоступен. Состояние протоколов неизвестно.")}</div>`;
    return (
      top +
      (busy() ? '<div class="note">Выполняется операция с протоколами. Сборка образа занимает несколько минут; результат появится в журнале.</div>' : "") +
      `<div class="protocol-grid">${p.items.map(card).join("")}</div>
      <p class="subtitle">Версии проверены: ${p.checked ? esc(new Date(p.checked).toLocaleString("ru")) : "ещё не проверялись"}. Загружаются только релизы из указанных репозиториев; хеш сверяется с опубликованным разработчиком.</p>
      <h2>Контейнеры</h2>` +
      (p.containers_error ? `<p class="error">${esc(p.containers_error)}</p>` : "") +
      table(
        ["Контейнер", "Образ", "Состояние", "Проверка", "Перезапуски", "С момента (UTC)", "Порты"],
        p.containers.map(
          (c) =>
            `<tr><td>${esc(c.name)}<small>${esc(c.role || "Прочее")}</small></td><td><code>${esc(c.image)}</code></td><td>${status(c.state)}${c.state === "exited" && c.exit_code ? `<small>код ${esc(c.exit_code)}</small>` : ""}</td><td>${c.health ? status(c.health) : "—"}</td><td>${c.restarts ? pill("queued", String(c.restarts)) : "0"}</td><td>${esc(c.since.replace("T", " "))}</td><td class="wrap">${c.ports.map(esc).join("<br>") || "—"}</td></tr>`,
        ),
      ) +
      `<h2>Службы хоста</h2><div class="card unit-list">${p.units.map((u) => `<div class="service"><div><strong>${esc(u.title)}</strong><small>${esc(u.id)}.service</small></div>${status(u.state)}</div>`).join("")}</div>
      <div class="note">Состояние обновляется автоматически каждые 15 секунд, пока раздел открыт. Установка и обновление выполняются по одной операции и записываются в журнал.</div>`
    );
  };

  const notes = {
    hysteria: {
      install: "Будут загружены ядро Hysteria и H UI 0.0.25, создан системный пользователь и служба h-ui. Ядро останется выключенным до настройки в H UI. Перед установкой закройте TCP 8081 снаружи (ufw insert 1 deny 8081/tcp) — без этого правила установка будет отклонена.",
      update: "H UI будет кратко остановлен, клиенты переподключатся. После запуска проверяется реальный трафик через текущий выход; при ошибке вернётся прежняя версия.",
    },
    trusttunnel: {
      install: "Endpoint из релиза разработчика будет добавлен в текущий образ портала. Контейнер перезапустится.",
      update: "Заменяется только endpoint в текущем образе портала. Контейнер перезапустится, клиенты переподключатся. Обязательна проверка probe; при ошибке вернётся прежний образ.",
    },
    amnezia: {
      install: "Образ собирается из исходников amneziawg-go и amneziawg-tools на закреплённых коммитах (несколько минут). Создаётся контейнер amnezia-awg с новыми ключами и параметрами маскировки.",
      update: "Образ пересобирается из исходников новой версии. Ключи, параметры маскировки и пользователи сохраняются; клиенты кратко переподключатся. При ошибке вернётся прежний контейнер.",
    },
  };

  handle = async function (b) {
    const a = b.dataset.action;
    if (!a.startsWith("protocol-")) return previousHandle(b);
    if (busy()) return notice("Дождитесь завершения текущей операции с протоколами.");
    if (a === "protocol-check") return job("protocols.check", {});
    const p = item(b.dataset.id);
    if (!p) return;
    const update = a === "protocol-update";
    const versions = (update ? newer(p) : p.releases || []).map((r) => `<option value="${esc(r.version)}">${esc(r.version)}${r.published ? " · " + esc(r.published) : ""}</option>`).join("");
    if (update && !versions) return notice("Новых версий нет. Проверьте обновления.");
    modal(
      (update ? "Обновить " : "Установить ") + p.title,
      `<form id="protocol-form"><p>${esc(notes[p.id][update ? "update" : "install"])}</p>
        ${versions ? `<label class="field">Версия из ${esc(p.repo.replace("https://github.com/", ""))}<select name="version">${versions}</select></label>` : '<div class="note">Версии ещё не проверялись: будет установлен последний стабильный релиз разработчика.</div>'}
        ${!update && p.id === "amnezia" ? '<label class="field">UDP-порт AmneziaWG<input type="number" name="port" min="1024" max="65535" value="47443" required></label>' : ""}
        <div class="note">Операция выполняется агентом на сервере и записывается в журнал.</div>
        <div class="actions"><button type="submit" class="primary">${update ? "Обновить" : "Установить"}</button></div></form>`,
    );
    formSubmit("protocol-form", (f) => {
      const data = { component: p.id };
      if (f.get("version")) data.version = f.get("version");
      if (f.get("port")) data.port = Number(f.get("port"));
      return job(update ? "protocols.update" : "protocols.install", data);
    });
  };

  setInterval(() => {
    if (page === "protocols" && !$("#modal").open && !document.hidden) refresh();
  }, 15000);
})();
