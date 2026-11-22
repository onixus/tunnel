"use strict";
/* Device route groups inside the unified console. Same API as /admin/agent-routes. */
window.DeviceRoutes = {
  mount(root) {
    const $ = (id) => root.querySelector("#" + id);
    const token = document.querySelector('meta[name="route-csrf"]').content;
    let state = { groups: [], devices: [], users: [] },
      editing = null,
      busy = false;
    const message = (text, error) => {
      $("status").textContent = text;
      $("status").classList.toggle("error", !!error);
    };
    async function api(path, method, data, headers) {
      const response = await fetch("/admin/api/agent-routes" + path, {
        method: method || "GET",
        credentials: "same-origin",
        headers: Object.assign(
          { "Content-Type": "application/json", "X-CSRF-Token": token },
          headers || {},
        ),
        body: data === undefined ? undefined : JSON.stringify(data),
      });
      const result = await response.json();
      if (!response.ok)
        throw new Error(
          typeof result.detail === "string" ? result.detail : "Ошибка запроса",
        );
      return result;
    }
    function node(tag, text) {
      const el = document.createElement(tag);
      if (text !== undefined) el.textContent = text;
      return el;
    }
    function button(text, action, cls) {
      const el = node("button", text);
      el.type = "button";
      if (cls) el.className = cls;
      el.addEventListener("click", action);
      return el;
    }
    async function act(action) {
      if (busy) return;
      busy = true;
      root.querySelectorAll("button, select").forEach((el) => {
        el.disabled = true;
      });
      try {
        await action();
        await load();
        message("Сохранено. Клиент получит политику при следующем запросе.");
      } catch (error) {
        message(error.message + ". Обновите состояние перед повтором.", true);
      } finally {
        busy = false;
        root.querySelectorAll("button, select").forEach((el) => {
          el.disabled = false;
        });
        markUnavailable();
      }
    }
    function reset() {
      editing = null;
      $("editor").reset();
      $("editor-title").textContent = "Новая группа";
      $("exclude-lan").checked = true;
    }
    function markUnavailable() {
      root.querySelectorAll("[data-unavailable]").forEach((el) => {
        el.disabled = true;
      });
      $("enroll").disabled = busy || !state.users.length;
    }
    function render() {
      $("groups").replaceChildren();
      if (!state.groups.length)
        $("groups").append(node("p", "Групп пока нет."));
      for (const g of state.groups) {
        const row = node("div");
        row.className = "route-group";
        const title = node("div");
        title.append(node("strong", g.name));
        title.append(node("small", "VPN " + g.include.length + " · исключения " + g.exclude.length + (g.exclude_lan ? " · без LAN" : "")));
        row.append(title);
        const actions = node("div");
        actions.className = "actions";
        actions.append(
          button("Редактировать", () => {
            editing = Object.assign({}, g);
            $("editor-title").textContent = "Редактировать группу";
            $("name").value = g.name;
            $("include").value = g.include.join("\n");
            $("exclude").value = g.exclude.join("\n");
            $("exclude-lan").checked = g.exclude_lan;
          }),
        );
        actions.append(
          button(
            "Удалить",
            () => {
              if (confirm("Удалить группу «" + g.name + "» и её назначения?"))
                act(async () => {
                  await api("/groups/" + g.id, "DELETE", undefined, {
                    "If-Match": String(g.revision),
                  });
                  if (editing && editing.id === g.id) reset();
                });
            },
            "danger",
          ),
        );
        row.append(actions);
        $("groups").append(row);
      }
      $("devices").replaceChildren();
      if (!state.devices.length)
        $("devices").append(node("p", "Устройств пока нет."));
      for (const d of state.devices) {
        const row = node("div");
        row.className = "route-device";
        const title = node("div");
        title.append(node("strong", d.name));
        const fetched = d.fetched_at
          ? "получена " + new Date(d.fetched_at * 1000).toLocaleString()
          : "ещё не запрашивалась";
        title.append(node("small", d.email + " · " + d.platform + " · " + fetched));
        row.append(title);
        const select = node("select");
        select.setAttribute("aria-label", "Группа для " + d.name);
        const none = node("option", "Пользовательская политика");
        none.value = "";
        select.append(none);
        for (const g of state.groups) {
          const option = node("option", g.name);
          option.value = String(g.id);
          select.append(option);
        }
        select.value = d.group_id === null ? "" : String(d.group_id);
        const unavailable =
          d.revoked_at ||
          d.status !== "active" ||
          !d.token_active ||
          !["windows", "macos", "linux"].includes(d.platform);
        if (unavailable) {
          select.dataset.unavailable = "true";
          select.title = "Нужен активный настольный клиент с действующей привязкой.";
        }
        select.addEventListener("change", () => {
          const target = select.value === "" ? null : Number(select.value);
          if (!confirm("Изменить политику устройства «" + d.name + "»?")) {
            select.value = d.group_id === null ? "" : String(d.group_id);
            return;
          }
          act(() =>
            api("/devices/" + d.id, "PUT", {
              group_id: target,
              previous_group_id: d.group_id,
            }),
          );
        });
        row.append(select);
        $("devices").append(row);
      }
      const previous = $("user").value;
      $("user").replaceChildren();
      for (const u of state.users) {
        const option = node("option", u.email);
        option.value = String(u.id);
        $("user").append(option);
      }
      if (state.users.some((u) => String(u.id) === previous))
        $("user").value = previous;
      markUnavailable();
    }
    async function load() {
      state = await api("");
      render();
    }
    const networks = (id) =>
      $(id)
        .value.split(/[\s,]+/)
        .filter(Boolean);
    $("editor").addEventListener("submit", (event) => {
      event.preventDefault();
      const data = {
        name: $("name").value,
        include: networks("include"),
        exclude: networks("exclude"),
        exclude_lan: $("exclude-lan").checked,
      };
      const group = editing;
      act(async () => {
        await api(
          group ? "/groups/" + group.id : "/groups",
          group ? "PUT" : "POST",
          group ? Object.assign(data, { revision: group.revision }) : data,
        );
        reset();
      });
    });
    $("cancel").addEventListener("click", reset);
    $("refresh-routes").addEventListener("click", () => {
      if (!busy)
        load()
          .then(() => message("Состояние обновлено"))
          .catch((e) => message(e.message, true));
    });
    let codeTimer = 0;
    const forgetCode = () => {
      clearTimeout(codeTimer);
      const shown = $("code");
      if (shown) shown.textContent = "";
    };
    this.forget = forgetCode;
    $("enroll").addEventListener("click", () =>
      act(async () => {
        const result = await api("/enrollment-codes", "POST", {
          user_id: Number($("user").value),
        });
        $("code").textContent =
          result.code + " · действует " + result.expires_in + " секунд";
        clearTimeout(codeTimer);
        codeTimer = setTimeout(forgetCode, Math.min(result.expires_in, 180) * 1000);
      }),
    );
    // Clear before the console replaces this page; a detached node would keep the code.
    load().catch((error) => message(error.message, true));
  },
};
