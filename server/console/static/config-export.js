"use strict";

// Uses the console's authenticated API and modal; no third-party QR service.
function showConfigExport(source, id, preferQr = false) {
  modal(
    "Экспорт VPN-конфигурации",
    `<section id="config-export" class="config-export">
      <p class="note">QR-код и ссылка содержат секрет подключения. Передавайте их только владельцу.</p>
      <button id="reveal" class="primary">${preferQr ? "Показать QR-код" : "Показать ключ"}</button>
      <p class="export-status" role="status" aria-live="polite"></p>
    </section>`,
  );
  const dialog = $("#modal"), root = $("#config-export");
  const current = () => dialog.open && root.isConnected;
  const urls = new Set();
  let exported = null;
  function clear() {
    exported = null;
    for (const url of urls) URL.revokeObjectURL(url);
    urls.clear();
    root.replaceChildren();
    dialog.removeEventListener("close", clear);
    dialog.removeEventListener("cancel", clear);
    window.removeEventListener("pagehide", clear);
  }
  dialog.addEventListener("close", clear);
  dialog.addEventListener("cancel", clear);
  window.addEventListener("pagehide", clear);

  function save(content, type, extension) {
    if (!current() || !exported) return;
    const url = URL.createObjectURL(new Blob([content], { type }));
    urls.add(url);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${source}-${id}.${extension}`;
    link.hidden = true;
    root.append(link);
    link.click();
    link.remove();
    setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 1000);
  }

  root.querySelector("#reveal").onclick = async (event) => {
    const button = event.currentTarget;
    if (button.disabled) return;
    button.disabled = true;
    root.querySelector(".export-status").textContent = "Получаем конфигурацию…";
    try {
      const result = await api("export", { source, id, consent: true, qr: true });
      // A late response must not disclose this key in a different/closed dialog.
      if (!current()) return;
      if (typeof result.content !== "string" || !result.content)
        throw Error("Сервис не вернул конфигурацию.");
      exported = result;
      root.innerHTML = `
        <p class="note">QR-код и ссылка дают доступ к VPN. Сканируйте код в приложении, поддерживающем этот протокол.</p>
        <div class="export-tabs" role="group" aria-label="Формат конфигурации">
          <button id="show-qr" aria-controls="export-qr">QR-код</button>
          <button id="show-link" aria-controls="export-link">Ссылка</button>
        </div>
        <div id="export-qr" hidden>
          <img class="config-qr-image" alt="QR-код VPN-конфигурации" hidden>
          <p class="qr-error" role="status"></p>
          <button id="download-qr" disabled>Скачать QR (SVG)</button>
        </div>
        <div id="export-link" hidden><pre id="secret" tabindex="0" aria-label="Ссылка конфигурации"></pre></div>
        <div class="actions">
          <button id="copy-config">Копировать ссылку</button>
          <button id="download" class="primary">Скачать конфигурацию</button>
        </div>
        <p class="export-status" role="status" aria-live="polite"></p>`;
      const find = (selector) => root.querySelector(selector);
      find("#secret").textContent = exported.content;
      function selectQr(qr) {
        find("#export-qr").hidden = !qr;
        find("#export-link").hidden = qr;
        find("#show-qr").setAttribute("aria-pressed", String(qr));
        find("#show-link").setAttribute("aria-pressed", String(!qr));
      }
      find("#show-qr").onclick = () => selectQr(true);
      find("#show-link").onclick = () => selectQr(false);
      const validQr = typeof exported.qr_data_url === "string" &&
        /^data:image\/svg\+xml;base64,[A-Za-z0-9+/]+={0,2}$/.test(exported.qr_data_url);
      if (validQr) {
        const image = find(".config-qr-image");
        image.src = exported.qr_data_url;
        image.hidden = false;
        find("#download-qr").disabled = false;
        find("#download-qr").onclick = () => {
          if (exported) save(atob(exported.qr_data_url.split(",")[1]), "image/svg+xml", "svg");
        };
      } else {
        find(".qr-error").textContent = exported.qr_error ||
          "QR-код недоступен. Скопируйте ссылку или скачайте конфигурацию.";
      }
      find("#download").onclick = () => {
        if (exported) save(exported.content, "text/plain;charset=utf-8", "txt");
      };
      find("#copy-config").onclick = async () => {
        if (!exported) return;
        try {
          await navigator.clipboard.writeText(exported.content);
          if (current()) find(".export-status").textContent = "Ссылка скопирована.";
        } catch {
          if (!current()) return;
          selectQr(false);
          const selection = window.getSelection(), range = document.createRange();
          range.selectNodeContents(find("#secret"));
          selection.removeAllRanges();
          selection.addRange(range);
          find("#secret").focus();
          find(".export-status").textContent = "Автокопирование недоступно. Ссылка выделена: скопируйте её вручную.";
        }
      };
      selectQr(preferQr);
      find(preferQr ? "#show-qr" : "#show-link").focus();
    } catch (error) {
      if (!current()) return;
      root.querySelector(".export-status").textContent = error.message;
      button.disabled = false;
    }
  };
}
