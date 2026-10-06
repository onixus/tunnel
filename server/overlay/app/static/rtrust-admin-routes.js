'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const base = '/admin/api/agent-routes';
  let state = {groups: [], devices: [], users: []}, editing = null, busy = false;
  const message = text => { $('status').textContent = text; };
  async function api(path = '', method = 'GET', data, headers = {}) {
    const response = await fetch(base + path, {method, credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content, ...headers},
      body: data === undefined ? undefined : JSON.stringify(data)});
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Ошибка запроса');
    return result;
  }
  function node(tag, text) { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; return el; }
  function button(text, action) { const el = node('button', text); el.type = 'button'; el.addEventListener('click', action); return el; }
  async function act(action) {
    if (busy) return;
    busy = true;
    document.querySelectorAll('button, select').forEach(el => { el.disabled = true; });
    try { await action(); await load(); message('Сохранено. Клиент получит политику при следующем запросе.'); }
    catch (error) { message(error.message + '. Обновите состояние перед повтором.'); }
    finally { busy = false; document.querySelectorAll('button, select').forEach(el => { el.disabled = false; }); markUnavailable(); }
  }
  function reset() { editing = null; $('editor').reset(); $('editor-title').textContent = 'Новая группа'; }
  function markUnavailable() {
    document.querySelectorAll('[data-unavailable]').forEach(el => { el.disabled = true; });
    $('enroll').disabled = busy || !state.users.length;
  }
  function render() {
    $('groups').replaceChildren();
    for (const g of state.groups) {
      const row = node('div'); row.className = 'row'; row.append(node('strong', `${g.name} · ревизия ${g.revision}`));
      row.append(node('p', `VPN: ${g.include.join(', ')}. Исключения: ${g.exclude.join(', ') || 'нет'}. LAN: ${g.exclude_lan ? 'исключён' : 'включён'}`));
      row.append(button('Редактировать', () => { editing = {...g}; $('editor-title').textContent = 'Редактировать группу'; $('name').value = g.name; $('include').value = g.include.join('\n'); $('exclude').value = g.exclude.join('\n'); $('exclude-lan').checked = g.exclude_lan; }));
      row.append(button('Удалить', () => { if (confirm(`Удалить группу «${g.name}» и её назначения?`)) act(async () => { await api(`/groups/${g.id}`, 'DELETE', undefined, {'If-Match': String(g.revision)}); if (editing?.id === g.id) reset(); }); }));
      $('groups').append(row);
    }
    $('devices').replaceChildren();
    for (const d of state.devices) {
      const row = node('div'); row.className = 'row'; row.append(node('strong', `${d.name} · ${d.email} · ${d.platform}`));
      row.append(node('p', d.fetched_at ? `Последнее получение: ${new Date(d.fetched_at * 1000).toLocaleString()}; ревизия: ${d.fetched_revision || 'без политики'}` : 'Политика ещё не запрашивалась'));
      const select = node('select'); select.setAttribute('aria-label', `Группа для ${d.name}`);
      const none = node('option', 'Пользовательская политика'); none.value = ''; select.append(none);
      for (const g of state.groups) { const option = node('option', g.name); option.value = String(g.id); select.append(option); }
      select.value = d.group_id === null ? '' : String(d.group_id);
      const unavailable = d.revoked_at || d.status !== 'active' || !d.token_active || !['windows', 'macos', 'linux'].includes(d.platform);
      if (unavailable) { select.dataset.unavailable = 'true'; row.append(node('p', 'Назначение недоступно: нужен активный настольный клиент с действующей привязкой.')); }
      select.addEventListener('change', () => { const target = select.value === '' ? null : Number(select.value); if (!confirm(`Изменить политику устройства «${d.name}»?`)) { select.value = d.group_id === null ? '' : String(d.group_id); return; } act(() => api(`/devices/${d.id}`, 'PUT', {group_id: target, previous_group_id: d.group_id})); });
      row.append(select); $('devices').append(row);
    }
    const previous = $('user').value; $('user').replaceChildren();
    for (const u of state.users) { const option = node('option', u.email); option.value = String(u.id); $('user').append(option); }
    if (state.users.some(u => String(u.id) === previous)) $('user').value = previous;
    markUnavailable();
  }
  async function load() { state = await api(); render(); }
  const networks = id => $(id).value.split(/[\s,]+/).filter(Boolean);
  $('editor').addEventListener('submit', event => { event.preventDefault(); const data = {name: $('name').value, include: networks('include'), exclude: networks('exclude'), exclude_lan: $('exclude-lan').checked}; const group = editing; act(async () => { await api(group ? `/groups/${group.id}` : '/groups', group ? 'PUT' : 'POST', group ? {...data, revision: group.revision} : data); reset(); }); });
  $('cancel').addEventListener('click', reset);
  $('refresh').addEventListener('click', () => { if (!busy) load().then(() => message('Состояние обновлено')).catch(e => message(e.message)); });
  $('enroll').addEventListener('click', () => act(async () => { const result = await api('/enrollment-codes', 'POST', {user_id: Number($('user').value)}); $('code').textContent = `${result.code} · действует ${result.expires_in} секунд`; setTimeout(() => { $('code').textContent = ''; }, result.expires_in * 1000); }));
  load().catch(error => message(error.message));
})();
