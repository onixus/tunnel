/* Blocking head script: apply before styles/paint, even if storage is denied. */
(() => {
  'use strict';
  const root = document.documentElement;
  const media = matchMedia('(prefers-color-scheme: dark)');
  const valid = value => ['dark', 'light', 'system'].includes(value);
  let preference = 'system';
  try { const saved = localStorage.getItem('apex.theme'); if (valid(saved)) preference = saved; } catch (_) { /* Private/locked storage. */ }
  function apply() {
    const theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
    root.dataset.theme = theme;
    root.classList.toggle('dark', theme === 'dark');
    root.style.colorScheme = theme;
    document.querySelectorAll('[data-theme-switch]').forEach(select => { select.value = preference; });
  }
  apply();
  media.addEventListener('change', apply);
  addEventListener('storage', event => {
    if (event.key === 'apex.theme' || event.key === null) {
      preference = valid(event.newValue) ? event.newValue : 'system';
      apply();
    }
  });
  document.addEventListener('DOMContentLoaded', apply);
  document.addEventListener('change', event => {
    if (!event.target.matches('[data-theme-switch]')) return;
    preference = valid(event.target.value) ? event.target.value : 'system';
    try { localStorage.setItem('apex.theme', preference); } catch (_) { /* Still apply in memory. */ }
    apply();
  });
})();
