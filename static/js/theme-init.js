/* Run before CSS: only a UI preference is stored, never scanner or password data. */
(() => {
  let preference = 'system';
  try { const stored = localStorage.getItem('vs-theme'); if (['light', 'dark', 'system'].includes(stored)) preference = stored; } catch (_) {}
  const resolved = preference === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : preference;
  document.documentElement.dataset.themePreference = preference;
  document.documentElement.dataset.theme = resolved;
})();
