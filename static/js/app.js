(()=>{'use strict';
const root = document.documentElement;
const media = matchMedia('(prefers-color-scheme: dark)');
function applyPreference(preference, persist = false) {
  if (!['light', 'dark', 'system'].includes(preference)) preference = 'system';
  root.dataset.themePreference = preference;
  root.dataset.theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
  document.querySelectorAll('[data-theme-select]').forEach(select => { select.value = preference; });
  if (persist) { try { localStorage.setItem('vs-theme', preference); } catch (_) {} }
  document.dispatchEvent(new Event('vs-theme-change'));
}
document.querySelectorAll('[data-theme-select]').forEach(select => select.addEventListener('change', () => applyPreference(select.value, true)));
media.addEventListener('change', () => { if (root.dataset.themePreference === 'system') applyPreference('system'); });
window.addEventListener('storage', event => { if (event.key === 'vs-theme') applyPreference(event.newValue || 'system'); });
applyPreference(root.dataset.themePreference || 'system');
const currentPath = location.pathname.replace(/\/$/, '') || '/';
document.querySelectorAll('.sidebar-nav a').forEach(link => {
  const path = new URL(link.href, location.href).pathname.replace(/\/$/, '') || '/';
  if (path === currentPath) link.setAttribute('aria-current', 'page');
});
const sidebar=document.getElementById('sidebar'),toggle=document.getElementById('sidebarToggle'),backdrop=document.getElementById('drawerBackdrop'),close=document.getElementById('sidebarClose'),small=matchMedia('(max-width:1023px)');let lastFocus;
function setDrawer(open){if(!sidebar||!toggle)return;if(open)lastFocus=document.activeElement;document.body.classList.toggle('nav-open',open);toggle.setAttribute('aria-expanded',String(open));if(backdrop)backdrop.hidden=!open;sidebar.inert=small.matches&&!open;if(open){close?.focus()}else if(lastFocus&&document.contains(lastFocus)){lastFocus.focus()}}
toggle?.addEventListener('click',()=>setDrawer(!document.body.classList.contains('nav-open')));close?.addEventListener('click',()=>setDrawer(false));backdrop?.addEventListener('click',()=>setDrawer(false));sidebar?.querySelectorAll('a').forEach(link=>link.addEventListener('click',()=>setDrawer(false)));
document.addEventListener('keydown',event=>{if(!document.body.classList.contains('nav-open'))return;if(event.key==='Escape'){event.preventDefault();setDrawer(false)}if(event.key==='Tab'&&sidebar){const nodes=[...sidebar.querySelectorAll('a,button,input,select')].filter(x=>!x.disabled);const first=nodes[0],last=nodes[nodes.length-1];if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus()}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus()}}});
small.addEventListener('change',()=>setDrawer(false));if(sidebar)sidebar.inert=small.matches;
document.querySelectorAll('table').forEach(table=>{if(!table.parentElement.matches('.table-wrap,.table-responsive')){const wrapper=document.createElement('div');wrapper.className='table-wrap';wrapper.tabIndex=0;wrapper.setAttribute('role','region');wrapper.setAttribute('aria-label','Scrollable table');table.before(wrapper);wrapper.append(table)}});
document.querySelectorAll('[data-toggle-password], [data-toggle-for]').forEach(button => {
  button.addEventListener('click', () => {
    const input = button.dataset.toggleFor ? document.getElementById(button.dataset.toggleFor) : document.querySelector(button.dataset.togglePassword);
    if (!input) return;
    const showing = input.type === 'password';
    input.type = showing ? 'text' : 'password';
    button.textContent = showing ? 'Hide' : 'Show';
    button.setAttribute('aria-label', showing ? 'Hide password' : 'Show password');
  });
});
document.querySelectorAll('[data-image-fallback]').forEach(image=>image.addEventListener('error',()=>{image.src=image.dataset.imageFallback;image.removeAttribute('data-image-fallback')},{once:true}));
})();
