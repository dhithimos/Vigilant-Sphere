/* No npm dependencies. Tests the preference policy with a minimal DOM fixture. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const init = fs.readFileSync(path.join(root, 'static/js/theme-init.js'), 'utf8');
const app = fs.readFileSync(path.join(root, 'static/js/app.js'), 'utf8');

function fixture(stored, osDark, storageFails = false) {
  const listeners = {}, windowListeners = {}, selectListeners = {}, writes = [];
  const media = { matches: osDark, addEventListener: (event, fn) => { listeners[event] = fn; } };
  const narrow = { matches: false, addEventListener() {} };
  const html = { dataset: {} };
  const select = { value: '', addEventListener: (event, fn) => { selectListeners[event] = fn; } };
  const context = {
    document: {
      documentElement: html,
      querySelectorAll: selector => selector === '[data-theme-select]' ? [select] : [],
      getElementById: () => null,
      dispatchEvent() {}, addEventListener() {},
    },
    matchMedia: query => query.includes('prefers-color-scheme') ? media : narrow,
    localStorage: {
      getItem: () => { if (storageFails) throw Error('Storage blocked'); return stored; },
      setItem: (key, value) => { if (storageFails) throw Error('Storage blocked'); writes.push([key, value]); },
    },
    window: { addEventListener: (event, fn) => { windowListeners[event] = fn; } },
    location: { pathname: '/dashboard/', href: 'http://localhost/dashboard/' },
    URL, Event: class { constructor(type) { this.type = type; } },
  };
  vm.createContext(context);
  vm.runInContext(init, context);
  vm.runInContext(app, context);
  return { html, media, listeners, windowListeners, select, selectListeners, writes };
}

let f = fixture(null, true);
assert.equal(f.html.dataset.theme, 'dark');
assert.equal(f.select.value, 'system');
f.media.matches = false; f.listeners.change();
assert.equal(f.html.dataset.theme, 'light');

f = fixture('dark', false);
assert.equal(f.html.dataset.theme, 'dark');
f.listeners.change();
assert.equal(f.html.dataset.theme, 'dark');
f.select.value = 'light'; f.selectListeners.change();
assert.deepEqual(f.writes, [['vs-theme', 'light']]);
assert.equal(f.html.dataset.theme, 'light');
f.select.value = 'system'; f.selectListeners.change();
f.media.matches = true; f.listeners.change();
assert.equal(f.html.dataset.theme, 'dark');

f.windowListeners.storage({ key: 'vs-theme', newValue: 'light' });
assert.equal(f.html.dataset.theme, 'light');
assert.equal(f.select.value, 'light');
assert.equal(fixture('invalid', false).html.dataset.theme, 'light');
assert.equal(fixture(null, true, true).html.dataset.theme, 'dark');
console.log('PASS: OS fallback, OS changes, manual priority, persistence, System reset, cross-tab preference, invalid and blocked storage.');
