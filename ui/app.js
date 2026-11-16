import { S, plural } from './strings.js';

const T = window.__TAURI__;
const invoke = (cmd, args) => T.core.invoke(cmd, args);
const appWindow = T.window.getCurrentWindow();
const $ = (s) => document.querySelector(s);

// Registry and file system strings are untrusted: every dynamic string goes through esc().
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ic = (code) => `<span class="ic">${code}</span>`;
const nf = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });
const fmtSize = (b) => {
  if (b == null) return S.unknown;
  let i = 0, v = b;
  while (v >= 1024 && i < S.sizeUnits.length - 1) { v /= 1024; i++; }
  return `${nf.format(i === 0 ? v : Math.round(v * 10) / 10)} ${S.sizeUnits[i]}`;
};
const fmtDate = (ms) => new Date(ms).toLocaleString('ru-RU', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' });
// shortcut: a letter tile instead of the extracted program icon, extract via ExtractIconEx if users want it.
const letter = (name) => esc((name || '?').trim().charAt(0).toUpperCase());
const pill = ([kind, text]) => `<span class="pill ${kind}">${esc(text)}</span>`;

const state = {
  view: 'list', tab: 'programs',
  info: null, apps: null, appsError: null, query: '',
  details: null, detailsError: null,
  busy: false,
};

function set(patch) { Object.assign(state, patch); render(); }

// ---------- views ----------
const views = {};

views.list = () => {
  const tabs = `<div class="seg" role="tablist">
    <button class="${state.tab === 'programs' ? 'on' : ''}" data-act="tab" data-tab="programs">${S.tabPrograms}</button>
    <button class="${state.tab === 'history' ? 'on' : ''}" data-act="tab" data-tab="history">${S.tabHistory}</button></div>`;
  const head = `<div class="head"><div><h1 class="display">${S.homeTitle}</h1><p class="subtitle">${S.homeSub}</p></div>${tabs}</div>`;
  let body;
  if (state.appsError) {
    body = `<div class="strip danger"><span>${S.loadError}: ${esc(state.appsError)}</span><button class="btn secondary" data-act="reload">${S.retry}</button></div>`;
  } else if (!state.apps) {
    body = `<p class="count">${S.loadingRegistry}</p>${'<div class="skel"></div>'.repeat(6)}`;
  } else {
    body = `<div class="search">${ic('')}<input id="q" type="search" autocomplete="off" placeholder="${S.searchPlaceholder}" value="${esc(state.query)}"></div>
      <p class="count" id="count"></p><div id="list"></div>`;
  }
  return { html: `<div class="col">${head}${body}</div>`, bar: '' };
};

function filtered() {
  const q = state.query.trim().toLowerCase();
  return (state.apps || []).filter((a) => !q || a.displayName.toLowerCase().includes(q) || (a.publisher || '').toLowerCase().includes(q));
}

function renderList() {
  const list = $('#list');
  if (!list) return;
  const apps = filtered();
  $('#count').textContent = S.found(apps.length);
  list.innerHTML = apps.length ? apps.map((a) => `
    <button class="card row" data-act="open" data-id="${esc(a.id)}">
      <span class="tile letter sm">${letter(a.displayName)}</span>
      <span class="grow"><div class="name">${esc(a.displayName)}</div>
        <div class="muted">${esc([a.publisher, a.displayVersion].filter(Boolean).join(' · ') || '—')}</div></span>
      <span class="muted">${a.estimatedSizeKb != null ? fmtSize(a.estimatedSizeKb * 1024) : ''}</span>
      ${pill(a.perUser ? ['muted', S.onlyMe] : ['muted', S.forAll])}
      ${ic('')}
    </button>`).join('') : `<div class="card muted">${S.nothingFound}</div>`;
}

views.card = () => {
  const d = state.details;
  if (state.detailsError) return { html: `<div class="col"><button class="link back" data-act="home">${ic('')} ${S.allPrograms}</button><div class="strip danger">${esc(state.detailsError)}</div></div>`, bar: '' };
  if (!d) return { html: `<div class="col"><div class="skel"></div></div>`, bar: '' };
  const a = d.app;
  const folder = (p) => p ? `<button class="iconbtn" data-act="folder" data-path="${esc(p)}" title="${S.showInFolder}">${ic('')}</button>` : '';
  const row = (k, v, mono, path) => `<dt>${k}</dt><dd><span class="${mono ? 'mono' : ''}">${v}</span>${folder(path)}</dd>`;
  const sub = [a.publisher, a.displayVersion, a.installDate].filter(Boolean).map(esc).join(' · ');
  const warn = !a.perUser && !state.info.elevated && !state.info.sandbox
    ? `<div class="strip warn"><span>${S.perMachineWarn}</span><button class="btn secondary" data-act="admin">${S.restartAdmin}</button></div>` : '';
  const err = d.launchError ? `<div class="strip danger"><span><b>${S.launchErrorTitle}.</b> ${esc(d.launchError)}</span></div>` : '';
  const html = `<div class="col">
    <button class="link back" data-act="home">${ic('')} ${S.allPrograms}</button>
    <div class="head" style="justify-content:flex-start;align-items:center;gap:20px">
      <span class="tile letter lg">${letter(a.displayName)}</span>
      <div><h1 class="display" style="font-size:40px">${esc(a.displayName)}</h1><p class="subtitle" style="margin-top:6px">${sub || '—'}</p></div></div>
    ${warn}${err}
    <div class="card"><h3 style="margin-bottom:16px">${S.details}</h3><dl class="kv">
      ${row(S.kId, esc(a.id), true)}
      ${a.productCode ? row(S.kProduct, esc(a.productCode), true) : ''}
      ${row(S.kSources, a.sources.map((s) => esc(`${s.hive.toUpperCase()}\\${s.path} (${s.view})`)).join('<br>'), true)}
      ${row(S.kDir, a.installLocation ? esc(a.installLocation) : S.unknown, !!a.installLocation, a.installLocation)}
      ${row(S.kIcon, a.displayIcon ? esc(a.displayIcon) : S.unknown, !!a.displayIcon)}
      ${row(S.kUninstall, a.uninstallString ? esc(a.uninstallString) : S.unknown, !!a.uninstallString)}
      ${d.launch ? row(S.kWillRun, esc([d.launch.exe, d.launch.args].filter(Boolean).join(' ')), true) : ''}
      ${row(S.kQuiet, a.quietUninstallString ? `${esc(a.quietUninstallString)} <span class="faint">(${S.kQuietUnused})</span>` : S.kQuietUnused, !!a.quietUninstallString)}
      ${row(S.kDate, esc(a.installDate || S.unknown))}
      ${row(S.kSize, a.estimatedSizeKb != null ? fmtSize(a.estimatedSizeKb * 1024) : S.unknown)}
    </dl></div></div>`;
  return { html, bar: '' };
};

// ---------- rendering ----------
function render() {
  const v = views[state.view]();
  $('#main').innerHTML = v.html;
  const bar = $('#bar');
  bar.hidden = !v.bar;
  bar.innerHTML = v.bar;
  document.querySelectorAll('[data-indet]').forEach((el) => { el.indeterminate = true; });
  $('#modepill').innerHTML = state.info?.sandbox ? `<span class="pill warn">${S.sandboxPill}</span>`
    : state.info?.elevated ? `<span class="pill muted">${S.adminPill}</span>` : '';
  if (state.view === 'list') renderList();
}

// ---------- actions ----------
async function loadApps() {
  set({ apps: null, appsError: null });
  try { set({ apps: await invoke('list_apps') }); } catch (e) { set({ appsError: String(e) }); }
}

async function openCard(id) {
  set({ view: 'card', details: null, detailsError: null });
  try { set({ details: await invoke('describe_app', { id }) }); } catch (e) { set({ detailsError: String(e) }); }
}

const actions = {
  'win-min': () => appWindow.minimize(),
  'win-max': () => appWindow.toggleMaximize(),
  'win-close': () => appWindow.close(),
  reload: () => loadApps(),
  home: () => set({ view: 'list', tab: 'programs' }),
  tab: (el) => set({ tab: el.dataset.tab, view: 'list' }),
  open: (el) => openCard(el.dataset.id),
  folder: (el) => invoke('open_in_explorer', { path: el.dataset.path }).catch(() => {}),
  admin: () => invoke('restart_as_admin').catch((e) => alert(e)),
};

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el || el.disabled) return;
  const fn = actions[el.dataset.act];
  if (fn) fn(el, e);
});

document.addEventListener('input', (e) => {
  if (e.target.id === 'q') { state.query = e.target.value; renderList(); }
});

(async function init() {
  state.info = await invoke('app_info');
  render();
  loadApps();
})();
