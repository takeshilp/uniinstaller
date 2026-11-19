import { S } from './strings.js';

const T = window.__TAURI__;
const invoke = (cmd, args) => T.core.invoke(cmd, args);
const appWindow = T.window.getCurrentWindow();
const $ = (s) => document.querySelector(s);

// Registry and file system strings are untrusted (the WebView may run elevated): every dynamic string goes through esc().
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
const letter = (name) => esc((name || '?').trim().charAt(0).toUpperCase());
// Program icons as PNG data URLs by app id (null: none, the letter tile stays), fetched in page order, 4 at a time, after each render.
// History rows keep the letter: the program may be gone.
const icons = new Map();
const iconQueue = [];
const iconPending = new Set();
let iconsRunning = 0;
const appTile = (a, size) => {
  const url = icons.get(a.id);
  return url ? `<span class="tile ${size}"><img class="appicon" src="${esc(url)}" alt=""></span>`
    : `<span class="tile letter ${size}" data-icon="${esc(a.id)}">${letter(a.displayName)}</span>`;
};
function loadIcons() {
  document.querySelectorAll('[data-icon]').forEach((el) => {
    const id = el.dataset.icon;
    if (!icons.has(id) && !iconPending.has(id)) { iconPending.add(id); iconQueue.push(id); }
  });
  while (iconsRunning < 4 && iconQueue.length) {
    const id = iconQueue.shift();
    iconsRunning++;
    invoke('app_icon', { id }).catch(() => null).then((url) => {
      icons.set(id, url);
      iconPending.delete(id);
      iconsRunning--;
      if (url) {
        document.querySelectorAll('[data-icon]').forEach((el) => {
          if (el.dataset.icon !== id) return;
          el.classList.remove('letter');
          el.removeAttribute('data-icon');
          el.innerHTML = `<img class="appicon" src="${esc(url)}" alt="">`;
        });
      }
      loadIcons();
    });
  }
}
const pill = ([kind, text]) => `<span class="pill ${kind}">${esc(text)}</span>`;
const GROUPS = ['programFiles', 'shortcuts', 'registry', 'services', 'data', 'revert'];
const lastPart = (p) => String(p).split(/[\\/]/).filter(Boolean).pop() || String(p);
const regDisplay = (k) => `${k.hive.toUpperCase()}\\${k.path} (${k.view})`;

const state = {
  view: 'list', tab: 'programs',
  info: null, apps: null, appsError: null, query: '',
  details: null, detailsError: null,
  history: null, historyError: null,
  appId: null, plan: null, preview: false, op: null,
  selected: new Set(), expanded: new Set(),
  busy: false, loading: null, elapsed: 0, procs: [],
  outcome: null, modal: null, toast: null, popover: false, error: null,
  update: null, updating: false,
  trace: null,
  showHidden: false, hiddenOk: false,
  force: null,
  locks: null, closeList: null, closeInfo: null, continuations: [], contHidden: false,
};

function set(patch) { Object.assign(state, patch); render(); }
const fail = (e) => set({ error: String(e), busy: false, loading: null });

// ---------- helpers on plans and operations ----------
const isSystem = (t) => t.type === 'service' || t.type === 'task';
// A value of a captured service key (an ident's `node`) by name, and a DWORD value as a number.
const regVal = (node, name) => (node?.values || []).find((v) => v.name.toLowerCase() === name.toLowerCase());
const dword = (v) => (v && v.kind === 4 && v.data.length === 4 ? (v.data[0] | (v.data[1] << 8) | (v.data[2] << 16) | (v.data[3] << 24)) >>> 0 : null);
// What a service or task row shows: its name, what it runs and its state. `ident` is the scan's identity or the item's backup (absent when blocked
// before one was taken). Untrusted text: callers pass the result through esc().
// shortcut: an indirect display name (`@file,-id`) shows the key name instead; resolve it in Rust (SHLoadIndirectString) if users see raw names.
const sysLines = (t, ident) => {
  if (t.type === 'service') {
    const n = ident?.node;
    const disp = n ? fmtVal(regVal(n, 'DisplayName')) : '';
    const name = disp && disp !== S.valEmpty && !disp.startsWith('@') ? disp : t.name;
    const image = n ? fmtVal(regVal(n, 'ImagePath')) : '';
    const start = n ? (S.startType[dword(regVal(n, 'Start'))] ?? '?') : '';
    return { name, where: S.svcWhere(t.name, image === S.valEmpty ? '' : image), state: n ? S.svcState(start, dword(regVal(n, 'DelayedAutostart')) === 1, ident.running) : '' };
  }
  const acts = ident?.actions || [];
  return { name: lastPart(t.path), where: S.taskWhere(t.path, acts[0] || ''), state: ident?.actions ? S.taskState(ident.enabled, acts.length) : '' };
};
const candName = (c) => isSystem(c.target) ? sysLines(c.target, c.ident).name : c.target.type === 'path' ? lastPart(c.target.path) : c.target.type === 'regKey' ? lastPart(c.target.key.path) : c.target.name || S.regDefault;
const candWhere = (c) => isSystem(c.target) ? sysLines(c.target, c.ident).where : c.target.type === 'path' ? c.target.path : c.target.type === 'regKey' ? regDisplay(c.target.key) : `${regDisplay(c.target.key)} → ${c.target.name || S.regDefault}`;
// A registry value for people: text, list, number, else the first bytes in hex. Untrusted: callers pass the result through esc().
const fmtVal = (v) => {
  if (!v) return S.valEmpty;
  const d = v.data || [];
  const text = () => { let s = ''; for (let i = 0; i + 1 < d.length; i += 2) s += String.fromCharCode(d[i] | (d[i + 1] << 8)); return s; };
  let out;
  if (v.kind === 1 || v.kind === 2) out = text().replace(/\0+$/, '');
  else if (v.kind === 7) out = text().split('\0').filter(Boolean).join(' · ');
  else if (v.kind === 4 && d.length === 4) out = String((d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)) >>> 0);
  else out = d.slice(0, 24).map((b) => b.toString(16).padStart(2, '0')).join(' ') + (d.length > 24 ? ' …' : '');
  if (!out) return S.valEmpty;
  return out.length > 80 ? `${out.slice(0, 80)}…` : out;
};
// Evidence for a forced target is the user's word (folder and name), not a registry entry: its own wording where it differs.
const evText = (code) => (state.op?.forced && S.evidenceForced[code]) || S.evidence[code] || code;
const isRegistry = (c) => ['regKey', 'regValue', 'regRevert'].includes(c.target.type);
const isRevert = (c) => c.target.type === 'regRevert';
const groupable = (c) => c.blocks.length === 0 && (c.tier === 'safe' || c.tier === 'review');
const groupOf = (g) => (state.plan?.candidates || []).filter((c) => c.group === g);
const selectedCands = () => (state.plan?.candidates || []).filter((c) => state.selected.has(c.id) && c.blocks.length === 0);
const initialSelection = (plan) => new Set(plan.candidates.filter((c) => c.selected && c.blocks.length === 0).map((c) => c.id));
const restorable = (op) => op.items.filter((i) => (i.quarantine || i.regBackup) && i.restore !== 'restored');
const retryable = (op) => op.items.filter((i) => ['accessDenied', 'locked', 'failed', 'changed'].includes(i.status));
// Locked files: `state.locks` is {opId, loading} | {opId, items} | {opId, error}; the holders come from the core, never from here.
const lockedPath = (i) => i.target.type === 'path' && ['locked', 'accessDenied'].includes(i.status);
const lockOf = (id) => (state.locks?.opId === state.op?.id ? (state.locks.items || []).find((l) => l.candidateId === id) : null);
const lockFound = (i) => { const l = lockOf(i.candidateId); return !!l && (l.files > 0 || l.folders > 0); };
const uniqueHolders = (items) => { const seen = new Set(); return items.flatMap((l) => l.holders).filter((h) => !seen.has(h.pid) && seen.add(h.pid)); };
const holderName = (h) => h.name || h.image;
const lockLines = (i) => {
  if (i.target.type === 'service') return i.status === 'locked' ? [S.serviceLocked] : [];
  const l = lockOf(i.candidateId);
  if (!l) return [];
  const out = [];
  if (l.error) out.push(S.heldUnknown(l.error));
  l.holders.forEach((h) => out.push(S.heldBy(holderName(h), h.pid, S.holderKind[h.kind]) + (h.block ? ` — ${S.holderBlock[h.block]}` : '')));
  if (l.folders && !l.holders.length) out.push(S.heldFolder);
  if (!l.error && !l.holders.length && !l.folders && i.status === 'locked') out.push(S.heldNobody);
  if (l.reasons) out.push(S.rebootReasons(l.reasons));
  if (l.truncated) out.push(S.heldTruncated);
  return out;
};
const strip = (kind, text, btn = '') => `<div class="strip ${kind}"><span>${esc(text)}</span>${btn}</div>`;
const locksStrip = (op) => {
  const out = [];
  const L = state.locks?.opId === op.id ? state.locks : null;
  if (L?.loading) out.push(strip('info', S.locksLoading));
  else if (L?.error) out.push(strip('warn', S.locksError(L.error)));
  else if (L?.items && uniqueHolders(L.items).length) {
    const hs = uniqueHolders(L.items);
    const closable = L.items.every((l) => !l.reasons && l.holders.every((h) => !h.block));
    out.push(closable ? strip('warn', S.locksStrip(hs.map(holderName).join(', ')), `<button class="btn secondary" data-act="close-ask" ${dis()}>${S.closeRetry}</button>`) : strip('warn', S.locksBlocked));
  }
  const ci = state.closeInfo?.op.id === op.id ? state.closeInfo : null;
  if (ci) {
    if (ci.closed.length) out.push(strip('info', S.closedSummary(ci.closed.map(holderName).join(', '))));
    if (ci.stillRunning.length) out.push(strip('warn', S.notClosed(ci.stillRunning.map(holderName).join(', '))));
    if (ci.restartError) out.push(strip('warn', S.restartFailed));
  }
  if (op.continueAfterReboot) {
    out.push(strip('info', state.info.bootMs > op.continueAfterReboot ? S.afterRebootStrip : S.retryAfterRebootSet, `<button class="link" data-act="remind-off">${S.retryAfterRebootOff}</button>`));
  } else if (op.items.some((i) => ['locked', 'accessDenied'].includes(i.status)) && !['restored', 'partiallyRestored'].includes(op.status)) {
    out.push(strip('info', S.rebootHint, `<button class="btn secondary" data-act="remind-on" ${dis()}>${S.retryAfterReboot}</button>`));
  }
  return out.join('');
};
const itemGroup = (op, i) => {
  const c = op.plan?.candidates.find((x) => x.id === i.candidateId);
  if (c) return c.group;
  if (i.target.type === 'regRevert') return 'revert';
  if (isSystem(i.target)) return 'services';
  return i.target.type === 'path' ? (/\.lnk$/i.test(i.target.path) ? 'shortcuts' : 'programFiles') : 'registry';
};

// ---------- views ----------
const views = {};
const dis = () => (state.busy ? 'disabled' : '');

views.list = () => (state.tab === 'history' ? viewHistory() : viewPrograms());

function viewPrograms() {
  const tabs = tabsHtml();
  const traceBtn = `<button class="btn secondary" data-act="trace-open" ${dis()}>${ic('\uE896')} ${S.traceStart}</button>`;
  const forceBtn = `<button class="btn secondary" data-act="force-open" ${dis()}>${ic('\uE74D')} ${S.forceStart}</button>`;
  const hiddenToggle = `<label class="check"><input type="checkbox" data-act="show-hidden" ${state.showHidden ? 'checked' : ''} ${dis()}> ${S.showHidden}</label>`;
  const head = `<div class="head"><div><h1 class="display">${S.homeTitle}</h1><p class="subtitle">${S.homeSub}</p></div><div style="display:flex;gap:12px;align-items:center">${hiddenToggle}${forceBtn}${traceBtn}${tabs}</div></div>`;
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
}

function tabsHtml() {
  return `<div class="seg" role="tablist">
    <button class="${state.tab === 'programs' ? 'on' : ''}" data-act="tab" data-tab="programs">${S.tabPrograms}</button>
    <button class="${state.tab === 'history' ? 'on' : ''}" data-act="tab" data-tab="history">${S.tabHistory}</button></div>`;
}

function viewHistory() {
  const head = `<div class="head"><div><h1 class="display">${S.historyTitle}</h1><p class="subtitle">${S.historySub}</p></div>${tabsHtml()}</div>`;
  let body;
  if (state.historyError) body = `<div class="strip danger"><span>${esc(state.historyError)}</span></div>`;
  else if (!state.history) body = '<div class="skel"></div>'.repeat(3);
  else if (!state.history.length) body = `<div class="card muted">${S.historyEmpty}</div>`;
  else {
    body = state.history.map((h) => {
      if (h.type === 'broken') {
        return `<div class="card row"><span class="tile sm warn">${ic('')}</span>
          <span class="grow"><div class="name">${esc(h.id)}</div><div class="muted mono">${esc(h.path)}</div></span>
          ${pill(['danger', S.broken])}
          <button class="iconbtn" data-act="folder" data-path="${esc(h.path)}" title="${S.openFolder}">${ic('')}</button></div>`;
      }
      const op = h.op;
      return `<button class="card row" data-act="open-op" data-id="${esc(op.id)}">
        <span class="tile letter sm">${letter(op.app.displayName)}</span>
        <span class="grow"><div class="name">${esc(op.app.displayName)}</div>
          <div class="muted">${esc(fmtDate(op.createdMs))} · ${S.objects(op.items.length)}</div></span>
        ${op.forced ? pill(['warn', S.forcedPill]) : ''}${pill(S.opStatusPill[op.status] || ['muted', op.status])}${ic('')}</button>`;
    }).join('');
  }
  return { html: `<div class="col">${head}${body}</div>`, bar: '' };
}

function filtered() {
  const q = state.query.trim().toLowerCase();
  return (state.apps || []).filter((a) => !q || a.displayName.toLowerCase().includes(q) || (a.publisher || '').toLowerCase().includes(q));
}

function renderList() {
  const list = $('#list');
  if (!list) return;
  const apps = filtered();
  $('#count').textContent = S.found(apps.length) + (state.showHidden ? S.hiddenCount(apps.filter((a) => a.hidden).length) : '');
  list.innerHTML = apps.length ? apps.map((a) => `
    <button class="card row" data-act="open" data-id="${esc(a.id)}">
      ${appTile(a, 'sm')}
      <span class="grow"><div class="name">${esc(a.displayName)}</div>
        <div class="muted">${esc([a.publisher, a.displayVersion].filter(Boolean).join(' · ') || '—')}</div></span>
      <span class="muted">${a.estimatedSizeKb != null ? fmtSize(a.estimatedSizeKb * 1024) : ''}</span>
      ${a.hidden ? `<span class="pill warn" title="${esc(S.hiddenReason[a.hidden] || a.hidden)}">${S.hiddenPill}</span>` : ''}
      ${pill(['muted', a.perUser ? S.onlyMe : S.forAll])}${ic('')}
    </button>`).join('') : `<div class="card muted">${S.nothingFound}</div>`;
  loadIcons();
}

views.card = () => {
  const d = state.details;
  const back = `<button class="link back" data-act="home">${ic('')} ${S.allPrograms}</button>`;
  if (state.detailsError) return { html: `<div class="col">${back}<div class="strip danger">${esc(state.detailsError)}</div></div>`, bar: '' };
  if (!d) return { html: `<div class="col">${back}<div class="skel"></div></div>`, bar: '' };
  const a = d.app;
  const folder = (p) => p ? `<button class="iconbtn" data-act="folder" data-path="${esc(p)}" title="${S.showInFolder}">${ic('')}</button>` : '';
  const row = (k, v, mono, path) => `<dt>${k}</dt><dd><span class="${mono ? 'mono' : ''}">${v}</span>${folder(path)}</dd>`;
  const sub = [a.publisher, a.displayVersion, a.installDate].filter(Boolean).map(esc).join(' · ');
  const warn = !a.perUser && !state.info.elevated && !state.info.sandbox
    ? `<div class="strip warn"><span>${S.perMachineWarn}</span><button class="btn secondary" data-act="admin">${S.restartAdmin}</button></div>` : '';
  const err = d.launchError ? `<div class="strip danger"><span><b>${S.launchErrorTitle}.</b> ${esc(d.launchError)}</span></div>` : '';
  const tr = d.trace
    ? (d.trace.trusted ? `<div class="strip info"><span>${esc(S.traceOnCard(fmtDate(d.trace.createdMs)))}</span></div>`
      : `<div class="strip warn"><span>${esc(S.traceUntrusted(fmtDate(d.trace.createdMs), S.distrust[d.trace.distrust] || d.trace.distrust))}</span></div>`) : '';
  const hid = a.hidden ? `<div class="strip warn"><span>${esc(S.hiddenCard(S.hiddenReason[a.hidden] || a.hidden))}</span></div>` : '';
  const html = `<div class="col">${back}
    <div class="head" style="justify-content:flex-start;align-items:center;gap:20px;flex-wrap:nowrap">
      ${appTile(a, 'lg')}
      <div><h1 class="display" style="font-size:40px">${esc(a.displayName)}</h1><p class="subtitle" style="margin-top:6px">${sub || '—'}</p></div></div>
    ${hid}${warn}${err}${tr}
    <div class="card"><h3 style="margin-bottom:16px">${S.details}</h3><dl class="kv">
      ${row(S.kId, esc(a.id), true)}
      ${a.productCode ? row(S.kProduct, esc(a.productCode), true) : ''}
      ${row(S.kSources, a.sources.map((s) => esc(regDisplay(s))).join('<br>'), true)}
      ${row(S.kDir, a.installLocation ? esc(a.installLocation) : S.unknown, !!a.installLocation, a.installLocation)}
      ${row(S.kIcon, a.displayIcon ? esc(a.displayIcon) : S.unknown, !!a.displayIcon)}
      ${row(S.kUninstall, a.uninstallString ? esc(a.uninstallString) : S.unknown, !!a.uninstallString)}
      ${d.launch ? row(S.kWillRun, esc([d.launch.exe, d.launch.args].filter(Boolean).join(' ')), true) : ''}
      ${row(S.kQuiet, a.quietUninstallString ? `${esc(a.quietUninstallString)} <span class="faint">(${S.kQuietUnused})</span>` : S.kQuietUnused, !!a.quietUninstallString)}
      ${row(S.kDate, esc(a.installDate || S.unknown))}
      ${row(S.kSize, a.estimatedSizeKb != null ? fmtSize(a.estimatedSizeKb * 1024) : S.unknown)}
    </dl></div></div>`;
  const bar = `<div><div class="lbl">${S.sizeEstimate}</div><div class="tot">${a.estimatedSizeKb != null ? fmtSize(a.estimatedSizeKb * 1024) : '—'}</div></div>
    <div class="acts"><button class="btn secondary" data-act="preview" ${dis()}>${S.previewLeftovers}</button>
    <button class="btn primary" data-act="confirm" ${dis()} ${d.launchError ? 'disabled' : ''}>${S.runUninstaller}</button></div>`;
  return { html, bar };
};

views.loading = () => ({ html: `<div class="center"><div class="spinner"></div><h1 class="display" style="font-size:32px">${esc(state.loading)}</h1></div>`, bar: '' });

views.running = () => runningView(S.waitingTitle, S.waitingSub);

function runningView(title, subtitle) {
  const list = state.procs.map((p) => esc(p.image)).join('<br>') || '…';
  return {
    html: `<div class="center"><div class="spinner"></div>
      <h1 class="display" style="font-size:36px">${title}</h1>
      <p class="subtitle" style="max-width:560px">${subtitle}</p>
      <div class="mono muted" id="elapsed">${fmtElapsed(state.elapsed)}</div>
      <div class="card proc"><div class="muted" style="margin-bottom:6px">${S.waitingProcs}</div><div class="mono muted" id="procs">${list}</div></div>
      <button class="btn secondary" data-act="stop-wait">${S.stopWaiting}</button>
      <div class="faint" style="font-size:13px">${S.stopNote}</div></div>`,
    bar: '',
  };
}
const fmtElapsed = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;

// ---------- install tracing ----------
const TRACE_LIST_MAX = 20;
const listCard = (title, items, note) => {
  if (!items.length) return '';
  const shown = items.slice(0, TRACE_LIST_MAX).map((x) => `<div class="s mono">${esc(x)}</div>`).join('');
  const more = items.length > TRACE_LIST_MAX ? `<div class="s">${esc(S.andMore(items.length - TRACE_LIST_MAX))}</div>` : '';
  return `<div class="card"><h3 style="margin-bottom:8px">${esc(title)}</h3>${note ? `<div class="muted" style="margin-bottom:8px">${esc(note)}</div>` : ''}${shown}${more}</div>`;
};

views.trace = () => {
  const t = state.trace;
  if (t.phase === 'before' || t.phase === 'after') {
    return { html: `<div class="center"><div class="spinner"></div><h1 class="display" style="font-size:32px">${esc(t.phase === 'before' ? S.traceBefore : S.traceAfter)}</h1>
      <p class="subtitle">${S.traceSnapshotSub}</p></div>`, bar: '' };
  }
  if (t.phase === 'running') return runningView(S.traceWaitingTitle, S.traceWaitingSub);
  if (t.phase === 'launch') {
    const n = t.run || {};
    const failed = !!n.launchError;
    const title = failed ? S.traceNotStarted : n.exitCode ? S.traceExit(n.exitCode) : S.traceInstalled;
    const detail = failed ? `<div class="card mono muted pre" style="margin-top:12px">${esc(n.launchError)}</div>` : '';
    const warn = !failed && (n.stoppedByUser || n.timedOut) ? `<div class="strip warn"><span>${S.traceMayRun}</span></div>` : '';
    const bar = `<div></div><div class="acts"><button class="btn secondary" data-act="trace-cancel">${S.traceCancel}</button>
      ${failed ? '' : `<button class="btn primary" data-act="trace-done">${S.traceDone}</button>`}</div>`;
    return { html: `<div class="col"><div class="center" style="align-items:flex-start;text-align:left">${warn}
      <h1 class="display" style="font-size:40px">${esc(title)}</h1>${failed ? '' : `<p class="subtitle">${S.traceLaunchOnce}</p>`}${detail}</div></div>`, bar };
  }
  if (t.phase === 'done') {
    const sm = t.summary;
    const link = sm.link;
    const strip = link.type === 'linked' ? `<div class="strip info"><span>${esc(S.traceLinked(link.app.displayName))}</span></div>`
      : link.type === 'severalPrograms' ? `<div class="strip warn"><span>${esc(S.traceSeveral(link.names.join(', ')))}</span></div>`
      : `<div class="strip warn"><span>${S.traceNoProgram}</span></div>`;
    const row = (k, v) => `<dt>${k}</dt><dd><span>${esc(v)}</span></dd>`;
    const secs = ((sm.beforeMs + sm.afterMs) / 1000).toFixed(1);
    const counts = `<div class="card"><h3 style="margin-bottom:16px">${S.traceCounts}</h3><dl class="kv">
      ${row(S.tCreated, sm.created)}${row(S.tModifiedValues, sm.modifiedValues.length)}${row(S.tModifiedFiles, sm.modifiedFiles.length)}
      ${row(S.tDeleted, sm.deleted.length)}${row(S.tNoise, sm.noise)}${row(S.tUnreadable, sm.unreadable)}${row(S.tSnapshot, S.snapshotStat(sm.objects, secs))}</dl></div>`;
    const lists = listCard(S.tModifiedValues, sm.modifiedValues, S.restorableNote(sm.restorableValues))
      + listCard(S.tModifiedFiles, sm.modifiedFiles) + listCard(S.tDeleted, sm.deleted);
    const bar = `<div></div><div class="acts"><button class="btn secondary" data-act="home">${S.toPrograms}</button>
      ${link.type === 'linked' ? `<button class="btn primary" data-act="trace-open-app" data-id="${esc(link.app.id)}">${S.traceOpenApp}</button>` : ''}</div>`;
    return { html: `<div class="col"><div class="head"><div><h1 class="display" style="font-size:40px">${S.traceSaved}</h1></div></div>
      ${strip}${counts}${lists}<div class="strip warn"><span>${S.traceAttribution}</span></div></div>`, bar };
  }
  // pick
  const file = t.picked ? `<span class="mono">${esc(t.picked)}</span>` : `<span class="muted">${S.traceNoFile}</span>`;
  const bar = `<div></div><div class="acts"><button class="btn secondary" data-act="trace-cancel">${S.cancel}</button>
    <button class="btn primary" data-act="trace-begin" ${t.picked && !state.busy ? '' : 'disabled'}>${S.traceBegin}</button></div>`;
  return { html: `<div class="col"><div class="head"><div><h1 class="display">${S.traceTitle}</h1><p class="subtitle">${S.traceSub}</p></div></div>
    <div class="strip warn"><span>${S.traceNoise}</span></div>
    <div class="card"><h3 style="margin-bottom:8px">${S.traceScopeTitle}</h3>${S.traceScope.map((l) => `<div class="muted">${esc(l)}</div>`).join('')}
      <div class="faint" style="margin-top:8px">${S.traceNotScope}</div></div>
    <div class="card row"><span class="grow"><div class="muted" style="margin-bottom:4px">${S.traceFile}</div>${file}</span>
      <button class="btn secondary" data-act="trace-pick" ${state.busy ? 'disabled' : ''}>${S.tracePick}</button></div></div>`, bar };
};

// ---------- forced removal ("remove by path") ----------
views.force = () => {
  const f = state.force;
  const back = `<button class="link back" data-act="force-cancel">${ic('')} ${S.allPrograms}</button>`;
  if (f.phase === 'checking') {
    return { html: `<div class="center"><div class="spinner"></div><h1 class="display" style="font-size:32px">${S.forceChecking}</h1><p class="subtitle">${S.forceCheckingSub}</p></div>`, bar: '' };
  }
  if (f.phase === 'refused') {
    const c = f.check;
    return { html: `<div class="col">${back}<div class="strip danger"><span>${esc(S.forceRefused[c.code] || c.code)}</span></div>
      <div class="card mono muted pre">${esc(c.detail)}</div></div>`,
      bar: `<div></div><div class="acts"><button class="btn secondary" data-act="force-other">${S.forceOther}</button>
        <button class="btn primary" data-act="force-cancel">${S.toPrograms}</button></div>` };
  }
  if (f.phase === 'listed') {
    const c = f.check;
    const open = c.how !== 'inside' ? `<button class="btn primary" data-act="force-open-app" data-id="${esc(c.app.id)}">${S.forceOpenApp}</button>` : '';
    return { html: `<div class="col">${back}<div class="strip info"><span>${esc(S.forceListed[c.how](c.app.displayName))}</span></div></div>`,
      bar: `<div></div><div class="acts"><button class="btn secondary" data-act="force-other">${S.forceOther}</button>${open}</div>` };
  }
  if (f.phase === 'confirm') {
    const fd = f.check.found;
    const row = (k, v, mono) => `<dt>${k}</dt><dd><span class="${mono ? 'mono' : ''}">${v}</span></dd>`;
    const info = [fd.product, fd.publisher, fd.fileVersion].filter(Boolean).join(' · ');
    const where = fd.forced.folder
      ? `<dt>${S.kFolder}</dt><dd><span class="mono">${esc(fd.forced.folder)}</span><button class="iconbtn" data-act="folder" data-path="${esc(fd.forced.folder)}" title="${S.showInFolder}">${ic('')}</button></dd>`
      : row(S.kFileOnly, esc(fd.forced.picked), true);
    const strips = (fd.otherVolume ? `<div class="strip warn"><span>${S.forceOtherVolume}</span></div>` : '')
      + (fd.outsideZones ? `<div class="strip warn"><span>${S.forceOutsideZones}</span></div>` : '');
    const noUn = !fd.uninstallers.length;
    const radios = noUn ? `<div class="muted">${S.forceUnMissing}</div>`
      : fd.uninstallers.map((u, i) => `<label class="opt"><input type="radio" name="fun" data-act="force-un" data-i="${i}" ${f.un === i ? 'checked' : ''}>
          <span><div class="t">${esc(lastPart(u))}</div><div class="mono muted" style="word-break:break-all">${esc(u)}</div><div class="faint" style="font-size:13px">${S.forceUnFound}</div></span></label>`).join('')
        + `<label class="opt"><input type="radio" name="fun" data-act="force-un" data-i="-1" ${f.un === -1 ? 'checked' : ''}><span>${S.forceUnNone}</span></label>`;
    const label = f.un !== null && f.un >= 0 ? S.runUninstaller : (f.un === -1 || noUn) ? S.searchLeftovers : S.forceUnChoose;
    const links = fd.shortcuts.length ? listCard(S.forceLinksTitle, fd.shortcuts) : `<div class="card muted">${S.forceLinksNone}</div>`;
    const bar = `<div></div><div class="acts"><button class="btn secondary" data-act="force-cancel">${S.cancel}</button>
      <button class="btn primary" id="frun" data-act="force-go" ${forceReady() && !state.busy ? '' : 'disabled'}>${label}</button></div>`;
    return { html: `<div class="col">${back}<div class="head"><div><h1 class="display">${S.forceTitle}</h1></div></div>
      <div class="strip warn"><span>${S.forceNote}</span></div>${strips}
      <div class="card"><h3 style="margin-bottom:16px">${S.forcePicked}</h3><dl class="kv">${where}${info ? row(S.kProductInfo, esc(info)) : ''}</dl>
        ${fd.forced.folder ? '' : `<div class="muted" style="margin-top:10px">${S.kFileOnlyNote}</div>`}</div>
      <div class="card"><h3>${S.forceNameTitle}</h3>
        <label class="field"><span class="lbl">${S.forceName}</span><input type="text" id="fname" maxlength="200" autocomplete="off" value="${esc(f.name)}"></label>
        <label class="field"><span class="lbl">${S.forcePublisher}</span><input type="text" id="fpub" maxlength="200" autocomplete="off" value="${esc(f.publisher)}"></label>
        <div class="faint" style="margin-top:10px;font-size:13px">${S.forceNameHint}</div></div>
      <div class="card"><h3 style="margin-bottom:8px">${S.forceUnTitle}</h3>${radios}</div>${links}</div>`, bar };
  }
  // pick
  return { html: `<div class="col">${back}<div class="head"><div><h1 class="display">${S.forceTitle}</h1><p class="subtitle">${S.forceSub}</p></div></div>
    <div class="strip warn"><span>${S.forceNote}</span></div>
    <div class="card"><div style="display:flex;gap:12px;flex-wrap:wrap">
      <button class="btn secondary" data-act="force-pick-file" ${dis()}>${S.forcePickFile}</button>
      <button class="btn secondary" data-act="force-pick-folder" ${dis()}>${S.forcePickFolder}</button></div>
      <div class="muted" style="margin-top:14px">${S.forceListedHint}</div></div></div>`,
    bar: `<div></div><div class="acts"><button class="btn secondary" data-act="force-cancel">${S.cancel}</button></div>` };
};

// The run button needs a name and, when uninstallers were found, an explicit choice (none is preselected).
const forceReady = () => {
  const f = state.force;
  return !!f.name.trim() && (!f.check.found.uninstallers.length || f.un !== null);
};

async function forcePick(folder) {
  set({ busy: true });
  let picked;
  try { picked = await invoke('force_pick', { folder, title: folder ? S.forcePickTitleFolder : S.forcePickTitleFile, filter: S.forceFilter }); }
  catch (e) { set({ busy: false, error: String(e) }); return; }
  if (!picked) { set({ busy: false }); return; }
  set({ force: { phase: 'checking' } });
  let check;
  try { check = await invoke('force_check'); } catch (e) { set({ force: { phase: 'pick' }, busy: false, error: String(e) }); return; }
  const f = { phase: check.type === 'ok' ? 'confirm' : check.type, check, un: null, name: '', publisher: '' };
  if (check.type === 'ok') { f.name = check.found.name || ''; f.publisher = check.found.publisher || ''; }
  set({ force: f, busy: false });
}

async function forceRun() {
  const f = state.force, fd = f.check.found;
  const uninstaller = f.un !== null && f.un >= 0 ? fd.uninstallers[f.un] : null;
  if (uninstaller) {
    set({ view: 'running', busy: true, elapsed: 0, procs: [] });
    timer = setInterval(() => { state.elapsed++; const el = $('#elapsed'); if (el) el.textContent = fmtElapsed(state.elapsed); }, 1000);
  } else set({ view: 'loading', loading: S.forceStarting, busy: true });
  let op;
  try { op = await invoke('force_run', { name: f.name.trim(), publisher: f.publisher.trim() || null, uninstaller }); }
  catch (e) { clearInterval(timer); set({ view: 'force', busy: false, loading: null, error: String(e) }); return; }
  clearInterval(timer);
  state.busy = false;
  await afterNative(op);
}

views.outcome = () => {
  const o = state.outcome;
  return {
    html: `<div class="col"><div class="center" style="align-items:flex-start;text-align:left">
      <h1 class="display" style="font-size:40px">${esc(o.title)}</h1>
      ${o.sub ? `<p class="subtitle">${esc(o.sub)}</p>` : ''}
      ${o.detail ? `<div class="card mono muted pre" style="margin-top:12px">${esc(o.detail)}</div>` : ''}
      <div style="margin-top:16px;display:flex;gap:12px">
        ${o.canScan ? `<button class="btn secondary" data-act="scan-op" ${dis()}>${S.searchLeftovers}</button>` : ''}
        <button class="btn primary" data-act="home">${S.toPrograms}</button></div></div></div>`,
    bar: '',
  };
};

function reviewGroupCard(g) {
  const cands = groupOf(g);
  if (!cands.length) return '';
  const toggleable = cands.filter(groupable);
  const nSel = toggleable.filter((c) => state.selected.has(c.id)).length;
  const allSafe = cands.filter((c) => c.blocks.length === 0).every((c) => c.tier === 'safe') && cands.some((c) => c.blocks.length === 0);
  const open = state.expanded.has(g);
  const [title, desc] = S.groups[g];
  const size = cands.reduce((s, c) => s + c.size, 0);
  const checked = toggleable.length && nSel === toggleable.length;
  const indet = nSel > 0 && nSel < toggleable.length;
  const head = `<div class="group-head" data-act="expand" data-group="${g}">
    <input type="checkbox" data-act="toggle-group" data-group="${g}" ${checked ? 'checked' : ''} ${indet ? 'data-indet' : ''} ${!toggleable.length || state.preview ? 'disabled' : ''} aria-label="${esc(title)}">
    <span class="tile ${allSafe ? '' : 'warn'}">${ic(S.groupIcon[g])}</span>
    <span class="grow"><h3>${esc(title)}</h3><div class="desc">${esc(desc)}</div></span>
    <span class="sizeval">${fmtSize(size)}</span>
    <span class="badge ${allSafe ? 'safe' : 'call'}">${allSafe ? S.badgeSafe : S.badgeCall}</span>
    <span class="ic chev">${open ? '' : ''}</span></div>`;
  let kids = '';
  if (open) {
    const sorted = [...cands.filter((c) => c.tier !== 'weak'), ...cands.filter((c) => c.tier === 'weak')];
    kids = `<div class="children">${sorted.map(childRow).join('')}</div>`;
  }
  return `<div class="card">${head}${kids}</div>`;
}

function childRow(c) {
  const best = [...c.evidence].sort((a, b) => b.points - a.points)[0];
  const tip = c.evidence.map((e) => `${evText(e.code)} (${e.points > 0 ? '+' : ''}${e.points})`).join('\n');
  const why = c.tier === 'weak' ? S.weakMatch : `${best ? evText(best.code) : ''} · ${S.score(c.score)}`;
  const blocked = c.blocks.length
    ? `<div class="bl">${esc(S.blocked(c.blocks.map((b) => `${S.blockCode[b.code] || b.code}${b.detail ? ` (${b.detail})` : ''}`).join('; ')))}</div>` : '';
  const folder = c.target.type === 'path'
    ? `<button class="iconbtn" data-act="folder" data-path="${esc(c.target.path)}" title="${S.showInFolder}">${ic('')}</button>` : '';
  const was = c.target.type === 'regRevert' ? `<div class="s">${esc(S.wasNow(fmtVal(c.target.previous), fmtVal(c.ident?.val)))}</div>` : '';
  const sys = isSystem(c.target) ? `<div class="s">${esc(sysLines(c.target, c.ident).state)}</div>` : '';
  return `<div class="child ${c.tier === 'weak' ? 'weakrow' : ''}" title="${esc(tip)}">
    <input type="checkbox" data-act="toggle" data-id="${esc(c.id)}" ${state.selected.has(c.id) ? 'checked' : ''} ${c.blocks.length || state.preview ? 'disabled' : ''}>
    <span class="grow"><div class="t">${esc(candName(c))}</div><div class="s">${esc(candWhere(c))}</div>${was}${sys}
      <div class="s">${esc(why)}</div>${blocked}</span>
    <span class="sizeval muted" style="font-size:15px">${c.target.type === 'path' ? fmtSize(c.size) : ''}</span>${folder}</div>`;
}

views.review = () => {
  const plan = state.plan, op = state.op;
  const total = plan.candidates.filter((c) => c.blocks.length === 0).reduce((s, c) => s + c.size, 0);
  const eyebrow = state.preview ? S.previewEyebrow : op.forced ? S.forceEyebrow(op.app.displayName, op.native?.exitCode) : S.removedEyebrow(op.app.displayName, op.native?.exitCode);
  const strips = [];
  if (plan.stillRunning?.length) strips.push(`<div class="strip warn"><span>${esc(S.stillRunning(plan.stillRunning.join(', ')))}</span></div>`);
  if (plan.installDirStatus.type === 'rejected') strips.push(`<div class="strip warn"><span>${esc(S.dirRejected(plan.installDirStatus.reason))}</span></div>`);
  if (plan.installDirStatus.type === 'notSet') strips.push(`<div class="strip warn"><span>${esc(op?.forced ? S.forceFileOnly(op.forced.picked) : S.dirNotSet)}</span></div>`);
  if (op?.forced) {
    strips.push(`<div class="strip info"><span>${S.forceReviewNote}</span></div>`);
    if (!op.forced.searchNames.length) strips.push(`<div class="strip warn"><span>${esc(S.forceNoNameSearch(op.app.displayName))}</span></div>`);
  }
  if (!state.info.elevated && !state.info.sandbox && groupOf('services').length) {
    strips.push(`<div class="strip warn"><span>${S.servicesNeedAdmin}</span><button class="btn secondary" data-act="admin">${S.restartAdmin}</button></div>`);
  }
  const tu = plan.trace;
  if (tu) {
    const when = fmtDate(tu.createdMs);
    if (tu.trusted) {
      strips.push(`<div class="strip info"><span>${esc(S.traceUsed(when))}${tu.reported ? ` ${esc(S.traceReported(tu.reported))}` : ''}</span></div>`);
    } else {
      strips.push(`<div class="strip warn"><span>${esc(S.traceNotUsed(when, S.distrust[tu.distrust] || tu.distrust))}</span></div>`);
    }
  }
  const head = `<div class="head"><div><p class="eyebrow">${esc(eyebrow)}</p>
    <div class="big">${fmtSize(total)}<small>${S.leftovers}</small></div>
    <p class="subtitle">${S.reviewSub}</p></div>
    <button class="link" data-act="export-json">${S.exportJson}</button></div>`;
  const groups = GROUPS.map(reviewGroupCard).join('');
  const body = plan.candidates.length ? groups : `<div class="card"><h3>${S.noLeftovers}</h3>
    <div style="margin-top:14px"><button class="btn primary" data-act="home">${S.done}</button></div></div>`;
  const sel = selectedCands();
  const regN = sel.filter(isRegistry).length;
  const sysN = sel.filter((c) => isSystem(c.target)).length;
  const selSize = sel.reduce((s, c) => s + c.size, 0);
  const bar = state.preview
    ? `<div></div><div class="acts"><button class="btn secondary" data-act="back-card">${S.back}</button>
       <button class="btn primary" data-act="export-json">${S.exportJson}</button></div>`
    : `<div><div class="lbl">${S.selected}</div><div class="tot">${fmtSize(selSize)}${regN ? `<small>· ${S.registryRecords(regN)}</small>` : ''}${sysN ? `<small>· ${S.systemObjects(sysN)}</small>` : ''}</div></div>
       <div class="acts"><button class="btn secondary" data-act="scan-op" ${dis()}>${S.scanAgain}</button>
       <button class="btn primary" data-act="apply" ${dis()} ${sel.length ? '' : 'disabled'}>${ic('')} ${S.deleteSelected}</button></div>`;
  return { html: `<div><button class="link back" data-act="home">${ic('')} ${S.allPrograms}</button>${strips.join('')}${head}${body}</div>`, bar: plan.candidates.length || state.preview ? bar : '' };
};

views.result = () => {
  const op = state.op;
  const failed = op.items.filter((i) => ['removed', 'notFound', 'reverted'].includes(i.status)).length;
  const verify = op.verify;
  const vLines = verify
    ? [verify.appStillListed ? S.verifyListed : S.verifyGone, verify.reappeared.length ? S.verifyReappeared(verify.reappeared.length) : S.verifyClean].slice(op.forced ? 1 : 0) : [];
  const forcedStrip = op.forced ? `<div class="strip info"><span>${esc(op.native ? S.forceResultRan(op.launch.exe) : S.forceResultSkipped)}</span></div>` : '';
  const verCard = vLines.length ? `<div class="card"><h3 style="margin-bottom:8px">${S.verification}</h3>${vLines.map((l) => `<div class="muted">${esc(l)}</div>`).join('')}</div>` : '';
  const denied = op.items.some((i) => i.status === 'accessDenied' && !lockFound(i)) && !state.info.elevated
    ? `<div class="strip warn"><span>${S.deniedStrip}</span>${state.info.sandbox ? '' : `<button class="btn secondary" data-act="admin">${S.restartAdmin}</button>`}</div>` : '';
  const sysRestored = op.items.some((i) => isSystem(i.target) && i.restore === 'restored') ? `<div class="strip info"><span>${S.systemRestoredNote}</span></div>` : '';
  const rowsFor = (g) => op.items.filter((i) => itemGroup(op, i) === g).map((i) => {
    const p = i.restore ? S.restoreStatus[i.restore] : S.itemStatus[i.status];
    const name = candName({ target: i.target, ident: i.regBackup });
    const where = candWhere({ target: i.target, ident: i.regBackup });
    const note = i.restoreDetail || i.detail;
    return `<div class="child"><span class="grow"><div class="t">${esc(name)}</div><div class="s">${esc(where)}</div>${note ? `<div class="s">${esc(note)}</div>` : ''}${lockLines(i).map((t) => `<div class="s">${esc(t)}</div>`).join('')}</span>${pill(p || ['muted', i.status])}</div>`;
  }).join('');
  const groups = GROUPS.map((g) => {
    const r = rowsFor(g);
    return r ? `<div class="card"><h3 style="margin-bottom:6px">${esc(S.groups[g][0])}</h3>${r}</div>` : '';
  }).join('');
  const nRest = restorable(op).length, nRetry = retryable(op).length;
  const scanLabel = ['awaitingReview', 'running'].includes(op.status) || (op.status === 'pendingReboot' && !op.items.length) || op.items.some((i) => i.status === 'changed');
  const bar = `<div><div class="lbl">${S.canRestore(nRest)}</div></div>
    <div class="acts">${nRest ? `<button class="btn secondary" data-act="restore" ${dis()}>${S.restoreAll}</button>` : ''}
    ${nRetry ? `<button class="btn secondary" data-act="retry" ${dis()}>${S.retryFailed}</button>` : ''}
    ${scanLabel ? `<button class="btn primary" data-act="scan-op" ${dis()}>${S.searchLeftovers}</button>` : `<button class="btn primary" data-act="home">${S.toPrograms}</button>`}</div>`;
  const html = `<div class="col"><div class="head"><div><p class="eyebrow">${esc(S.resultEyebrow(op.app.displayName, fmtDate(op.createdMs)))}${op.forced ? ` ${pill(['warn', S.forcedPill])}` : ''}</p>
    <h1 class="display" style="font-size:44px">${esc(S.opStatus[op.status] || op.status)}</h1>
    <p class="subtitle">${esc(S.resultCounts(failed, op.items.length))}${op.statusDetail ? ` · ${esc(op.statusDetail)}` : ''}</p></div>
    <button class="link" data-act="export-report">${S.exportReport}</button></div>
    ${locksStrip(op)}${denied}${sysRestored}${forcedStrip}${verCard}${groups}</div>`;
  return { html, bar };
};

// ---------- popover, modal, toast, banner ----------
function renderPopover() {
  const p = $('#popover');
  p.hidden = !state.popover;
  if (!state.popover) return;
  const i = state.info;
  p.innerHTML = `<div class="card"><h3 style="margin-bottom:12px">${S.settings}</h3><dl class="kv" style="grid-template-columns:110px 1fr">
    <dt>${S.version}</dt><dd><span>${esc(i.version)}</span></dd>
    <dt>${S.rights}</dt><dd><span>${i.elevated ? S.rightsAdmin : S.rightsUser}</span></dd>
    ${i.sandbox ? `<dt>${S.sandboxPath}</dt><dd><span class="mono">${esc(i.dataDir)}</span></dd>` : ''}
    <dt>${S.dataFolder}</dt><dd><span class="mono">${esc(i.dataDir)}</span><button class="iconbtn" data-act="folder" data-path="${esc(i.dataDir)}">${ic('')}</button></dd></dl>
    <div style="margin-top:14px"><button class="btn secondary" data-act="check-update" ${dis()}>${S.checkUpdates}</button></div>
    <div class="muted" id="upmsg" style="margin-top:8px"></div></div>`;
}

function renderModal() {
  const m = $('#modal');
  if (!state.modal) { m.innerHTML = ''; return; }
  if (state.modal === 'system') {
    const n = selectedCands().filter((c) => isSystem(c.target)).length;
    m.innerHTML = `<div class="overlay" data-act="modal-cancel-overlay"><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="mt">
      <h2 id="mt">${esc(S.confirmSystemTitle(n))}</h2>
      <div class="muted">${S.confirmSystemNote}</div>
      <div class="acts"><button class="btn secondary" id="mcancel" data-act="modal-cancel">${S.cancel}</button>
      <button class="btn primary" data-act="modal-system-go">${S.proceed}</button></div></div></div>`;
    $('#mcancel').focus();
    return;
  }
  if (state.modal === 'revert') {
    const n = selectedCands().filter(isRevert).length;
    m.innerHTML = `<div class="overlay" data-act="modal-cancel-overlay"><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="mt">
      <h2 id="mt">${esc(S.confirmRevertTitle(n))}</h2>
      <div class="muted">${S.confirmRevertNote}</div>
      <div class="acts"><button class="btn secondary" id="mcancel" data-act="modal-cancel">${S.cancel}</button>
      <button class="btn primary" data-act="modal-revert-go">${S.proceed}</button></div></div></div>`;
    $('#mcancel').focus();
    return;
  }
  if (state.modal === 'close') {
    const hs = state.closeList || [];
    m.innerHTML = `<div class="overlay" data-act="modal-cancel-overlay"><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="mt">
      <h2 id="mt">${esc(S.confirmCloseTitle(hs.length))}</h2>
      <div class="cmd">${hs.map((h) => esc(`${holderName(h)} — ${h.image}, PID ${h.pid}`)).join('<br>')}</div>
      <div class="muted">${S.confirmCloseNote}</div>
      <div class="acts"><button class="btn secondary" id="mcancel" data-act="modal-cancel">${S.cancel}</button>
      <button class="btn primary" data-act="modal-close-go">${S.closeGo}</button></div></div></div>`;
    $('#mcancel').focus();
    return;
  }
  const d = state.details;
  const cmd = d.launch ? [d.launch.exe, d.launch.args].filter(Boolean).join(' ') : '';
  m.innerHTML = `<div class="overlay" data-act="modal-cancel-overlay"><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="mt">
    <h2 id="mt">${esc(S.confirmTitle(d.app.displayName))}</h2>
    <div class="muted">${S.willRun}</div><div class="cmd">${esc(cmd)}</div>
    <div class="muted">${S.confirmNote}</div>
    ${d.app.hidden ? `<label class="check"><input type="checkbox" data-act="hidden-ok" ${state.hiddenOk ? 'checked' : ''}> ${S.hiddenConfirm}</label>` : ''}
    <div class="acts"><button class="btn secondary" id="mcancel" data-act="modal-cancel">${S.cancel}</button>
    <button class="btn primary" id="mrun" data-act="modal-run" ${d.app.hidden && !state.hiddenOk ? 'disabled' : ''}>${S.run}</button></div></div></div>`;
  $('#mcancel').focus();
}

let toastTimer;
function renderToast() {
  const t = $('#toast');
  t.innerHTML = state.toast ? `<div class="t"><span class="mono">${esc(state.toast.text)}</span>${state.toast.path ? `<button class="link" data-act="folder" data-path="${esc(state.toast.path)}">${S.openFolder}</button>` : ''}</div>` : '';
  clearTimeout(toastTimer);
  if (state.toast) toastTimer = setTimeout(() => set({ toast: null }), 9000);
}

function renderBanner() {
  const b = $('#banner');
  if (state.error) {
    b.innerHTML = `<div class="strip danger"><span>${S.error}: ${esc(state.error)}</span><button class="btn secondary" data-act="dismiss-error">OK</button></div>`;
  } else if (state.updating) {
    b.innerHTML = `<div class="strip info"><span>${S.updating}</span></div>`;
  } else if (state.update) {
    const off = state.busy || state.op?.status === 'running' ? 'disabled' : '';
    b.innerHTML = `<div class="strip info"><span>${esc(S.updateAvailable(state.update))}</span><span><button class="btn secondary" data-act="update-install" ${off}>${S.updateNow}</button>
      <button class="link" data-act="update-later" style="margin-left:10px">${S.later}</button></span></div>`;
  } else if (state.continuations.length && !state.contHidden) {
    const c = state.continuations;
    b.innerHTML = `<div class="strip info"><span>${esc(S.rebootBanner(c[0].app.displayName, c.length - 1))}</span><span><button class="btn secondary" data-act="continue-op" ${dis()}>${S.continueOp}</button>
      <button class="link" data-act="continue-later" style="margin-left:10px">${S.later}</button><button class="link" data-act="continue-off" style="margin-left:10px">${S.retryAfterRebootOff}</button></span></div>`;
  } else b.innerHTML = '';
}

// ---------- rendering ----------
function render() {
  const v = views[state.view]();
  const main = $('#main');
  const top = main.scrollTop;
  main.innerHTML = v.html;
  main.scrollTop = top;
  const bar = $('#bar');
  bar.hidden = !v.bar;
  bar.innerHTML = v.bar;
  document.querySelectorAll('[data-indet]').forEach((el) => { el.indeterminate = true; });
  $('#modepill').innerHTML = state.info?.sandbox ? `<span class="pill warn">${S.sandboxPill}</span>`
    : state.info?.elevated ? `<span class="pill muted">${S.adminPill}</span>` : '';
  if (state.view === 'list') renderList();
  renderPopover(); renderModal(); renderToast(); renderBanner();
  loadIcons();
}

// ---------- actions ----------
async function loadApps() {
  const hidden = state.showHidden;
  set({ apps: null, appsError: null });
  try {
    const apps = await invoke('list_apps', { includeHidden: hidden });
    if (hidden === state.showHidden) set({ apps }); // a later toggle wins over a slow answer
  } catch (e) { if (hidden === state.showHidden) set({ appsError: String(e) }); }
}

async function loadHistory() {
  set({ history: null, historyError: null });
  try { set({ history: await invoke('history') }); } catch (e) { set({ historyError: String(e) }); }
}

async function openCard(id) {
  set({ view: 'card', appId: id, details: null, detailsError: null });
  try { set({ details: await invoke('describe_app', { id }) }); } catch (e) { set({ detailsError: String(e) }); }
}

async function doPreview() {
  set({ view: 'loading', loading: S.previewLeftovers + '…', busy: true });
  try {
    const plan = await invoke('preview_plan', { id: state.appId });
    set({ view: 'review', plan, preview: true, op: null, busy: false, loading: null, selected: initialSelection(plan), expanded: new Set() });
  } catch (e) { set({ view: 'card', busy: false, loading: null, error: String(e) }); }
}

let timer;
async function startUninstall() {
  set({ modal: null, view: 'running', busy: true, elapsed: 0, procs: [] });
  timer = setInterval(() => { state.elapsed++; const el = $('#elapsed'); if (el) el.textContent = fmtElapsed(state.elapsed); }, 1000);
  let op;
  try { op = await invoke('uninstall', { id: state.appId, hiddenOk: state.hiddenOk }); } catch (e) { clearInterval(timer); set({ view: 'card', busy: false, error: String(e) }); return; }
  clearInterval(timer);
  state.busy = false;
  await afterNative(op);
}

async function afterNative(op) {
  state.op = op;
  const n = op.native || {};
  // A forced removal's uninstaller was found by path: go on to the leftovers by itself only after a clean exit (spec 3.2).
  const forcedDoubt = !!op.forced && !!op.native && (n.exitCode !== 0 || n.timedOut || n.stoppedByUser);
  if (op.status === 'awaitingReview' && !forcedDoubt) return scanOp(op.id);
  const o = { canScan: false, detail: [n.exitCode != null ? S.exitCode(n.exitCode) : '', n.launchError || '', op.statusDetail || ''].filter(Boolean).join('\n') };
  if (n.launchError) o.title = S.outNotStarted;
  else if (op.status === 'pendingReboot') { o.title = S.outReboot; o.sub = S.outRebootSub; }
  else if (forcedDoubt) { o.title = n.timedOut ? S.outTimeout : n.stoppedByUser ? S.outRunning : S.forceUnFailed(n.exitCode); o.sub = S.forceUnFailedSub; o.canScan = true; }
  else if (op.status === 'running') { o.title = n.timedOut ? S.outTimeout : S.outRunning; o.canScan = true; }
  else if (op.status === 'failed') o.title = S.outStillInstalled;
  else o.title = S.opStatus[op.status] || op.status;
  set({ view: 'outcome', outcome: o, op, busy: false });
}

async function scanOp(opId) {
  set({ view: 'loading', loading: S.loadingRegistry, busy: true });
  try {
    const op = await invoke('scan_leftovers', { opId });
    set({ view: 'review', op, plan: op.plan, preview: false, busy: false, loading: null, selected: initialSelection(op.plan), expanded: new Set() });
  } catch (e) {
    set({ view: state.op ? 'result' : 'list', busy: false, loading: null, error: String(e) });
  }
}

async function runOp(cmd, args) {
  set({ busy: true });
  try {
    const op = await invoke(cmd, args);
    set({ op, view: 'result', busy: false, closeInfo: null });
    loadLocks(op);
  } catch (e) { fail(e); }
}

// Who holds the files of the locked items. An answer (or an error) that is not the latest request, or is for another operation, is dropped.
let locksSeq = 0;
function loadLocks(op) {
  const seq = ++locksSeq;
  if (!op || ['restored', 'partiallyRestored'].includes(op.status) || !op.items.some(lockedPath)) { set({ locks: null }); return; }
  set({ locks: { opId: op.id, loading: true } });
  const keep = () => seq === locksSeq && state.op?.id === op.id;
  invoke('lock_holders', { opId: op.id }).then(
    (items) => { if (keep()) set({ locks: { opId: op.id, items } }); },
    (e) => { if (keep()) set({ locks: { opId: op.id, error: String(e) } }); },
  );
}

// The modal froze the list it showed; the core closes exactly those PIDs, or refuses.
async function closeRetry() {
  const pids = (state.closeList || []).map((h) => h.pid);
  set({ modal: null, view: 'loading', loading: S.closing, busy: true });
  try {
    const r = await invoke('close_and_retry', { opId: state.op.id, pids });
    set({ op: r.op, plan: r.op.plan, view: 'result', busy: false, loading: null, closeInfo: r });
    loadLocks(r.op);
  } catch (e) {
    set({ view: 'result', busy: false, loading: null, error: String(e) });
    loadLocks(state.op);
  }
}

async function remind(on) {
  try { set({ op: await invoke('remind_after_reboot', { opId: state.op.id, on }) }); } catch (e) { fail(e); }
}

function applySelected() { return runOp('apply', { opId: state.op.id, ids: selectedCands().map((c) => c.id) }); }

async function traceOpen() {
  invoke('trace_cancel').catch(() => {});
  set({ view: 'trace', trace: { phase: 'pick', picked: null }, popover: false });
}

async function tracePick() {
  set({ busy: true });
  try {
    const picked = await invoke('pick_installer', { title: S.tracePickTitle, filter: S.traceFilter });
    set({ busy: false, trace: { ...state.trace, picked } });
  } catch (e) { traceFail(e); }
}

function traceFail(e) {
  clearInterval(timer);
  invoke('trace_cancel').catch(() => {});
  set({ view: 'trace', trace: { phase: 'pick', picked: null }, busy: false, error: String(e) });
}

async function traceBegin() {
  set({ busy: true, trace: { ...state.trace, phase: 'before' } });
  try { await invoke('trace_begin'); } catch (e) { return traceFail(e); }
  set({ elapsed: 0, procs: [], trace: { ...state.trace, phase: 'running' } });
  timer = setInterval(() => { state.elapsed++; const el = $('#elapsed'); if (el) el.textContent = fmtElapsed(state.elapsed); }, 1000);
  let run;
  try { run = await invoke('trace_install'); } catch (e) { return traceFail(e); }
  clearInterval(timer);
  set({ busy: false, trace: { ...state.trace, phase: 'launch', run } });
}

async function traceDone() {
  set({ busy: true, trace: { ...state.trace, phase: 'after' } });
  let summary;
  try { summary = await invoke('trace_finish'); } catch (e) { return traceFail(e); }
  set({ busy: false, trace: { ...state.trace, phase: 'done', summary } });
  loadApps();
}

async function exportJson() {
  try {
    const path = state.preview ? await invoke('export_plan', { id: state.appId }) : await invoke('export_report', { opId: state.op.id });
    set({ toast: { text: path, path } });
  } catch (e) { fail(e); }
}

function toggleGroup(g) {
  const cands = groupOf(g).filter(groupable);
  const all = cands.every((c) => state.selected.has(c.id));
  cands.forEach((c) => (all ? state.selected.delete(c.id) : state.selected.add(c.id)));
  render();
}

const actions = {
  'win-min': () => appWindow.minimize(),
  'win-max': () => appWindow.toggleMaximize(),
  'win-close': () => appWindow.close(),
  settings: () => set({ popover: !state.popover }),
  reload: () => loadApps(),
  home: () => set({ view: 'list', tab: 'programs', popover: false }),
  tab: (el) => { set({ tab: el.dataset.tab, view: 'list' }); if (el.dataset.tab === 'history') loadHistory(); },
  open: (el) => openCard(el.dataset.id),
  'open-op': (el) => {
    const h = state.history.find((x) => x.type === 'ok' && x.op.id === el.dataset.id);
    if (h) { set({ op: h.op, plan: h.op.plan, view: 'result', closeInfo: null }); loadLocks(h.op); }
  },
  folder: (el) => invoke('open_in_explorer', { path: el.dataset.path }).catch(() => {}),
  admin: () => invoke('restart_as_admin').catch(fail),
  preview: () => doPreview(),
  'trace-open': () => traceOpen(),
  'trace-pick': () => tracePick(),
  'trace-begin': () => traceBegin(),
  'trace-done': () => traceDone(),
  'trace-cancel': () => { invoke('trace_cancel').catch(() => {}); set({ view: 'list', tab: 'programs', trace: null }); },
  'trace-open-app': (el) => openCard(el.dataset.id),
  'force-open': () => set({ view: 'force', force: { phase: 'pick' }, popover: false }),
  'force-pick-file': () => forcePick(false),
  'force-pick-folder': () => forcePick(true),
  'force-un': (el) => { state.force.un = Number(el.dataset.i); render(); },
  'force-go': () => forceRun(),
  'force-other': () => set({ force: { phase: 'pick' } }),
  'force-open-app': (el) => openCard(el.dataset.id),
  'force-cancel': () => set({ view: 'list', tab: 'programs', force: null }),
  'back-card': () => set({ view: 'card', preview: false }),
  confirm: () => set({ modal: 'uninstall', hiddenOk: false }),
  'show-hidden': (el) => { state.showHidden = el.checked; loadApps(); },
  'hidden-ok': (el) => { state.hiddenOk = el.checked; $('#mrun').disabled = !el.checked; },
  'modal-cancel': () => set({ modal: null }),
  'modal-cancel-overlay': (el, e) => { if (e.target === el) set({ modal: null }); },
  'modal-run': () => startUninstall(),
  'stop-wait': () => invoke('stop_waiting'),
  expand: (el, e) => {
    if (e.target.closest('input')) return;
    const g = el.dataset.group;
    if (state.expanded.has(g)) state.expanded.delete(g); else state.expanded.add(g);
    render();
  },
  toggle: (el) => { if (el.checked) state.selected.add(el.dataset.id); else state.selected.delete(el.dataset.id); render(); },
  'toggle-group': (el) => toggleGroup(el.dataset.group),
  'export-json': () => exportJson(),
  'export-report': () => exportJson(),
  'scan-op': () => scanOp(state.op.id),
  apply: () => (selectedCands().some((c) => isSystem(c.target)) ? set({ modal: 'system' }) : selectedCands().some(isRevert) ? set({ modal: 'revert' }) : applySelected()),
  'modal-system-go': () => { if (selectedCands().some(isRevert)) set({ modal: 'revert' }); else { set({ modal: null }); applySelected(); } },
  'modal-revert-go': () => { set({ modal: null }); applySelected(); },
  'close-ask': () => set({ modal: 'close', closeList: uniqueHolders(state.locks.items) }),
  'modal-close-go': () => closeRetry(),
  'remind-on': () => remind(true),
  'remind-off': () => remind(false),
  'continue-later': () => set({ contHidden: true }),
  'continue-off': () => {
    const first = state.continuations[0];
    invoke('remind_after_reboot', { opId: first.id, on: false }).then(() => set({ continuations: state.continuations.slice(1) })).catch(fail);
  },
  'continue-op': () => {
    const [op, ...rest] = state.continuations;
    if (op.status === 'pendingReboot' && !op.items.length) { set({ continuations: rest, op }); scanOp(op.id); }
    else { set({ continuations: rest, op, plan: op.plan, view: 'result', closeInfo: null }); loadLocks(op); }
  },
  restore: () => runOp('restore', { opId: state.op.id }),
  retry: () => runOp('apply', { opId: state.op.id, ids: retryable(state.op).map((i) => i.candidateId) }),
  'dismiss-error': () => set({ error: null }),
  'check-update': () => checkUpdate(true),
  'update-later': () => set({ update: null }),
  'update-install': () => installUpdate(),
};

async function checkUpdate(manual) {
  const msg = (t) => { const el = $('#upmsg'); if (el) el.textContent = t; };
  try {
    const v = await invoke('update_check');
    if (v) set({ update: v }); else if (manual) msg(S.upToDate);
  } catch (e) { if (manual) msg(S.updateCheckFailed); }
}

async function installUpdate() {
  set({ updating: true });
  try { await invoke('update_install'); } catch (e) { set({ updating: false, error: String(e) }); }
}

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el || el.disabled) return;
  const fn = actions[el.dataset.act];
  if (fn) fn(el, e);
});
document.addEventListener('click', (e) => {
  if (state.popover && !e.target.closest('#popover') && !e.target.closest('[data-act="settings"]')) set({ popover: false });
});

document.addEventListener('input', (e) => {
  if (e.target.id === 'q') { state.query = e.target.value; renderList(); }
  if (e.target.id === 'fname' || e.target.id === 'fpub') {
    state.force[e.target.id === 'fname' ? 'name' : 'publisher'] = e.target.value;
    const run = $('#frun');
    if (run) run.disabled = !forceReady() || state.busy;
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (state.modal) set({ modal: null }); else if (state.popover) set({ popover: false });
});

T.event.listen('native-progress', (ev) => {
  state.procs = ev.payload;
  const el = $('#procs');
  if (el) el.innerHTML = state.procs.map((p) => esc(p.image)).join('<br>') || '…';
});

appWindow.onResized?.(async () => {
  const g = $('#maxglyph');
  if (g) g.textContent = (await appWindow.isMaximized()) ? '' : '';
});

(async function init() {
  state.info = await invoke('app_info');
  render();
  loadApps();
  checkUpdate(false);
  invoke('reboot_continuations').then((c) => set({ continuations: c })).catch(() => {});
})();
