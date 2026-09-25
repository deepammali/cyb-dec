'use strict';

// Every string that reaches the page may come from a scanned server (banners,
// errors), so the DOM is built with text nodes only, never HTML strings.
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (id) => document.getElementById(id);
const plural = (n, one, many) => (n === 1 ? one : many || one + 's');

const LABEL = {
  pq: 'Post-quantum', classical: 'Classical', plaintext: 'Plaintext', unverified: 'Unverified',
  error: 'Error', closed: 'Closed', no_response: 'No response', pending: 'Probing…', skipped: 'Not scanned',
};
const ICON = { pq: '✓', classical: '✕', plaintext: '✕', unverified: '!', error: '!', closed: '–', no_response: '…', skipped: '–' };
const SEVERITY = { plaintext: 0, classical: 1, unverified: 2, error: 3, pq: 4, closed: 5, no_response: 6 };
const CONF = {
  confirmed: 'Confirmed', high: 'One check', partial: 'Some clients', inconsistent: 'Unverified', low: 'Low',
};
const PRIORITY = {
  now: ['Now', 'Exposed to harvest-now-decrypt-later, or plaintext.'],
  harden: ['Harden', 'Standards and compliance (NIST, CNSA 2.0).'],
  plan: ['Plan', 'Signatures and crypto agility.'],
};
const VERDICT = { ready: 'Post-quantum', not_ready: 'Not post-quantum', undetermined: "Couldn't determine", running: 'Scanning', stopped: 'Stopped' };

const state = { catalog: null, selected: new Set(), scan: null };

// ---------- scope ----------

const presetServices = (id) => state.catalog.presets.find((p) => p.id === id).services;
const allNames = () => state.catalog.services.map((s) => s.name);
const allSelected = () => state.selected.size === state.catalog.services.length;

function buildScope() {
  const chips = $('chips');
  chips.replaceChildren(
    ...state.catalog.presets.map((p) =>
      h('button', { type: 'button', class: 'chip', 'data-preset': p.id, 'aria-pressed': 'false', onclick: () => togglePreset(p.id) }, p.label)),
    h('button', { type: 'button', class: 'chip chip-custom', id: 'custom-toggle', 'aria-expanded': 'false', 'aria-controls': 'custom', onclick: toggleCustom }, 'Custom'),
  );
  const box = $('custom');
  for (const group of [...new Set(state.catalog.services.map((s) => s.group))]) {
    box.append(h('div', { class: 'custom-group' },
      h('p', { class: 'custom-title', text: group }),
      state.catalog.services.filter((s) => s.group === group).map((s) =>
        h('label', { class: 'check' },
          h('input', { type: 'checkbox', value: s.name, onchange: (e) => onCustomCheck(e.target, s.name) }),
          h('span', null, s.name), h('small', null, String(s.port))))));
  }
  $('protocol').replaceChildren(...state.catalog.protocols.map((p) => h('option', { value: p.id }, p.label)));
  updateScope();
}

function togglePreset(id) {
  if (id === 'all') {
    state.selected = new Set(allNames());
  } else {
    const svcs = presetServices(id);
    const active = !allSelected() && svcs.every((n) => state.selected.has(n));
    if (allSelected()) state.selected = new Set(svcs); // from "Everything", a role means "just this"
    else if (active) svcs.forEach((n) => state.selected.delete(n));
    else svcs.forEach((n) => state.selected.add(n));
    if (!state.selected.size) state.selected = new Set(allNames());
  }
  updateScope();
}

function onCustomCheck(input, name) {
  if (input.checked) state.selected.add(name);
  else if (state.selected.size > 1) state.selected.delete(name);
  else input.checked = true; // keep at least one service selected
  updateScope();
}

function toggleCustom() {
  const box = $('custom');
  box.hidden = !box.hidden;
  $('custom-toggle').setAttribute('aria-expanded', String(!box.hidden));
}

function updateScope() {
  const all = allSelected();
  for (const b of $('chips').querySelectorAll('[data-preset]')) {
    const id = b.dataset.preset;
    const on = id === 'all' ? all : !all && presetServices(id).every((n) => state.selected.has(n));
    b.setAttribute('aria-pressed', String(on));
  }
  for (const cb of $('custom').querySelectorAll('input')) cb.checked = state.selected.has(cb.value);
  const chosen = state.catalog.services.filter((s) => state.selected.has(s.name));
  $('scope-summary').textContent = all
    ? `All ${chosen.length} services · results stream in · stop anytime`
    : `${chosen.length} ${plural(chosen.length, 'service')}: ${chosen.map((s) => `${s.name} ${s.port}`).join(', ')}`;
}

// host:port (including [v6]:port and URLs with a port) switches to a single-port scan.
const PORT_RE = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#[\]\s]+):(\d{1,5})(?:[/?#].*)?$/i;
const targetPort = (v) => { const m = v.trim().match(PORT_RE); return m ? Number(m[2]) : 0; };

function onHostInput() {
  const port = targetPort($('host').value);
  $('protocol-row').hidden = !port;
  $('scope-row').hidden = !!port;
  if (port) $('protocol-note').textContent = `Port ${port} was entered, so only that port is probed.`;
  $('form-error').hidden = true;
}

function showFormError(msg) {
  const el = $('form-error');
  el.textContent = msg;
  el.hidden = false;
}

// ---------- scanning ----------

async function startScan() {
  const host = $('host').value.trim();
  if (!host) { showFormError('Enter a hostname, IP address, or host:port.'); $('host').focus(); return; }
  if (state.scan && !state.scan.done) return;
  $('form-error').hidden = true;

  const body = { host };
  if (targetPort(host)) body.protocol = $('protocol').value;
  else if (!allSelected()) body.services = [...state.selected];
  syncURL(body);

  const scan = state.scan = {
    host, ctrl: new AbortController(), rows: new Map(), planned: [], controls: [], path: null,
    started: performance.now(), startedAt: new Date(), elapsed: 0,
    report: null, done: false, stopped: false, filter: null, expanded: new Set(), showCollapsed: {}, timer: 0,
  };
  setRunning(true);
  announce(`Scanning ${host}.`);
  try {
    const resp = await fetch('api/scan/stream', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: scan.ctrl.signal,
    });
    if (!resp.ok) {
      const e = await resp.json().catch(() => ({}));
      throw new Error(e.error || `Request failed (${resp.status}).`);
    }
    await readNDJSON(resp, (ev) => onEvent(scan, ev));
    if (!scan.done) throw new Error('The scan ended before it finished. Try again.');
  } catch (err) {
    if (scan.stopped) await finishStopped(scan);
    else { showFormError(err.message); if (!scan.rows.size) $('report').hidden = true; }
  } finally {
    clearInterval(scan.timer);
    scan.done = true;
    setRunning(false);
  }
}

async function readNDJSON(resp, onLine) {
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) onLine(JSON.parse(line));
    }
  }
  if (buf.trim()) onLine(JSON.parse(buf));
}

function onEvent(scan, ev) {
  if (ev.type === 'start') {
    scan.host = ev.host;
    scan.planned = ev.services;
    scan.controls = ev.controls || [];
    scan.path = ev.path || null;
    for (const s of ev.services) scan.rows.set(s.port, { plan: s, report: null });
    $('report').hidden = false;
    renderAll(scan);
    scan.timer = setInterval(() => renderProgress(scan), 250);
  } else if (ev.type === 'service') {
    const s = ev.service;
    const row = scan.rows.get(s.port) || { plan: { name: s.service, port: s.port } };
    row.report = s;
    scan.rows.set(s.port, row);
    renderAll(scan);
    const n = resolved(scan).length;
    if (n === scan.planned.length || n % 5 === 0) announce(`${n} of ${scan.planned.length} services scanned.`);
  } else if (ev.type === 'done') {
    scan.report = ev.report;
    scan.elapsed = (performance.now() - scan.started) / 1000;
    scan.done = true;
    renderAll(scan);
    announce(`Scan finished. ${ev.report.headline}`);
    $('verdict-title').focus();
  }
}

function stopScan() {
  const scan = state.scan;
  if (!scan || scan.done) return;
  scan.stopped = true;
  scan.ctrl.abort();
}

// A stopped stream never sends "done"; ask the server to summarize what arrived.
async function finishStopped(scan) {
  scan.elapsed = (performance.now() - scan.started) / 1000;
  try {
    const resp = await fetch('api/rollup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: scan.host, planned: scan.planned.length, services: resolved(scan) }),
    });
    if (resp.ok) scan.report = await resp.json();
  } catch { /* the partial table still renders without the summary */ }
  scan.done = true;
  $('report').hidden = false;
  renderAll(scan);
  announce('Scan stopped.');
  $('verdict-title').focus();
}

function setRunning(on) {
  $('go').hidden = on;
  $('stop').hidden = !on;
  $('host').readOnly = on;
  if (on) $('stop').focus();
}

const resolved = (scan) => [...scan.rows.values()].filter((r) => r.report).map((r) => r.report);

// ---------- classification ----------

function category(r) {
  if (r.errorKind === 'no_starttls') return 'plaintext';
  if (r.state === 'pq' && r.assessment && r.assessment.confidence === 'inconsistent') return 'unverified';
  return r.state;
}

function keyExchange(r) {
  const c = category(r);
  if (c === 'plaintext') return 'plaintext (no TLS)';
  if (['closed', 'no_response', 'error'].includes(c)) return '—';
  const g = r.negotiatedGroup || '';
  if (r.kind === 'ssh') return r.state === 'pq' ? r.bestPqGroup : 'no post-quantum method';
  if (r.state === 'pq') return g.includes('MLKEM') ? g : `${r.bestPqGroup} only`;
  if (g.startsWith('none')) return 'TLS 1.2 · classical';
  return g ? `${g} · classical` : 'classical';
}

function countCategories(reports) {
  const counts = {};
  for (const r of reports) { const c = category(r); counts[c] = (counts[c] || 0) + 1; }
  return counts;
}

// ---------- rendering ----------

function renderAll(scan) {
  renderVerdict(scan);
  renderRecs(scan);
  renderServices(scan);
}

function renderVerdict(scan) {
  const rep = scan.report;
  const done = resolved(scan);
  const total = scan.planned.length;
  const counts = countCategories(rep ? rep.services : done);
  const running = !scan.done && !rep;

  let verdict = rep ? rep.verdict : running ? 'running' : 'stopped';
  let headline = rep ? rep.headline : provisional(counts, done.length, total);
  const stoppedNote = scan.stopped
    ? h('p', { class: 'stopped' }, `Stopped: ${done.length} of ${total} ${plural(total, 'service')} scanned. Unscanned services aren't included below.`)
    : null;

  const chips = h('div', { class: 'counts', role: 'group', 'aria-label': 'Filter services by result' },
    Object.keys(SEVERITY).filter((c) => counts[c]).map((c) =>
      h('button', {
        type: 'button', class: `count s-${c}`, 'aria-pressed': String(scan.filter === c),
        onclick: () => {
          scan.filter = scan.filter === c ? null : c;
          renderServices(scan);
          renderVerdict(scan);
          const again = $('verdict').querySelector(`.count.s-${c}`);
          if (again) again.focus();
        },
      }, h('span', { class: 'icon', 'aria-hidden': 'true' }, ICON[c]), `${LABEL[c]} ${counts[c]}`)));

  const progress = running ? progressBar(scan) : null;
  const meta = !running
    ? h('div', { class: 'meta-row' },
      h('span', { class: 'meta' }, `${scan.startedAt.toISOString().slice(0, 16).replace('T', ' ')} UTC · ${scan.elapsed.toFixed(1)} s`),
      h('span', { class: 'actions' },
        h('button', { type: 'button', class: 'link', onclick: (e) => copyText(location.href, e.currentTarget, 'Copy link') }, 'Copy link'),
        h('button', { type: 'button', class: 'link', onclick: () => downloadJSON(scan) }, 'Download JSON'),
        h('button', { type: 'button', class: 'link', onclick: () => window.print() }, 'Print')))
    : null;

  const v = $('verdict');
  v.className = `verdict v-${verdict}`;
  v.replaceChildren(...[
    h('div', { class: 'verdict-top' },
      h('span', { class: `badge b-${verdict}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), VERDICT[verdict]),
      h('span', { class: 'target' }, scan.host)),
    h('h2', { id: 'verdict-title', tabindex: '-1' }, headline),
    stoppedNote, chips, progress, trustPanel(scan), meta,
  ].filter(Boolean));
}

function provisional(counts, n, total) {
  if (!n) return `Probing ${total} ${plural(total, 'service')}…`;
  const parts = Object.keys(SEVERITY).filter((c) => counts[c]).map((c) => `${counts[c]} ${LABEL[c].toLowerCase()}`);
  return `So far: ${parts.join(', ')}.`;
}

function progressBar(scan) {
  const fill = h('span', { class: 'fill' });
  const text = h('span', { class: 'progress-text' });
  const bar = h('div', { class: 'bar', role: 'progressbar', 'aria-label': 'Services scanned', 'aria-valuemin': '0' }, fill);
  scan.progressEls = { fill, text, bar };
  renderProgress(scan);
  return h('div', { class: 'progress' }, bar, text);
}

function renderProgress(scan) {
  const els = scan.progressEls;
  if (!els || scan.done) return;
  const n = resolved(scan).length;
  const total = scan.planned.length || 1;
  els.fill.style.width = `${Math.round((100 * n) / total)}%`;
  els.bar.setAttribute('aria-valuemax', String(total));
  els.bar.setAttribute('aria-valuenow', String(n));
  els.text.textContent = `${n} / ${scan.planned.length} · ${((performance.now() - scan.started) / 1000).toFixed(1)} s`;
}

function trustPanel(scan) {
  const cs = (scan.report && scan.report.controls) || scan.controls || [];
  const path = (scan.report && scan.report.path) || scan.path;
  const passed = cs.filter((c) => c.pass).length;
  const ctlOK = cs.length > 0 && passed === cs.length;

  let pathClass = 't-na', pathText = 'Network path not verified';
  if (path && path.error) { pathClass = 't-na'; pathText = 'Network path check unavailable'; }
  else if (path && path.loopback) { pathClass = 't-na'; pathText = 'Network path: local reference only'; }
  else if (path && path.carried) { pathClass = 't-pass'; pathText = 'Network path carries ML-KEM'; }
  else if (path) { pathClass = 't-fail'; pathText = 'Network path strips ML-KEM'; }

  return h('details', { class: 'trust' },
    h('summary', null,
      h('span', { class: `trust-item ${ctlOK ? 't-pass' : 't-fail'}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, ctlOK ? '✓' : '✕'), `Engine controls ${passed}/${cs.length} passed`),
      h('span', { class: `trust-item ${pathClass}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, pathClass === 't-pass' ? '✓' : pathClass === 't-fail' ? '✕' : '–'), pathText)),
    h('div', { class: 'trust-body' },
      h('p', null, 'Before every result is trusted, the engine probes local reference servers whose answers are known. A failed positive control would mean false negatives, and a failed negative control would mean false positives.'),
      h('ul', { class: 'checks' }, cs.map((c) => h('li', { class: c.pass ? 'o-pass' : 'o-fail' },
        h('span', { class: 'icon', 'aria-hidden': 'true' }, c.pass ? '✓' : '✕'),
        h('span', null, h('strong', null, c.name), ` expected ${c.expect}; got ${c.got}.`)))),
      path
        ? h('p', null, h('strong', null, 'Network path. '), path.error
          ? `Reference ${path.reference} could not be checked: ${path.error}.`
          : `Reference ${path.reference}: ${path.detail}. ${path.loopback
            ? 'The reference is on this machine, so it verifies only targets on this machine; for anything else, use a known ML-KEM server reached the same way as your targets.'
            : path.carried ? 'ML-KEM offers reach servers from here.' : 'A known ML-KEM server read as classical, so classical results from this scanner may be false negatives.'}`)
        : h('p', null, h('strong', null, 'Network path. '), 'Not verified. A middlebox that strips ML-KEM offers would make every server look classical. Start the scanner with --reference <a server known to support ML-KEM> to check.')));
}

function renderRecs(scan) {
  const sec = $('recs');
  if (!scan.report) { sec.hidden = true; return; }
  const recs = scan.report.recommendations || [];
  sec.hidden = false;
  const exposed = (scan.report.services || []).some((r) => ['pq', 'classical'].includes(r.state) || r.errorKind === 'no_starttls');
  const head = h('div', { class: 'section-head' },
    h('h2', { id: 'recs-title' }, 'Improve quantum resilience'),
    recs.length ? h('span', { class: 'section-note' }, `${recs.length} ${plural(recs.length, 'recommendation')}, from this scan's evidence`) : null);
  if (!recs.length) {
    sec.replaceChildren(head, h('p', { class: 'empty' }, exposed
      ? 'Nothing to change: every exposed service uses post-quantum key exchange and there is nothing left to harden.'
      : 'No recommendations: no exposed service could be assessed.'));
    return;
  }
  let n = 0;
  const groups = Object.keys(PRIORITY).filter((p) => recs.some((r) => r.priority === p)).map((p) =>
    h('div', { class: `rec-group p-${p}` },
      h('div', { class: 'rec-group-head' }, h('span', { class: `prio prio-${p}` }, PRIORITY[p][0]), h('span', { class: 'section-note' }, PRIORITY[p][1])),
      recs.filter((r) => r.priority === p).map((r) => { n++; return recCard(scan, r, n, n === 1); })));
  sec.replaceChildren(head, ...groups);
}

function recCard(scan, r, n, open) {
  return h('details', { class: 'rec', id: `rec-${r.id}`, open },
    h('summary', null,
      h('span', { class: 'rec-num' }, String(n)),
      h('span', { class: 'rec-title' }, r.title),
      h('span', { class: 'rec-svcs' }, r.services.map((key) => h('button', {
        type: 'button', class: 'svc-link', onclick: (e) => { e.preventDefault(); e.stopPropagation(); jumpToRow(scan, portOf(key)); },
      }, key.replace(':', ' '))))),
    h('div', { class: 'rec-body' },
      h('p', null, r.why),
      r.steps && r.steps.length ? h('ol', { class: 'steps' }, r.steps.map((s) => h('li', null, s))) : null,
      (r.snippets || []).map((s) => h('div', { class: 'snippet' },
        h('div', { class: 'snippet-head' }, h('span', null, s.label),
          h('button', { type: 'button', class: 'link', onclick: (e) => copyText(s.code, e.currentTarget, 'Copy') }, 'Copy')),
        h('pre', null, h('code', null, s.code)))),
      r.refs && r.refs.length ? h('p', { class: 'refs' }, 'References: ', r.refs.map((ref, i) => [i ? ' · ' : '', h('a', { href: ref.url, rel: 'noreferrer' }, ref.label)])) : null));
}

const portOf = (key) => Number(String(key).split(':').pop());

function jumpToRow(scan, port) {
  scan.filter = null;
  scan.expanded.add(port);
  const row = scan.rows.get(port);
  if (row && row.report) scan.showCollapsed[category(row.report)] = true;
  renderVerdict(scan);
  renderServices(scan);
  const btn = $(`svc-${port}`);
  if (btn) { btn.scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }); btn.focus({ preventScroll: true }); }
}

function renderServices(scan) {
  const sec = $('services');
  const main = [], collapsed = { closed: [], no_response: [] }, pending = [];
  for (const row of scan.rows.values()) {
    if (!row.report) { pending.push(row); continue; }
    const c = category(row.report);
    if (scan.filter && c !== scan.filter) continue;
    if (collapsed[c] && !scan.filter && !scan.showCollapsed[c] && !scan.printing) collapsed[c].push(row);
    else main.push(row);
  }
  main.sort((a, b) => SEVERITY[category(a.report)] - SEVERITY[category(b.report)]);

  const head = h('div', { class: 'section-head' },
    h('h2', { id: 'services-title' }, 'Services'),
    scan.filter ? h('span', { class: 'section-note' }, `Showing ${LABEL[scan.filter].toLowerCase()} only · `,
      h('button', { type: 'button', class: 'link', onclick: () => { scan.filter = null; renderAll(scan); } }, 'Show all')) : null);

  const table = h('div', { class: 'svc-table', role: 'list' },
    h('div', { class: 'svc-head', 'aria-hidden': 'true' },
      h('span', null, 'Service'), h('span', null, 'Port'), h('span', null, 'Key exchange'), h('span', null, 'Result'), h('span', null, 'Confidence')),
    main.map((row) => serviceRow(scan, row)),
    scan.filter ? null : pending.map((row) => pendingRow(scan, row)),
    Object.entries(collapsed).filter(([, rows]) => rows.length).map(([c, rows]) =>
      h('div', { class: `collapsed s-${c}`, role: 'listitem' },
        h('span', null, h('span', { class: 'icon', 'aria-hidden': 'true' }, ICON[c]), `${rows.length} ${c === 'closed' ? 'closed' : 'no response'}: `,
          h('span', { class: 'collapsed-list' }, rows.map((r) => `${r.report.service} ${r.report.port}`).join(', '))),
        h('button', { type: 'button', class: 'link', onclick: () => { scan.showCollapsed[c] = true; renderServices(scan); } }, 'Show'))));
  sec.replaceChildren(head, table);
}

function serviceRow(scan, row) {
  const r = row.report;
  const c = category(r);
  const open = scan.expanded.has(r.port) || !!scan.printing;
  const id = `svc-${r.port}`;
  const conf = r.assessment && c !== 'unverified' && CONF[r.assessment.confidence];
  const btn = h('button', {
    type: 'button', class: `row s-${c}`, id, 'aria-expanded': String(open), 'aria-controls': `${id}-detail`,
    onclick: () => { if (scan.expanded.has(r.port)) scan.expanded.delete(r.port); else scan.expanded.add(r.port); renderServices(scan); $(id).focus(); },
  },
  h('span', { class: 'c-name' }, h('span', { class: 'chev', 'aria-hidden': 'true' }), r.service, r.detected ? h('span', { class: 'tag' }, 'detected') : null),
  h('span', { class: 'c-port' }, h('span', { class: 'sr-only' }, 'port '), String(r.port)),
  h('span', { class: 'c-kex' }, keyExchange(r)),
  h('span', { class: 'c-status' }, h('span', { class: `pill s-${c}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, ICON[c]), LABEL[c])),
  h('span', { class: 'c-conf' }, conf ? h('span', { class: `conf conf-${r.assessment.confidence}` }, conf) : null));
  return h('div', { class: 'row-wrap', role: 'listitem' }, btn, open ? detailPanel(scan, r, `${id}-detail`) : null);
}

function pendingRow(scan, row) {
  const c = scan.done ? 'skipped' : 'pending';
  return h('div', { class: `row-wrap`, role: 'listitem' },
    h('div', { class: `row s-${c}` },
      h('span', { class: 'c-name' }, h('span', { class: 'chev placeholder', 'aria-hidden': 'true' }), row.plan.name),
      h('span', { class: 'c-port' }, String(row.plan.port)),
      h('span', { class: 'c-kex' }, '—'),
      h('span', { class: 'c-status' }, h('span', { class: `pill s-${c}` }, c === 'pending' ? h('span', { class: 'spinner', 'aria-hidden': 'true' }) : null, LABEL[c])),
      h('span', { class: 'c-conf' })));
}

function detailPanel(scan, r, id) {
  const a = r.assessment || {};
  const recs = ((scan.report && scan.report.recommendations) || []).filter((rec) => rec.services.some((k) => portOf(k) === r.port));
  const facts = [
    ['Tested', r.address || `${r.host}:${r.port}`],
    ['Protocol', r.protocol ? `${r.protocol}${r.detected ? ' (auto-detected)' : ''}` : null],
    ['Server says', r.banner],
    ['TLS', r.tlsVersion ? `${r.tlsVersion} · ${r.cipherSuite}` : null],
    ['Certificate', r.certSignatureAlgorithm ? `${r.certSubject ? `CN=${r.certSubject} · ` : ''}${r.certSignatureAlgorithm} · expires ${r.certNotAfter}` : null],
    ['Error', r.error],
  ].filter(([, v]) => v);

  return h('div', { class: 'detail', id },
    h('p', { class: 'detail-headline' }, r.headline),
    a.summary ? h('section', { class: `sure conf-box-${a.confidence}` },
      h('h3', null, 'How sure is this?', CONF[a.confidence] ? h('span', { class: `conf conf-${a.confidence}` }, CONF[a.confidence]) : null),
      h('p', null, a.summary),
      a.checks && a.checks.length ? h('ul', { class: 'checks' }, a.checks.map((c) => h('li', { class: `o-${c.outcome}` },
        h('span', { class: 'icon', 'aria-hidden': 'true' }, { pq: '✓', pass: '✓', classical: '✕', fail: '✕', not_run: '–' }[c.outcome] || '?'),
        h('span', null, h('strong', null, `${c.name}. `), c.detail)))) : null,
      a.question ? h('p', { class: 'qa' }, h('strong', null, a.question), ' ', a.answer) : null,
      a.limits ? h('p', { class: 'limits' }, h('strong', null, 'Limits. '), a.limits) : null) : null,
    h('section', { class: 'evidence' },
      h('h3', null, 'Evidence'),
      h('dl', { class: 'facts' }, facts.map(([k, v]) => h('div', null, h('dt', null, k), h('dd', null, v)))),
      r.kind !== 'ssh' && r.groups && r.groups.length ? h('ul', { class: 'groups' }, r.groups.map((g) => {
        const o = g.supported ? 'pq' : g.serverChose || g.alerted ? 'classical' : 'inconclusive';
        const chose = g.alerted ? 'refused the offer' : g.serverChose ? `chose ${g.serverChose}` : g.note || 'no answer';
        return h('li', { class: `o-${o}` },
          h('span', { class: 'icon', 'aria-hidden': 'true' }, o === 'pq' ? '✓' : o === 'classical' ? (g.lowConfidence ? '~' : '✕') : '?'),
          h('span', null, h('code', null, g.group), ` offered as ${g.offered || g.group} → server ${chose}`,
            g.lowConfidence ? h('span', { class: 'muted' }, ' (legacy draft: a “no” is not authoritative)') : null));
      })) : null,
      r.kind === 'ssh' && r.advertised && r.advertised.length ? h('p', { class: 'advertised' }, 'Advertised key exchange: ', r.advertised.map((k, i) => [i ? ', ' : '', h('code', null, k)])) : null),
    recs.length ? h('section', { class: 'applies' },
      h('h3', null, 'What to do'),
      h('ul', null, recs.map((rec) => h('li', null, h('button', {
        type: 'button', class: 'link', onclick: () => { const d = $(`rec-${rec.id}`); d.open = true; d.scrollIntoView({ block: 'start' }); d.querySelector('summary').focus(); },
      }, rec.title), h('span', { class: `prio prio-${rec.priority}` }, PRIORITY[rec.priority][0]))))) : null);
}

// ---------- carry: link, JSON, print ----------

function syncURL(body) {
  const p = new URLSearchParams({ host: body.host });
  if (body.protocol && body.protocol !== 'auto') p.set('protocol', body.protocol);
  if (body.services) p.set('services', body.services.join(','));
  history.replaceState(null, '', `?${p}`);
}

function initFromURL() {
  const p = new URLSearchParams(location.search);
  const host = p.get('host');
  if (!host) return false;
  $('host').value = host;
  onHostInput();
  if (p.get('protocol')) $('protocol').value = p.get('protocol');
  if (p.get('services')) {
    const want = p.get('services').split(',');
    const valid = allNames().filter((n) => want.includes(n));
    if (valid.length) { state.selected = new Set(valid); updateScope(); }
  }
  return true;
}

// Clipboard API needs a secure context; internal http:// deployments fall back.
async function copyText(text, btn, label) {
  let ok = false;
  try { if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); ok = true; } } catch { /* fall back */ }
  if (!ok) {
    const ta = h('textarea', { class: 'sr-only', readonly: true });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
  }
  btn.textContent = ok ? 'Copied' : 'Copy failed';
  setTimeout(() => { btn.textContent = label; }, 1800);
}

function downloadJSON(scan) {
  const data = scan.report || { host: scan.host, partial: true, services: resolved(scan) };
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a = h('a', { href: url, download: `pqscan-${scan.host.replace(/[^a-z0-9.-]/gi, '_')}-${scan.startedAt.toISOString().slice(0, 10)}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Printing is the auditor's report: expand every row and recommendation.
let printOpened = [];
addEventListener('beforeprint', () => {
  const scan = state.scan;
  if (scan) { scan.printing = true; renderServices(scan); }
  printOpened = [...document.querySelectorAll('details:not([open])')];
  printOpened.forEach((d) => { d.open = true; });
});
addEventListener('afterprint', () => {
  printOpened.forEach((d) => { d.open = false; });
  const scan = state.scan;
  if (scan) { scan.printing = false; renderServices(scan); }
});

function announce(msg) { $('announcer').textContent = msg; }

// ---------- boot ----------

$('scan-form').addEventListener('submit', (e) => { e.preventDefault(); startScan(); });
$('stop').addEventListener('click', stopScan);
$('host').addEventListener('input', onHostInput);

(async function boot() {
  try {
    const resp = await fetch('api/catalog');
    if (!resp.ok) throw new Error(`catalog request failed (${resp.status})`);
    state.catalog = await resp.json();
  } catch (err) {
    showFormError(`Couldn't load the service list: ${err.message}`);
    return;
  }
  state.selected = new Set(allNames());
  buildScope();
  if (initFromURL()) startScan();
})();
