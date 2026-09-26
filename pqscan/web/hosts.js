// Hosts view: scan one host (probe) or a list of targets (estate).
import {
  h, $, plural, reducedMotion, VERDICT, CONF, PRIORITY, readNDJSON, postJSON, copyText, downloadJSON, downloadCBOM,
  announce, showFormError, stamp, assessmentBlock, trustPanel, recsSection, openRec, onPrint,
} from './core.js';

const LABEL = {
  pq: 'Post-quantum', classical: 'Classical', plaintext: 'Plaintext', unverified: 'Unverified',
  error: 'Error', closed: 'Closed', no_response: 'No response', pending: 'Probing…', skipped: 'Not scanned',
};
const ICON = { pq: '✓', classical: '✕', plaintext: '✕', unverified: '!', error: '!', closed: '–', no_response: '…', skipped: '–' };
const SEVERITY = { plaintext: 0, classical: 1, unverified: 2, error: 3, pq: 4, closed: 5, no_response: 6 };
const HOST_ORDER = { not_ready: 0, undetermined: 1, ready: 2 };

const st = { catalog: null, selected: new Set(), mode: 'host', scan: null, estate: null };
const running = () => (st.scan && !st.scan.done) || (st.estate && !st.estate.done);

// ---------- scope ----------

const presetServices = (id) => st.catalog.presets.find((p) => p.id === id).services;
const allNames = () => st.catalog.services.map((s) => s.name);
const allSelected = () => st.selected.size === st.catalog.services.length;

function buildScope() {
  $('chips').replaceChildren(
    ...st.catalog.presets.map((p) =>
      h('button', { type: 'button', class: 'chip', 'data-preset': p.id, 'aria-pressed': 'false', onclick: () => togglePreset(p.id) }, p.label)),
    h('button', { type: 'button', class: 'chip chip-custom', id: 'custom-toggle', 'aria-expanded': 'false', 'aria-controls': 'custom', onclick: toggleCustom }, 'Custom'),
  );
  const box = $('custom');
  for (const group of [...new Set(st.catalog.services.map((s) => s.group))]) {
    box.append(h('div', { class: 'custom-group' },
      h('p', { class: 'custom-title', text: group }),
      st.catalog.services.filter((s) => s.group === group).map((s) =>
        h('label', { class: 'check' },
          h('input', { type: 'checkbox', value: s.name, onchange: (e) => onCustomCheck(e.target, s.name) }),
          h('span', null, s.name), h('small', null, String(s.port))))));
  }
  $('protocol').replaceChildren(...st.catalog.protocols.map((p) => h('option', { value: p.id }, p.label)));
  $('targets-note').textContent = `Up to ${st.catalog.maxHosts} hosts; CIDRs expand to their addresses. The scope below applies to entries without a port.`;
  updateScope();
}

function togglePreset(id) {
  if (id === 'all') {
    st.selected = new Set(allNames());
  } else {
    const svcs = presetServices(id);
    const active = !allSelected() && svcs.every((n) => st.selected.has(n));
    if (allSelected()) st.selected = new Set(svcs); // from "Everything", a role means "just this"
    else if (active) svcs.forEach((n) => st.selected.delete(n));
    else svcs.forEach((n) => st.selected.add(n));
    if (!st.selected.size) st.selected = new Set(allNames());
  }
  updateScope();
}

function onCustomCheck(input, name) {
  if (input.checked) st.selected.add(name);
  else if (st.selected.size > 1) st.selected.delete(name);
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
    const on = id === 'all' ? all : !all && presetServices(id).every((n) => st.selected.has(n));
    b.setAttribute('aria-pressed', String(on));
  }
  for (const cb of $('custom').querySelectorAll('input')) cb.checked = st.selected.has(cb.value);
  const chosen = st.catalog.services.filter((s) => st.selected.has(s.name));
  $('scope-summary').textContent = all
    ? `All ${chosen.length} services · results stream in · stop anytime`
    : `${chosen.length} ${plural(chosen.length, 'service')}: ${chosen.map((s) => `${s.name} ${s.port}`).join(', ')}`;
}

// host:port (including [v6]:port and URLs with a port) switches to a single-port scan.
const PORT_RE = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#[\]\s]+):(\d{1,5})(?:[/?#].*)?$/i;
const targetPort = (v) => { const m = v.trim().match(PORT_RE); return m ? Number(m[2]) : 0; };

function syncForm() {
  const estate = st.mode === 'estate';
  const port = !estate && targetPort($('host').value);
  $('host-row').hidden = estate;
  $('host-hint').hidden = estate;
  $('targets-row').hidden = !estate;
  $('targets-hint').hidden = !estate;
  $('protocol-row').hidden = !port;
  $('scope-row').hidden = !!port;
  if (port) $('protocol-note').textContent = `Port ${port} was entered, so only that port is probed.`;
  showFormError('form-error', '');
}

function setRunning(on) {
  $('go').hidden = on;
  $('stop').hidden = !on;
  $('host').readOnly = on;
  $('targets').readOnly = on;
  for (const r of document.querySelectorAll('input[name="mode"]')) r.disabled = on;
  if (on) $('stop').focus();
}

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
  if (r.perAddress) return 'differs by address';
  if (r.assessment && r.assessment.confidence === 'mixed') return 'mixed pool';
  if (r.state === 'pq') return g.includes('MLKEM') ? g : `${r.bestPqGroup} only`;
  if (g.startsWith('none')) return 'TLS 1.2 · classical';
  return g ? `${g} · classical` : 'classical';
}

function countCategories(reports) {
  const counts = {};
  for (const r of reports) { const c = category(r); counts[c] = (counts[c] || 0) + 1; }
  return counts;
}

const resolved = (scan) => [...scan.rows.values()].filter((r) => r.report).map((r) => r.report);

// ---------- services table (single host and each estate host) ----------

// A "scan" here is any set of service rows: rows (port → {plan, report}),
// expanded ports, filter, collapsed groups, an id prefix, and rerender().
function newRows(idPrefix, rerender) {
  return { rows: new Map(), expanded: new Set(), filter: null, showCollapsed: {}, idPrefix, rerender, report: null, done: false };
}

function servicesTable(scan) {
  const main = [], collapsed = { closed: [], no_response: [] }, pending = [];
  for (const row of scan.rows.values()) {
    if (!row.report) { pending.push(row); continue; }
    const c = category(row.report);
    if (scan.filter && c !== scan.filter) continue;
    if (collapsed[c] && !scan.filter && !scan.showCollapsed[c] && !scan.printing) collapsed[c].push(row);
    else main.push(row);
  }
  main.sort((a, b) => SEVERITY[category(a.report)] - SEVERITY[category(b.report)]);
  return h('div', { class: 'svc-table', role: 'list' },
    h('div', { class: 'svc-head', 'aria-hidden': 'true' },
      h('span', null, 'Service'), h('span', null, 'Port'), h('span', null, 'Key exchange'), h('span', null, 'Result'), h('span', null, 'Confidence')),
    main.map((row) => serviceRow(scan, row)),
    scan.filter ? null : pending.map((row) => pendingRow(scan, row)),
    Object.entries(collapsed).filter(([, rows]) => rows.length).map(([c, rows]) =>
      h('div', { class: `collapsed s-${c}`, role: 'listitem' },
        h('span', null, h('span', { class: 'icon', 'aria-hidden': 'true' }, ICON[c]), `${rows.length} ${c === 'closed' ? 'closed' : 'no response'}: `,
          h('span', { class: 'collapsed-list' }, rows.map((r) => `${r.report.service} ${r.report.port}`).join(', '))),
        h('button', { type: 'button', class: 'link', onclick: () => { scan.showCollapsed[c] = true; scan.rerender(); } }, 'Show'))));
}

function serviceRow(scan, row) {
  const r = row.report;
  const c = category(r);
  const open = scan.expanded.has(r.port) || !!scan.printing;
  const id = `${scan.idPrefix}svc-${r.port}`;
  const conf = r.assessment && c !== 'unverified' && CONF[r.assessment.confidence];
  const btn = h('button', {
    type: 'button', class: `row s-${c}`, id, 'aria-expanded': String(open), 'aria-controls': `${id}-detail`,
    onclick: () => {
      if (scan.expanded.has(r.port)) scan.expanded.delete(r.port); else scan.expanded.add(r.port);
      scan.rerender();
      const again = $(id);
      if (again) again.focus();
    },
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
  return h('div', { class: 'row-wrap', role: 'listitem' },
    h('div', { class: `row s-${c}` },
      h('span', { class: 'c-name' }, h('span', { class: 'chev placeholder', 'aria-hidden': 'true' }), row.plan.name),
      h('span', { class: 'c-port' }, String(row.plan.port)),
      h('span', { class: 'c-kex' }, '—'),
      h('span', { class: 'c-status' }, h('span', { class: `pill s-${c}` }, c === 'pending' ? h('span', { class: 'spinner', 'aria-hidden': 'true' }) : null, LABEL[c])),
      h('span', { class: 'c-conf' })));
}

const portOf = (key) => Number(String(key).split(':').pop());

function detailPanel(scan, r, id) {
  const recs = ((scan.report && scan.report.recommendations) || []).filter((rec) => rec.services.some((k) => portOf(k) === r.port));
  const facts = [
    ['Tested', !r.addresses || r.addresses.length < 2 ? r.address || `${r.host}:${r.port}`
      : r.perAddress ? `${r.addresses.join(', ')}; the evidence below is from ${r.address}`
        : `${r.addresses.join(', ')} (same result on every address)`],
    ['Protocol', r.protocol ? `${r.protocol}${r.detected ? ' (auto-detected)' : ''}` : null],
    ['Server says', r.banner],
    ['TLS', r.tlsVersion ? `${r.tlsVersion} · ${r.cipherSuite}` : null],
    ['Certificate', r.certSignatureAlgorithm ? `${r.certSubject ? `CN=${r.certSubject} · ` : ''}${r.certSignatureAlgorithm} · expires ${(r.certNotAfter || "").slice(0, 10)}` : null],
    ['Terminates at', r.edge ? `${r.edge.name} (${r.edge.evidence}): the origin and the hops behind it weren't measured` : null],
    ['Error', r.error],
  ].filter(([, v]) => v);

  return h('div', { class: 'detail', id },
    h('p', { class: 'detail-headline' }, r.headline),
    assessmentBlock(r.assessment),
    r.perAddress ? h('section', { class: 'per-address' },
      h('h3', null, 'Each address'),
      h('ul', { class: 'groups' }, r.perAddress.map((pa) => {
        const c = pa.state;
        return h('li', { class: `o-${c === 'pq' ? 'pq' : c === 'classical' ? 'classical' : 'inconclusive'}` },
          h('span', { class: 'icon', 'aria-hidden': 'true' }, ICON[c] || '?'),
          h('span', null, h('code', null, pa.address), ` ${pa.headline}`));
      }))) : null,
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
      h('ul', null, recs.map((rec) => h('li', null,
        h('button', { type: 'button', class: 'link', onclick: () => openRec('recs', rec.id) }, rec.title),
        h('span', { class: `prio prio-${rec.priority}` }, PRIORITY[rec.priority][0]))))) : null);
}

function focusRow(id) {
  const btn = $(id);
  if (btn) { btn.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' }); btn.focus({ preventScroll: true }); }
}

function countChips(counts, order, labels, icons, active, onPick, label) {
  return h('div', { class: 'counts', role: 'group', 'aria-label': label },
    order.filter((c) => counts[c]).map((c) =>
      h('button', { type: 'button', class: `count s-${c}`, 'aria-pressed': String(active === c), 'data-key': c, onclick: () => onPick(c) },
        h('span', { class: 'icon', 'aria-hidden': 'true' }, icons[c]), `${labels[c]} ${counts[c]}`)));
}

function progressBar(state, total, label) {
  const fill = h('span', { class: 'fill' });
  const text = h('span', { class: 'progress-text' });
  const bar = h('div', { class: 'bar', role: 'progressbar', 'aria-label': label, 'aria-valuemin': '0', 'aria-valuemax': String(total) }, fill);
  state.progressEls = { fill, text, bar };
  return h('div', { class: 'progress' }, bar, text);
}

function tickProgress(state, n, total) {
  const els = state.progressEls;
  if (!els || state.done) return;
  els.fill.style.width = `${Math.round((100 * n) / (total || 1))}%`;
  els.bar.setAttribute('aria-valuenow', String(n));
  els.text.textContent = `${n} / ${total} · ${((performance.now() - state.started) / 1000).toFixed(1)} s`;
}

// ---------- single host ----------

async function startHostScan() {
  const host = $('host').value.trim();
  if (!host) { showFormError('form-error', 'Enter a hostname, IP address, or host:port.'); $('host').focus(); return; }
  const body = { host };
  if (targetPort(host)) body.protocol = $('protocol').value;
  else if (!allSelected()) body.services = [...st.selected];
  syncURL(body);

  st.estate = null;
  const scan = st.scan = Object.assign(newRows('', () => renderHostServices(scan)), {
    kind: 'host', host, ctrl: new AbortController(), planned: [], controls: [], path: null,
    started: performance.now(), startedAt: new Date(), elapsed: 0, stopped: false, timer: 0,
  });
  setRunning(true);
  announce(`Scanning ${host}.`);
  try {
    const resp = await postJSON('api/scan/stream', body, scan.ctrl.signal);
    await readNDJSON(resp, (ev) => onHostEvent(scan, ev));
    if (!scan.done) throw new Error('The scan ended before it finished. Try again.');
  } catch (err) {
    if (scan.stopped) await finishHostStopped(scan);
    else { showFormError('form-error', err.message); if (!scan.rows.size) $('report').hidden = true; }
  } finally {
    clearInterval(scan.timer);
    scan.done = true;
    setRunning(false);
  }
}

function onHostEvent(scan, ev) {
  if (ev.type === 'start') {
    scan.host = ev.host;
    scan.planned = ev.services;
    scan.controls = ev.controls || [];
    scan.path = ev.path || null;
    for (const s of ev.services) scan.rows.set(s.port, { plan: s, report: null });
    $('report').hidden = false;
    renderHost(scan);
    scan.timer = setInterval(() => tickProgress(scan, resolved(scan).length, scan.planned.length), 250);
  } else if (ev.type === 'service') {
    const s = ev.service;
    const row = scan.rows.get(s.port) || { plan: { name: s.service, port: s.port } };
    row.report = s;
    scan.rows.set(s.port, row);
    renderHost(scan);
    const n = resolved(scan).length;
    if (n === scan.planned.length || n % 5 === 0) announce(`${n} of ${scan.planned.length} services scanned.`);
  } else if (ev.type === 'done') {
    scan.report = ev.report;
    scan.elapsed = (performance.now() - scan.started) / 1000;
    scan.done = true;
    renderHost(scan);
    announce(`Scan finished. ${ev.report.headline}`);
    $('verdict-title').focus();
  }
}

// A stopped stream never sends "done"; ask the server to summarize what arrived.
async function finishHostStopped(scan) {
  scan.elapsed = (performance.now() - scan.started) / 1000;
  try {
    const resp = await postJSON('api/rollup', { host: scan.host, planned: scan.planned.length, services: resolved(scan) });
    scan.report = await resp.json();
  } catch { /* the partial table still renders without the summary */ }
  scan.done = true;
  $('report').hidden = false;
  renderHost(scan);
  announce('Scan stopped.');
  $('verdict-title').focus();
}

function renderHost(scan) {
  renderHostVerdict(scan);
  renderHostRecs(scan);
  renderHostServices(scan);
}

function renderHostVerdict(scan) {
  const rep = scan.report;
  const done = resolved(scan);
  const total = scan.planned.length;
  const counts = countCategories(rep ? rep.services : done);
  const live = !scan.done && !rep;
  const verdict = rep ? rep.verdict : live ? 'running' : 'stopped';
  const headline = rep ? rep.headline : !done.length ? `Probing ${total} ${plural(total, 'service')}…`
    : `So far: ${Object.keys(SEVERITY).filter((c) => counts[c]).map((c) => `${counts[c]} ${LABEL[c].toLowerCase()}`).join(', ')}.`;

  const v = $('verdict');
  v.className = `verdict v-${verdict}`;
  v.replaceChildren(...[
    h('div', { class: 'verdict-top' },
      h('span', { class: `badge b-${verdict}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), VERDICT[verdict]),
      h('span', { class: 'target' }, scan.host)),
    h('h2', { id: 'verdict-title', tabindex: '-1' }, headline),
    scan.stopped ? h('p', { class: 'stopped' }, `Stopped: ${done.length} of ${total} ${plural(total, 'service')} scanned. Unscanned services aren't included below.`) : null,
    countChips(counts, Object.keys(SEVERITY), LABEL, ICON, scan.filter, (c) => {
      scan.filter = scan.filter === c ? null : c;
      renderHostServices(scan);
      renderHostVerdict(scan);
      const again = $('verdict').querySelector(`.count[data-key="${c}"]`);
      if (again) again.focus();
    }, 'Filter services by result'),
    live ? progressBar(scan, total, 'Services scanned') : null,
    trustPanel((rep && rep.controls) || scan.controls, (rep && rep.path) || scan.path),
    !live ? h('div', { class: 'meta-row' },
      h('span', { class: 'meta' }, stamp(scan.startedAt, scan.elapsed)),
      h('span', { class: 'actions' },
        h('button', { type: 'button', class: 'link', onclick: (e) => copyText(location.href, e.currentTarget, 'Copy link') }, 'Copy link'),
        h('button', { type: 'button', class: 'link', onclick: () => downloadJSON(scan.report || { host: scan.host, partial: true, services: done }, `pqscan-${scan.host}-${scan.startedAt.toISOString().slice(0, 10)}.json`) }, 'Download JSON'),
        scan.report ? h('button', { type: 'button', class: 'link', title: 'CycloneDX 1.6 cryptography bill of materials', onclick: (e) => downloadCBOM('host', scan.report, `pqscan-${scan.host}-cbom.cdx.json`, e.currentTarget) }, 'Download CBOM') : null,
        h('button', { type: 'button', class: 'link', onclick: () => window.print() }, 'Print'))) : null,
  ].filter(Boolean));
  if (live) tickProgress(scan, done.length, total);
}

function renderHostRecs(scan) {
  const sec = $('recs');
  if (!scan.report) { sec.hidden = true; return; }
  sec.hidden = false;
  const exposed = (scan.report.services || []).some((r) => ['pq', 'classical'].includes(r.state) || r.errorKind === 'no_starttls');
  recsSection(sec, scan.report.recommendations || [], {
    note: "from this scan's evidence",
    emptyText: exposed
      ? 'Nothing to change: every exposed service uses post-quantum key exchange and there is nothing left to harden.'
      : 'No recommendations: no exposed service could be assessed.',
    label: (key) => key.replace(':', ' '),
    onTarget: (key) => {
      const port = portOf(key);
      scan.filter = null;
      scan.expanded.add(port);
      const row = scan.rows.get(port);
      if (row && row.report) scan.showCollapsed[category(row.report)] = true;
      renderHostVerdict(scan);
      renderHostServices(scan);
      focusRow(`svc-${port}`);
    },
  });
}

function renderHostServices(scan) {
  $('services').replaceChildren(
    h('div', { class: 'section-head' },
      h('h2', { id: 'services-title' }, 'Services'),
      scan.filter ? h('span', { class: 'section-note' }, `Showing ${LABEL[scan.filter].toLowerCase()} only · `,
        h('button', { type: 'button', class: 'link', onclick: () => { scan.filter = null; renderHost(scan); } }, 'Show all')) : null),
    servicesTable(scan));
}

// ---------- estate ----------

async function startEstate() {
  const targets = $('targets').value.trim();
  if (!targets) { showFormError('form-error', 'Enter at least one target: a host, host:port, URL, or CIDR per line.'); $('targets').focus(); return; }
  const body = { targets };
  if (!allSelected()) body.services = [...st.selected];

  st.scan = null;
  history.replaceState(null, '', location.pathname);
  const est = st.estate = {
    kind: 'estate', ctrl: new AbortController(), entries: [], controls: [], path: null, report: null,
    started: performance.now(), startedAt: new Date(), elapsed: 0, done: false, stopped: false, filter: null,
    expanded: new Set(), timer: 0,
  };
  setRunning(true);
  announce('Estate scan started.');
  try {
    const resp = await postJSON('api/estate/stream', body, est.ctrl.signal);
    await readNDJSON(resp, (ev) => onEstateEvent(est, ev));
    if (!est.done) throw new Error('The scan ended before it finished. Try again.');
  } catch (err) {
    if (est.stopped) await finishEstateStopped(est);
    else { showFormError('form-error', err.message); if (!est.entries.length) $('report').hidden = true; }
  } finally {
    clearInterval(est.timer);
    est.done = true;
    setRunning(false);
  }
}

function onEstateEvent(est, ev) {
  if (ev.type === 'start') {
    est.controls = ev.controls || [];
    est.path = ev.path || null;
    est.entries = ev.targets.map((t, i) => {
      const entry = { index: i, target: t, host: t.host, status: 'queued', report: null };
      entry.scan = newRows(`h${i}-`, () => renderEstateHosts(est));
      return entry;
    });
    $('report').hidden = false;
    renderEstate(est);
    est.timer = setInterval(() => tickProgress(est, est.entries.filter((e) => e.report).length, est.entries.length), 250);
    return;
  }
  if (ev.type === 'done') {
    est.report = ev.report;
    est.elapsed = (performance.now() - est.started) / 1000;
    est.done = true;
    for (const e of est.entries) e.scan.done = true;
    renderEstate(est);
    announce(`Estate scan finished. ${ev.report.headline}`);
    $('verdict-title').focus();
    return;
  }
  const entry = est.entries[ev.index];
  if (!entry) return;
  if (ev.type === 'host-start') {
    entry.status = 'running';
    for (const s of ev.services || []) entry.scan.rows.set(s.port, { plan: s, report: null });
  } else if (ev.type === 'service') {
    const row = entry.scan.rows.get(ev.service.port) || { plan: { name: ev.service.service, port: ev.service.port } };
    row.report = ev.service;
    entry.scan.rows.set(ev.service.port, row);
  } else if (ev.type === 'host-done') {
    entry.status = 'done';
    entry.report = entry.scan.report = ev.report;
    entry.scan.done = true;
    const n = est.entries.filter((e) => e.report).length;
    if (n === est.entries.length || n % 5 === 0) announce(`${n} of ${est.entries.length} hosts scanned.`);
  }
  renderEstate(est);
}

async function finishEstateStopped(est) {
  est.elapsed = (performance.now() - est.started) / 1000;
  try {
    const resp = await postJSON('api/estate/rollup', { targets: est.entries.length, hosts: est.entries.filter((e) => e.report).map((e) => e.report) });
    est.report = await resp.json();
  } catch { /* the partial table still renders without the summary */ }
  est.done = true;
  for (const e of est.entries) e.scan.done = true;
  $('report').hidden = false;
  renderEstate(est);
  announce('Estate scan stopped.');
  $('verdict-title').focus();
}

function renderEstate(est) {
  renderEstateVerdict(est);
  renderEstateRecs(est);
  renderEstateHosts(est);
}

function hostVerdictCounts(est) {
  const counts = {};
  const hosts = est.report ? est.report.hosts : est.entries.filter((e) => e.report).map((e) => e.report);
  for (const hr of hosts) counts[hr.verdict] = (counts[hr.verdict] || 0) + 1;
  return counts;
}

function renderEstateVerdict(est) {
  const rep = est.report;
  const total = est.entries.length;
  const doneN = est.entries.filter((e) => e.report).length;
  const counts = hostVerdictCounts(est);
  const live = !est.done && !rep;
  const verdict = rep ? rep.verdict : live ? 'running' : 'stopped';
  const headline = rep ? rep.headline : !doneN ? `Scanning ${total} ${plural(total, 'target')}…`
    : `So far: ${doneN} of ${total} hosts scanned, ${counts.not_ready || 0} not post-quantum.`;
  const labels = { not_ready: 'Not post-quantum', undetermined: "Couldn't determine", ready: 'Post-quantum' };
  const icons = { not_ready: '✕', undetermined: '?', ready: '✓' };

  const v = $('verdict');
  v.className = `verdict v-${verdict}`;
  v.replaceChildren(...[
    h('div', { class: 'verdict-top' },
      h('span', { class: `badge b-${verdict}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), VERDICT[verdict]),
      h('span', { class: 'target' }, `${total} ${plural(total, 'target')}`)),
    h('h2', { id: 'verdict-title', tabindex: '-1' }, headline),
    est.stopped ? h('p', { class: 'stopped' }, `Stopped: ${doneN} of ${total} ${plural(total, 'host')} finished. Hosts that didn't finish aren't included in the summary or recommendations.`) : null,
    countChips(counts, Object.keys(HOST_ORDER), labels, icons, est.filter, (c) => {
      est.filter = est.filter === c ? null : c;
      renderEstateHosts(est);
      renderEstateVerdict(est);
      const again = $('verdict').querySelector(`.count[data-key="${c}"]`);
      if (again) again.focus();
    }, 'Filter hosts by result'),
    rep ? h('p', { class: 'estate-services' }, estateServiceLine(rep.summary)) : null,
    live ? progressBar(est, total, 'Hosts scanned') : null,
    trustPanel((rep && rep.controls) || est.controls, (rep && rep.path) || est.path),
    !live ? h('div', { class: 'meta-row' },
      h('span', { class: 'meta' }, stamp(est.startedAt, est.elapsed)),
      h('span', { class: 'actions' },
        h('button', { type: 'button', class: 'link', onclick: () => downloadJSON(est.report || { partial: true, hosts: est.entries.filter((e) => e.report).map((e) => e.report) }, `pqscan-estate-${est.startedAt.toISOString().slice(0, 10)}.json`) }, 'Download JSON'),
        est.report ? h('button', { type: 'button', class: 'link', title: 'CycloneDX 1.6 cryptography bill of materials', onclick: (e) => downloadCBOM('estate', est.report, `pqscan-estate-${est.startedAt.toISOString().slice(0, 10)}-cbom.cdx.json`, e.currentTarget) }, 'Download CBOM') : null,
        h('button', { type: 'button', class: 'link', onclick: () => window.print() }, 'Print'))) : null,
  ].filter(Boolean));
  if (live) tickProgress(est, doneN, total);
}

function estateServiceLine(s) {
  const parts = [
    [s.services.pq, 'post-quantum'], [s.services.classical, 'classical'], [s.plaintext, 'plaintext'],
    [s.services.closed, 'closed'], [s.services.noResponse, 'no response'],
  ].filter(([n]) => n).map(([n, l]) => `${n} ${l}`);
  return parts.length ? `Services across the estate: ${parts.join(' · ')}.` : '';
}

function renderEstateRecs(est) {
  const sec = $('recs');
  if (!est.report) { sec.hidden = true; return; }
  sec.hidden = false;
  recsSection(sec, est.report.recommendations || [], {
    note: 'across the estate',
    emptyText: est.report.summary.hostsReady || est.report.summary.hostsNotReady
      ? 'Nothing to change across the assessed hosts.' : 'No recommendations: no exposed service could be assessed.',
    label: (key) => key.replace(/:(\d+)$/, ' $1'),
    onTarget: (key) => {
      const m = String(key).match(/^(.*) (\S+):(\d+)$/);
      if (!m) return;
      const port = Number(m[3]);
      const entry = est.entries.find((e) => e.host === m[1] && e.scan.rows.has(port));
      if (!entry) return;
      est.filter = null;
      est.expanded.add(entry.index);
      entry.scan.expanded.add(port);
      const row = entry.scan.rows.get(port);
      if (row.report) entry.scan.showCollapsed[category(row.report)] = true;
      renderEstateVerdict(est);
      renderEstateHosts(est);
      focusRow(`${entry.scan.idPrefix}svc-${port}`);
    },
  });
}

function needsAction(hr) {
  return (hr.services || []).filter((s) => SEVERITY[category(s)] <= 2)
    .map((s) => `${s.service} ${s.port} (${keyExchange(s)})`);
}

function renderEstateHosts(est) {
  const entries = est.entries.filter((e) => !est.filter || (e.report && e.report.verdict === est.filter));
  entries.sort((a, b) => {
    const ra = a.report ? HOST_ORDER[a.report.verdict] : 3;
    const rb = b.report ? HOST_ORDER[b.report.verdict] : 3;
    return ra - rb || a.index - b.index;
  });
  $('services').replaceChildren(
    h('div', { class: 'section-head' },
      h('h2', { id: 'services-title' }, 'Hosts'),
      est.filter ? h('span', { class: 'section-note' }, 'Filtered · ',
        h('button', { type: 'button', class: 'link', onclick: () => { est.filter = null; renderEstate(est); } }, 'Show all')) : null),
    h('div', { class: 'svc-table hosts-table', role: 'list' },
      h('div', { class: 'svc-head host-head', 'aria-hidden': 'true' },
        h('span', null, 'Host'), h('span', null, 'Result'), h('span', null, 'Exposed'), h('span', null, 'Needs action')),
      entries.map((e) => hostRow(est, e))));
}

function hostRow(est, e) {
  const id = `host-${e.index}`;
  const label = e.target.port ? (e.host.includes(':') ? `[${e.host}]:${e.target.port}` : `${e.host}:${e.target.port}`) : e.host;
  if (!e.report) {
    const scanned = resolved(e.scan).length;
    const status = e.status === 'running'
      ? `${est.done ? 'Stopped at' : 'Scanning…'} ${scanned}/${e.scan.rows.size}`
      : est.done ? 'Not scanned' : 'Queued';
    return h('div', { class: 'row-wrap', role: 'listitem' },
      h('div', { class: 'row host-row s-pending' },
        h('span', { class: 'c-name' }, h('span', { class: 'chev placeholder', 'aria-hidden': 'true' }), label),
        h('span', { class: 'c-status' }, h('span', { class: 'pill s-pending' }, e.status === 'running' && !est.done ? h('span', { class: 'spinner', 'aria-hidden': 'true' }) : null, status)),
        h('span', { class: 'c-exposed' }, '—'), h('span', { class: 'c-kex' }, '')));
  }
  const hr = e.report;
  const open = est.expanded.has(e.index) || !!est.printing;
  const exposed = hr.counts.pq + hr.counts.classical + (hr.services || []).filter((s) => s.errorKind === 'no_starttls').length;
  const need = needsAction(hr);
  const cls = { ready: 'pq', not_ready: 'classical', undetermined: 'error' }[hr.verdict];
  const btn = h('button', {
    type: 'button', class: `row host-row s-${cls}`, id, 'aria-expanded': String(open), 'aria-controls': `${id}-detail`,
    onclick: () => {
      if (est.expanded.has(e.index)) est.expanded.delete(e.index); else est.expanded.add(e.index);
      renderEstateHosts(est);
      const again = $(id);
      if (again) again.focus();
    },
  },
  h('span', { class: 'c-name' }, h('span', { class: 'chev', 'aria-hidden': 'true' }), label),
  h('span', { class: 'c-status' }, h('span', { class: `pill s-${cls}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, { pq: '✓', classical: '✕', error: '?' }[cls]), VERDICT[hr.verdict])),
  h('span', { class: 'c-exposed' }, h('span', { class: 'sr-only' }, 'exposed services: '), String(exposed)),
  h('span', { class: 'c-kex' }, need.length ? need.join(' · ') : '—'));
  e.scan.printing = est.printing;
  return h('div', { class: 'row-wrap', role: 'listitem' }, btn,
    open ? h('div', { class: 'detail host-detail', id: `${id}-detail` },
      h('p', { class: 'detail-headline' }, hr.headline),
      servicesTable(e.scan)) : null);
}

// ---------- URL state (single host only; target lists stay out of URLs) ----------

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
  syncForm();
  if (p.get('protocol')) $('protocol').value = p.get('protocol');
  if (p.get('services')) {
    const want = p.get('services').split(',');
    const valid = allNames().filter((n) => want.includes(n));
    if (valid.length) { st.selected = new Set(valid); updateScope(); }
  }
  return true;
}

// ---------- boot ----------

export function initHosts(catalog) {
  st.catalog = catalog;
  st.selected = new Set(allNames());
  buildScope();
  $('scan-form').addEventListener('submit', (e) => {
    e.preventDefault();
    if (running()) return;
    showFormError('form-error', '');
    if (st.mode === 'estate') startEstate(); else startHostScan();
  });
  $('stop').addEventListener('click', () => {
    const s = st.estate && !st.estate.done ? st.estate : st.scan && !st.scan.done ? st.scan : null;
    if (!s) return;
    s.stopped = true;
    s.ctrl.abort();
  });
  $('host').addEventListener('input', syncForm);
  for (const r of document.querySelectorAll('input[name="mode"]')) {
    r.addEventListener('change', () => { st.mode = r.value; syncForm(); });
  }
  onPrint((on) => {
    if (st.scan) { st.scan.printing = on; renderHostServices(st.scan); }
    if (st.estate) { st.estate.printing = on; renderEstateHosts(st.estate); }
  });
  if (initFromURL()) startHostScan();
}
