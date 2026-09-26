// Capture view: analyze packet captures for how each connection set up its keys.
import {
  h, $, plural, reducedMotion, VERDICT, PRIORITY, downloadJSON, announce, showFormError, stamp,
  recsSection, openRec, onPrint,
} from './core.js';
import { CLASS, size } from './files.js';

const NCLASS = {
  plaintext: ['Plaintext', '✕', 'No encryption: readable today.'],
  classical: ['Classical', '✕', 'Classical key exchange: recordable now, decryptable later.'],
  unknown: ['Incomplete', '?', "The capture doesn't show enough of the handshake to decide."],
  pq: ['Post-quantum', '✓', 'Keys established with ML-KEM or another post-quantum method.'],
};
const NORDER = ['plaintext', 'classical', 'unknown', 'pq'];

const st = { maxUpload: 0, captures: [], keylog: null, xhr: null, result: null, filter: null, expanded: new Set(), printing: false, startedAt: null, elapsed: 0 };

const groupLabel = (g) => `${g.protocol} ${g.server}${g.serverName ? ` (${g.serverName})` : ''}`;
// Recommendations name clients only where the client was the reason.
const clientLabel = (g) => (g.outcome === 'client-classical' ? `${g.clientIp} → ${g.serverName || g.server}` : null);

// ---------- selection ----------

function classify(files) {
  for (const f of files) {
    const n = f.name.toLowerCase();
    if (/\.(pcap|pcapng|cap|dmp)$/.test(n)) st.captures.push(f);
    else if (/key|\.log$|\.txt$/.test(n)) st.keylog = f;
    else st.captures.push(f);
  }
  renderSelection();
}

function renderSelection() {
  const bytes = st.captures.reduce((n, f) => n + f.size, 0) + (st.keylog ? st.keylog.size : 0);
  const over = st.maxUpload && bytes > st.maxUpload;
  $('cap-go').disabled = !st.captures.length || over;
  $('cap-clear').hidden = !st.captures.length && !st.keylog;
  const parts = [];
  if (st.captures.length) parts.push(h('strong', null, `${st.captures.length} ${plural(st.captures.length, 'capture')} · ${size(bytes)}`), h('span', { class: 'selection-names' }, st.captures.map((f) => f.name).join(', ')));
  else parts.push(h('span', { class: 'muted' }, 'No capture selected yet.'));
  if (st.keylog) parts.push(h('span', { class: 'selection-names' }, `Key log: ${st.keylog.name}`));
  $('cap-selection').replaceChildren(...parts);
  showFormError('cap-error', over ? `The selection is ${size(bytes)}; this server accepts ${size(st.maxUpload)} per upload (--max-upload).` : '');
}

// ---------- upload ----------

function setRunning(on) {
  $('cap-go').hidden = on;
  $('cap-stop').hidden = !on;
  $('cap-clear').disabled = on;
  for (const id of ['cap-pick', 'keylog-pick']) $(id).disabled = on;
  if (on) $('cap-stop').focus();
}

function progress(text, fraction) {
  const bar = $('cap-progress');
  bar.hidden = false;
  bar.querySelector('.fill').style.width = `${Math.round(100 * fraction)}%`;
  bar.querySelector('.bar').setAttribute('aria-valuenow', String(Math.round(100 * fraction)));
  bar.querySelector('.progress-text').textContent = text;
}

function analyze() {
  if (!st.captures.length || st.xhr) return;
  showFormError('cap-error', '');
  const fd = new FormData();
  if (st.keylog) fd.append('keylog', st.keylog, st.keylog.name);
  for (const f of st.captures) fd.append('capture', f, f.name);
  const xhr = st.xhr = new XMLHttpRequest();
  const started = performance.now();
  st.startedAt = new Date();
  xhr.open('POST', 'api/observe');
  xhr.responseType = 'json';
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) progress(`Uploading ${size(e.loaded)} of ${size(e.total)}`, e.loaded / e.total); };
  xhr.upload.onload = () => progress('Analyzing handshakes…', 1);
  const done = () => { st.xhr = null; setRunning(false); $('cap-progress').hidden = true; };
  xhr.onload = () => {
    done();
    if (xhr.status !== 200) {
      showFormError('cap-error', (xhr.response && xhr.response.error) || `Analysis failed (${xhr.status}).`);
      return;
    }
    st.elapsed = (performance.now() - started) / 1000;
    st.result = xhr.response;
    st.filter = null;
    st.expanded = new Set();
    $('cap-report').hidden = false;
    render();
    announce(`Analysis finished. ${st.result.headline}`);
    $('cap-verdict-title').focus();
  };
  xhr.onerror = () => { done(); showFormError('cap-error', 'The upload failed. Check that the pqscan server is still running.'); };
  xhr.onabort = () => { done(); showFormError('cap-error', 'Stopped. Nothing was kept on the server.'); };
  setRunning(true);
  progress('Uploading…', 0);
  xhr.send(fd);
}

// ---------- report ----------

function render() {
  renderVerdict();
  renderConnections();
  renderArtifacts();
  renderRecs();
}

function renderVerdict() {
  const r = st.result;
  const counts = r.counts || {};
  const k = r.keylog;
  const v = $('cap-verdict');
  v.className = `verdict v-${r.verdict}`;
  v.replaceChildren(...[
    h('div', { class: 'verdict-top' },
      h('span', { class: `badge b-${r.verdict}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), VERDICT[r.verdict]),
      h('span', { class: 'target' }, `${r.connections} ${plural(r.connections, 'connection')} · ${r.packets} packets`)),
    h('h2', { id: 'cap-verdict-title', tabindex: '-1' }, r.headline),
    h('div', { class: 'counts', role: 'group', 'aria-label': 'Filter connections by result' },
      NORDER.filter((c) => counts[c]).map((c) => h('button', {
        type: 'button', class: `count n-${c}`, 'aria-pressed': String(st.filter === c), 'data-key': c, title: NCLASS[c][2],
        onclick: () => {
          st.filter = st.filter === c ? null : c;
          renderVerdict();
          renderConnections();
          const again = $('cap-verdict').querySelector(`.count[data-key="${c}"]`);
          if (again) again.focus();
        },
      }, h('span', { class: 'icon', 'aria-hidden': 'true' }, NCLASS[c][1]), `${NCLASS[c][0]} ${counts[c]}`))),
    k ? h('p', { class: 'privacy-line' }, `Key log: ${k.sessions} TLS 1.3 ${plural(k.sessions, 'session')}, ${k.decrypted} ${plural(k.decrypted, 'connection')} decrypted${k.notDecrypted ? `, ${k.notDecrypted} not` : ''}${k.tls12Lines ? `; ${k.tls12Lines} TLS 1.2 ${plural(k.tls12Lines, 'line')} ignored (TLS 1.3 only)` : ''}.`) : null,
    r.unanalyzed ? h('p', { class: 'privacy-line' }, `${r.unanalyzed} TCP ${plural(r.unanalyzed, 'connection')} had no recognizable handshake or protocol (for example, captured after the handshake).`) : null,
    h('div', { class: 'meta-row' },
      h('span', { class: 'meta' }, stamp(st.startedAt, st.elapsed)),
      h('span', { class: 'actions' },
        h('button', { type: 'button', class: 'link', onclick: () => downloadJSON(r, `pqscan-capture-${st.startedAt.toISOString().slice(0, 10)}.json`) }, 'Download JSON'),
        h('button', { type: 'button', class: 'link', onclick: () => window.print() }, 'Print'))),
  ].filter(Boolean));
}

function renderConnections() {
  const r = st.result;
  const rows = (r.groups || []).map((g, i) => ({ g, i })).filter(({ g }) => !st.filter || g.class === st.filter);
  $('cap-list').replaceChildren(
    h('div', { class: 'section-head' },
      h('h2', { id: 'cap-list-title' }, 'Connections'),
      st.filter ? h('span', { class: 'section-note' }, `Showing ${NCLASS[st.filter][0].toLowerCase()} only · `,
        h('button', { type: 'button', class: 'link', onclick: () => { st.filter = null; render(); } }, 'Show all')) : null),
    (r.groups || []).length ? h('div', { class: 'svc-table conn-table', role: 'list' },
      h('div', { class: 'svc-head conn-head', 'aria-hidden': 'true' },
        h('span', null, 'Result'), h('span', null, 'Protocol'), h('span', null, 'Client → server'), h('span', null, 'Key exchange'), h('span', null, 'Count')),
      rows.map(({ g, i }) => connRow(g, i)))
      : h('p', { class: 'empty' }, 'No TLS, QUIC, SSH, IKEv2, WireGuard, or plaintext application connections were found.'));
}

function connRow(g, i) {
  const id = `c-${i}`;
  const open = st.expanded.has(i) || st.printing;
  const [label, icon] = NCLASS[g.class];
  const btn = h('button', {
    type: 'button', class: `row conn-row n-${g.class}`, id, 'aria-expanded': String(open), 'aria-controls': `${id}-detail`,
    onclick: () => {
      if (st.expanded.has(i)) st.expanded.delete(i); else st.expanded.add(i);
      renderConnections();
      const again = $(id);
      if (again) again.focus();
    },
  },
  h('span', { class: 'c-status' }, h('span', { class: 'chev', 'aria-hidden': 'true' }), h('span', { class: `pill n-${g.class}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, icon), label)),
  h('span', { class: 'c-format' }, g.protocol, (g.findings || []).length ? h('span', { class: 'tag' }, `${g.findings.length} in traffic`) : null),
  h('span', { class: 'c-path' }, `${g.clientIp} → ${g.server}`, g.serverName ? h('span', { class: 'muted' }, ` ${g.serverName}`) : null),
  h('span', { class: 'c-kex' }, g.keyExchange || '—'),
  h('span', { class: 'c-count' }, h('span', { class: 'sr-only' }, 'connections: '), `×${g.count}`));
  return h('div', { class: 'row-wrap', role: 'listitem' }, btn, open ? connDetail(g, `${id}-detail`) : null);
}

function connDetail(g, id) {
  const keys = new Set([groupLabel(g), clientLabel(g), ...(g.findings || []).map((f) => f.path)].filter(Boolean));
  const recs = (st.result.recommendations || []).filter((rec) => rec.services.some((s) => keys.has(s)));
  return h('div', { class: 'detail', id },
    h('p', { class: 'detail-headline' }, g.headline),
    h('section', { class: 'evidence' },
      h('h3', null, 'Evidence'),
      h('dl', { class: 'facts' },
        h('div', null, h('dt', null, 'Client'), h('dd', null, g.count > 1 ? `${g.client} and ${g.count - 1} more ${plural(g.count - 1, 'connection')}` : g.client)),
        h('div', null, h('dt', null, 'Server'), h('dd', null, g.server)),
        (g.evidence || []).map((e) => h('div', null, h('dt', null, e.label), h('dd', null, e.value))),
        g.decryption && g.decryption !== 'decrypted' ? h('div', null, h('dt', null, 'Key log'), h('dd', null, g.decryption)) : null),
      g.limits ? h('p', { class: 'limits' }, h('strong', null, 'Limits. '), g.limits) : null),
    (g.findings || []).length ? h('section', { class: 'in-traffic' },
      h('h3', null, 'Found in the traffic'),
      h('ul', { class: 'groups' }, g.findings.map((f) => h('li', { class: `o-${f.class === 'pq' || f.class === 'symmetric' ? 'pq' : 'classical'}` },
        h('span', { class: 'icon', 'aria-hidden': 'true' }, CLASS[f.class][1]),
        h('span', null, h('strong', null, `${CLASS[f.class][0]}: ${f.format}`), ` (${f.protection}). ${f.headline}`))))) : null,
    recs.length ? h('section', { class: 'applies' },
      h('h3', null, 'What to do'),
      h('ul', null, recs.map((rec) => h('li', null,
        h('button', { type: 'button', class: 'link', onclick: () => openRec('cap-recs', rec.id) }, rec.title),
        h('span', { class: `prio prio-${rec.priority}` }, PRIORITY[rec.priority][0]))))) : null);
}

function renderArtifacts() {
  const fs = st.result.findings || [];
  const sec = $('cap-artifacts');
  sec.hidden = !fs.length;
  if (!fs.length) return;
  sec.replaceChildren(
    h('div', { class: 'section-head' }, h('h2', null, 'Encrypted artifacts in the traffic'),
      h('span', { class: 'section-note' }, 'from plaintext connections and sessions opened with the key log')),
    h('div', { class: 'svc-table', role: 'list' }, fs.map((f) => h('div', { class: 'row-wrap', role: 'listitem' },
      h('div', { class: 'row find-row static' },
        h('span', { class: 'c-status' }, h('span', { class: `pill k-${f.class}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, CLASS[f.class][1]), CLASS[f.class][0])),
        h('span', { class: 'c-format' }, f.format),
        h('span', { class: 'c-kex' }, f.protection),
        h('span', { class: 'c-path' }, f.path))))));
}

function renderRecs() {
  const r = st.result;
  recsSection($('cap-recs'), r.recommendations || [], {
    note: 'from this capture',
    emptyText: r.connections ? 'Nothing to change: every captured connection used post-quantum key exchange.' : 'No recommendations: no connection could be assessed.',
    label: (key) => key.replace(/ \((client→server|server→client)\) /, ' ').replace(/^(\S+) [\d.:[\]a-f]+ → /, '$1 → '),
    onTarget: (key) => {
      const i = (r.groups || []).findIndex((g) => groupLabel(g) === key || clientLabel(g) === key || (g.findings || []).some((f) => f.path === key));
      if (i < 0) return;
      st.filter = null;
      st.expanded.add(i);
      renderVerdict();
      renderConnections();
      const btn = $(`c-${i}`);
      if (btn) { btn.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' }); btn.focus({ preventScroll: true }); }
    },
  });
}

// ---------- boot ----------

export function initCapture(catalog) {
  st.maxUpload = catalog.maxUpload || 0;
  $('cap-limit').textContent = st.maxUpload ? `Up to ${size(st.maxUpload)} per upload.` : '';
  const dz = $('cap-drop');
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('over'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('over'); if (!st.xhr) classify([...e.dataTransfer.files]); });
  $('cap-pick').addEventListener('change', (e) => { st.captures.push(...e.target.files); renderSelection(); e.target.value = ''; });
  $('keylog-pick').addEventListener('change', (e) => { st.keylog = e.target.files[0] || null; renderSelection(); e.target.value = ''; });
  $('cap-clear').addEventListener('click', () => { st.captures = []; st.keylog = null; renderSelection(); });
  $('cap-form').addEventListener('submit', (e) => { e.preventDefault(); analyze(); });
  $('cap-stop').addEventListener('click', () => { if (st.xhr) st.xhr.abort(); });
  onPrint((on) => { st.printing = on; if (st.result) renderConnections(); });
  renderSelection();
}
