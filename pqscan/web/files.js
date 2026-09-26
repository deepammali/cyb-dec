// Files view: inspect data at rest. Files are uploaded to this pqscan server,
// parsed in memory there, and never stored.
import {
  h, $, plural, reducedMotion, VERDICT, PRIORITY, downloadJSON, downloadCBOM, announce, showFormError, stamp,
  recsSection, openRec, onPrint,
} from './core.js';

export const CLASS = {
  exposed: ['Exposed', '✕', 'Encrypted to a classical public key: a copy taken today can be decrypted later.'],
  weak: ['Weak', '✕', 'Protection that is broken or deprecated today.'],
  inventory: ['Classical key', '~', 'Classical keys, certificates, and signatures to migrate.'],
  symmetric: ['Symmetric only', '✓', 'Protected only by a symmetric key or password.'],
  pq: ['Post-quantum', '✓', 'Key established with ML-KEM, or post-quantum keys and signatures.'],
};
export const ORDER = ['exposed', 'weak', 'inventory', 'symmetric', 'pq'];
const FCONF = { confirmed: 'Confirmed', high: 'High', low: 'Low' };

const st = { maxUpload: 0, files: [], xhr: null, result: null, filter: null, expanded: new Set(), printing: false, startedAt: null, elapsed: 0 };

export function size(b) {
  const f = (n, unit) => `${n.toFixed(1).replace(/\.0$/, '')} ${unit}`;
  if (b >= 1 << 30) return f(b / (1 << 30), 'GB');
  if (b >= 1 << 20) return f(b / (1 << 20), 'MB');
  if (b >= 1 << 10) return f(b / (1 << 10), 'KB');
  return `${b} B`;
}
const total = () => st.files.reduce((n, f) => n + f.file.size, 0);

// ---------- selection ----------

function addFiles(list) {
  const seen = new Set(st.files.map((f) => f.path));
  for (const f of list) {
    if (!seen.has(f.path)) { st.files.push(f); seen.add(f.path); }
  }
  renderSelection();
}

// Folder drops arrive as FileSystemEntry trees; walk them for relative paths.
function walkEntry(entry, prefix) {
  if (entry.isFile) return new Promise((res) => entry.file((f) => res([{ file: f, path: prefix + f.name }]), () => res([])));
  if (!entry.isDirectory) return Promise.resolve([]);
  const reader = entry.createReader();
  const all = [];
  return new Promise((res) => {
    const next = () => reader.readEntries(async (batch) => {
      if (!batch.length) { res((await Promise.all(all)).flat()); return; }
      for (const e of batch) all.push(walkEntry(e, `${prefix}${entry.name}/`));
      next();
    }, () => res([]));
    next();
  });
}

async function onDrop(e) {
  e.preventDefault();
  $('dropzone').classList.remove('over');
  if (st.xhr) return;
  const items = [...(e.dataTransfer.items || [])].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (items.length) addFiles((await Promise.all(items.map((en) => walkEntry(en, '')))).flat());
  else addFiles([...e.dataTransfer.files].map((f) => ({ file: f, path: f.name })));
}

function renderSelection() {
  const n = st.files.length;
  const bytes = total();
  const over = st.maxUpload && bytes > st.maxUpload;
  $('files-go').disabled = !n || over;
  $('files-clear').hidden = !n;
  const box = $('selection');
  if (!n) { box.replaceChildren(h('span', { class: 'muted' }, 'Nothing selected yet.')); showFormError('files-error', ''); return; }
  const names = st.files.slice(0, 4).map((f) => f.path).join(', ');
  box.replaceChildren(
    h('strong', null, `${n} ${plural(n, 'file')} · ${size(bytes)}`),
    h('span', { class: 'selection-names' }, n > 4 ? `${names}, and ${n - 4} more` : names));
  showFormError('files-error', over ? `The selection is ${size(bytes)}; this server accepts ${size(st.maxUpload)} per inspection (--max-upload). Inspect fewer files at once.` : '');
}

// ---------- upload ----------

function setRunning(on) {
  $('files-go').hidden = on;
  $('files-stop').hidden = !on;
  $('files-clear').disabled = on;
  for (const id of ['file-pick', 'dir-pick']) $(id).disabled = on;
  if (on) $('files-stop').focus();
}

function progress(text, fraction) {
  const bar = $('files-progress');
  bar.hidden = false;
  bar.querySelector('.fill').style.width = `${Math.round(100 * fraction)}%`;
  bar.querySelector('.bar').setAttribute('aria-valuenow', String(Math.round(100 * fraction)));
  bar.querySelector('.progress-text').textContent = text;
}

function inspectFiles() {
  if (!st.files.length || st.xhr) return;
  showFormError('files-error', '');
  const fd = new FormData();
  for (const f of st.files) fd.append('file', f.file, f.path);
  const xhr = st.xhr = new XMLHttpRequest();
  const started = performance.now();
  st.startedAt = new Date();
  xhr.open('POST', 'api/inspect');
  xhr.responseType = 'json';
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) progress(`Uploading ${size(e.loaded)} of ${size(e.total)}`, e.loaded / e.total); };
  xhr.upload.onload = () => progress('Reading headers…', 1);
  const done = () => { st.xhr = null; setRunning(false); $('files-progress').hidden = true; };
  xhr.onload = () => {
    done();
    if (xhr.status !== 200) {
      showFormError('files-error', (xhr.response && xhr.response.error) || `Inspection failed (${xhr.status}).`);
      return;
    }
    st.elapsed = (performance.now() - started) / 1000;
    st.result = xhr.response;
    st.filter = null;
    st.expanded = new Set();
    $('files-report').hidden = false;
    render();
    announce(`Inspection finished. ${st.result.headline}`);
    $('files-verdict-title').focus();
  };
  xhr.onerror = () => { done(); showFormError('files-error', 'The upload failed. Check that the pqscan server is still running.'); };
  xhr.onabort = () => { done(); showFormError('files-error', 'Stopped. Nothing was kept on the server.'); };
  setRunning(true);
  progress('Uploading…', 0);
  xhr.send(fd);
  announce(`Inspecting ${st.files.length} ${plural(st.files.length, 'file')}.`);
}

// ---------- report ----------

function render() {
  renderVerdict();
  renderFindings();
  renderRecs();
  renderSkipped();
}

function renderVerdict() {
  const r = st.result;
  const counts = r.counts || {};
  const v = $('files-verdict');
  v.className = `verdict v-${r.verdict}`;
  v.replaceChildren(
    h('div', { class: 'verdict-top' },
      h('span', { class: `badge b-${r.verdict}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), VERDICT[r.verdict]),
      h('span', { class: 'target', title: 'Items include archive members and mail parts, which are opened and read too.' },
        `${r.roots.length} ${plural(r.roots.length, 'file')} · ${r.files} ${plural(r.files, 'item')} read · ${size(r.bytes)}`)),
    h('h2', { id: 'files-verdict-title', tabindex: '-1' }, r.headline),
    h('div', { class: 'counts', role: 'group', 'aria-label': 'Filter findings by result' },
      ORDER.filter((c) => counts[c]).map((c) => h('button', {
        type: 'button', class: `count k-${c}`, 'aria-pressed': String(st.filter === c), 'data-key': c, title: CLASS[c][2],
        onclick: () => {
          st.filter = st.filter === c ? null : c;
          renderVerdict();
          renderFindings();
          const again = $('files-verdict').querySelector(`.count[data-key="${c}"]`);
          if (again) again.focus();
        },
      }, h('span', { class: 'icon', 'aria-hidden': 'true' }, CLASS[c][1]), `${CLASS[c][0]} ${counts[c]}`))),
    h('p', { class: 'privacy-line' }, 'Headers only: nothing was decrypted, no password was used, and the uploaded files were not stored.'),
    h('div', { class: 'meta-row' },
      h('span', { class: 'meta' }, stamp(st.startedAt, st.elapsed)),
      h('span', { class: 'actions' },
        h('button', { type: 'button', class: 'link', onclick: () => downloadJSON(r, `pqscan-files-${st.startedAt.toISOString().slice(0, 10)}.json`) }, 'Download JSON'),
        h('button', { type: 'button', class: 'link', title: 'CycloneDX 1.6 cryptography bill of materials', onclick: (e) => downloadCBOM('files', r, `pqscan-files-${st.startedAt.toISOString().slice(0, 10)}-cbom.cdx.json`, e.currentTarget) }, 'Download CBOM'),
        h('button', { type: 'button', class: 'link', onclick: () => window.print() }, 'Print'))));
}

function renderFindings() {
  const r = st.result;
  const rows = r.findings.map((f, i) => ({ f, i })).filter(({ f }) => !st.filter || f.class === st.filter);
  $('files-list').replaceChildren(
    h('div', { class: 'section-head' },
      h('h2', { id: 'files-list-title' }, 'Findings'),
      st.filter ? h('span', { class: 'section-note' }, `Showing ${CLASS[st.filter][0].toLowerCase()} only · `,
        h('button', { type: 'button', class: 'link', onclick: () => { st.filter = null; render(); } }, 'Show all')) : null),
    r.findings.length ? h('div', { class: 'svc-table find-table', role: 'list' },
      h('div', { class: 'svc-head find-head', 'aria-hidden': 'true' },
        h('span', null, 'Result'), h('span', null, 'Format'), h('span', null, 'Protection'), h('span', null, 'Where')),
      rows.map(({ f, i }) => findingRow(f, i)))
      : h('p', { class: 'empty' }, 'No encrypted data, keys, or certificates were found in these files.'));
}

function findingRow(f, i) {
  const id = `f-${i}`;
  const open = st.expanded.has(i) || st.printing;
  const [label, icon] = CLASS[f.class];
  const btn = h('button', {
    type: 'button', class: `row find-row k-${f.class}`, id, 'aria-expanded': String(open), 'aria-controls': `${id}-detail`,
    onclick: () => {
      if (st.expanded.has(i)) st.expanded.delete(i); else st.expanded.add(i);
      renderFindings();
      const again = $(id);
      if (again) again.focus();
    },
  },
  h('span', { class: 'c-status' }, h('span', { class: 'chev', 'aria-hidden': 'true' }), h('span', { class: `pill k-${f.class}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, icon), label)),
  h('span', { class: 'c-format' }, f.format, f.count > 1 ? h('span', { class: 'tag' }, `×${f.count}`) : null),
  h('span', { class: 'c-kex' }, f.protection || '—'),
  h('span', { class: 'c-path' }, f.path));
  return h('div', { class: 'row-wrap', role: 'listitem' }, btn, open ? findingDetail(f, `${id}-detail`) : null);
}

function findingDetail(f, id) {
  const recs = (st.result.recommendations || []).filter((rec) => rec.services.includes(f.path));
  return h('div', { class: 'detail', id },
    h('p', { class: 'detail-headline' }, f.headline),
    h('section', { class: 'evidence' },
      h('h3', null, 'Evidence', h('span', { class: `conf conf-${f.confidence === 'confirmed' ? 'confirmed' : f.confidence === 'low' ? 'low' : 'high'}` }, FCONF[f.confidence] || f.confidence)),
      h('dl', { class: 'facts' },
        h('div', null, h('dt', null, 'Where'), h('dd', null, f.path)),
        h('div', null, h('dt', null, 'Format'), h('dd', null, f.format)),
        (f.evidence || []).map((e) => h('div', null, h('dt', null, e.label), h('dd', null, e.value)))),
      f.limits ? h('p', { class: 'limits' }, h('strong', null, 'Limits. '), f.limits) : null),
    recs.length ? h('section', { class: 'applies' },
      h('h3', null, 'What to do'),
      h('ul', null, recs.map((rec) => h('li', null,
        h('button', { type: 'button', class: 'link', onclick: () => openRec('files-recs', rec.id) }, rec.title),
        h('span', { class: `prio prio-${rec.priority}` }, PRIORITY[rec.priority][0]))))) : null);
}

const shortPath = (p) => {
  const parts = p.split(/[/\\!]/);
  return parts.length > 2 ? `…/${parts.slice(-2).join('/')}` : p;
};

function renderRecs() {
  const r = st.result;
  recsSection($('files-recs'), r.recommendations || [], {
    note: 'from these files',
    emptyText: r.findings.length ? 'Nothing to change: no encrypted data here is exposed and nothing needs hardening.' : 'No recommendations: nothing cryptographic was found.',
    label: shortPath,
    onTarget: (path) => {
      const i = r.findings.findIndex((f) => f.path === path);
      if (i < 0) return;
      st.filter = null;
      st.expanded.add(i);
      renderVerdict();
      renderFindings();
      const btn = $(`f-${i}`);
      if (btn) { btn.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' }); btn.focus({ preventScroll: true }); }
    },
  });
}

function renderSkipped() {
  const r = st.result;
  const box = $('files-skipped');
  box.hidden = !r.skippedTotal;
  if (!r.skippedTotal) return;
  box.replaceChildren(
    h('summary', null, `${r.skippedTotal} ${plural(r.skippedTotal, 'item')} not fully read`),
    h('ul', null, (r.skipped || []).map((s) => h('li', null, h('code', null, s.path), ` — ${s.reason}`))),
    r.skippedTotal > (r.skipped || []).length ? h('p', { class: 'muted' }, `…and ${r.skippedTotal - r.skipped.length} more.`) : null);
}

// ---------- boot ----------

export function initFiles(catalog) {
  st.maxUpload = catalog.maxUpload || 0;
  $('files-limit').textContent = st.maxUpload ? `Up to ${size(st.maxUpload)} per inspection.` : '';
  const dz = $('dropzone');
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('over'));
  dz.addEventListener('drop', onDrop);
  for (const id of ['file-pick', 'dir-pick']) {
    $(id).addEventListener('change', (e) => {
      addFiles([...e.target.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
      e.target.value = '';
    });
  }
  $('files-clear').addEventListener('click', () => { st.files = []; renderSelection(); });
  $('files-form').addEventListener('submit', (e) => { e.preventDefault(); inspectFiles(); });
  $('files-stop').addEventListener('click', () => { if (st.xhr) st.xhr.abort(); });
  onPrint((on) => { st.printing = on; if (st.result) renderFindings(); });
  renderSelection();
}
