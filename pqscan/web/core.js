// Shared building blocks for every pqscan view.

// Every string that reaches the page may come from a scanned server, an
// uploaded file, or a capture, so the DOM is built with text nodes only.
export function h(tag, props, ...children) {
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
export const $ = (id) => document.getElementById(id);
export const plural = (n, one, many) => (n === 1 ? one : many || one + 's');
export const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

export const PRIORITY = {
  now: ['Now', 'Exposed to harvest-now-decrypt-later, or plaintext.'],
  harden: ['Harden', 'Standards and compliance (NIST, CNSA 2.0).'],
  plan: ['Plan', 'Signatures and crypto agility.'],
};
export const VERDICT = {
  ready: 'Post-quantum', not_ready: 'Not post-quantum', undetermined: "Couldn't determine", running: 'Scanning', stopped: 'Stopped',
};
export const CONF = {
  confirmed: 'Confirmed', high: 'One check', partial: 'Some clients', inconsistent: 'Unverified', mixed: 'Mixed', low: 'Low',
};
const CHECK_ICON = { pq: '✓', pass: '✓', classical: '✕', fail: '✕', not_run: '–' };

export async function readNDJSON(resp, onLine) {
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

// postJSON sends a JSON body and throws the server's error message on failure.
export async function postJSON(url, body, signal) {
  const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({}));
    throw new Error(e.error || `Request failed (${resp.status}).`);
  }
  return resp;
}

// Clipboard API needs a secure context; internal http:// deployments fall back.
export async function copyText(text, btn, label) {
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

export function downloadJSON(data, name) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a = h('a', { href: url, download: name.replace(/[^a-z0-9._-]/gi, '_') });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function announce(msg) { $('announcer').textContent = msg; }

export function showFormError(id, msg) {
  const el = $(id);
  el.textContent = msg;
  el.hidden = !msg;
}

export function stamp(date, seconds) {
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC · ${seconds.toFixed(1)} s`;
}

// "How sure is this?": confidence, the checks behind it, the false-result
// question and answer, and the limits.
export function assessmentBlock(a) {
  if (!a || !a.summary) return null;
  return h('section', { class: `sure conf-box-${a.confidence}` },
    h('h3', null, 'How sure is this?', CONF[a.confidence] ? h('span', { class: `conf conf-${a.confidence}` }, CONF[a.confidence]) : null),
    h('p', null, a.summary),
    a.checks && a.checks.length ? h('ul', { class: 'checks' }, a.checks.map((c) => h('li', { class: `o-${c.outcome}` },
      h('span', { class: 'icon', 'aria-hidden': 'true' }, CHECK_ICON[c.outcome] || '?'),
      h('span', null, h('strong', null, `${c.name}. `), c.detail)))) : null,
    a.question ? h('p', { class: 'qa' }, h('strong', null, a.question), ' ', a.answer) : null,
    a.limits ? h('p', { class: 'limits' }, h('strong', null, 'Limits. '), a.limits) : null);
}

// Engine controls and network-path status, with details on demand.
export function trustPanel(controls, path) {
  const cs = controls || [];
  const passed = cs.filter((c) => c.pass).length;
  const ctlOK = cs.length > 0 && passed === cs.length;
  let pathClass = 't-na', pathText = 'Network path not verified';
  if (path && path.error) pathText = 'Network path check unavailable';
  else if (path && path.loopback) pathText = 'Network path: local reference only';
  else if (path && path.carried) { pathClass = 't-pass'; pathText = 'Network path carries ML-KEM'; }
  else if (path) { pathClass = 't-fail'; pathText = 'Network path strips ML-KEM'; }

  let pathDetail = 'Not verified. A middlebox that strips ML-KEM offers would make every server look classical. Start the scanner with --reference <a server known to support ML-KEM> to check.';
  if (path && path.error) pathDetail = `Reference ${path.reference} could not be checked: ${path.error}.`;
  else if (path) {
    pathDetail = `Reference ${path.reference}: ${path.detail}. ${path.loopback
      ? 'The reference is on this machine, so it verifies only targets on this machine; for anything else, use a known ML-KEM server reached the same way as your targets.'
      : path.carried ? 'ML-KEM offers reach servers from here.' : 'A known ML-KEM server read as classical, so classical results from this scanner may be false negatives.'}`;
  }
  return h('details', { class: 'trust' },
    h('summary', null,
      h('span', { class: `trust-item ${ctlOK ? 't-pass' : 't-fail'}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, ctlOK ? '✓' : '✕'), `Engine controls ${passed}/${cs.length} passed`),
      h('span', { class: `trust-item ${pathClass}` }, h('span', { class: 'icon', 'aria-hidden': 'true' }, pathClass === 't-pass' ? '✓' : pathClass === 't-fail' ? '✕' : '–'), pathText)),
    h('div', { class: 'trust-body' },
      h('p', null, 'Before every result is trusted, the engine probes local reference servers whose answers are known. A failed positive control would mean false negatives, and a failed negative control would mean false positives.'),
      h('ul', { class: 'checks' }, cs.map((c) => h('li', { class: c.pass ? 'o-pass' : 'o-fail' },
        h('span', { class: 'icon', 'aria-hidden': 'true' }, c.pass ? '✓' : '✕'),
        h('span', null, h('strong', null, c.name), ` expected ${c.expect}; got ${c.got}.`)))),
      h('p', null, h('strong', null, 'Network path. '), pathDetail)));
}

// Recommendations grouped Now / Harden / Plan. onTarget(key) jumps to what a
// recommendation names; label(key) turns a key into its chip text.
export function recsSection(container, recs, { emptyText, note, onTarget, label }) {
  const head = h('div', { class: 'section-head' },
    h('h2', { id: `${container.id}-title` }, 'Improve quantum resilience'),
    recs.length ? h('span', { class: 'section-note' }, `${recs.length} ${plural(recs.length, 'recommendation')}, ${note}`) : null);
  if (!recs.length) {
    container.replaceChildren(head, h('p', { class: 'empty' }, emptyText));
    return;
  }
  let n = 0;
  const groups = Object.keys(PRIORITY).filter((p) => recs.some((r) => r.priority === p)).map((p) =>
    h('div', { class: `rec-group p-${p}` },
      h('div', { class: 'rec-group-head' }, h('span', { class: `prio prio-${p}` }, PRIORITY[p][0]), h('span', { class: 'section-note' }, PRIORITY[p][1])),
      recs.filter((r) => r.priority === p).map((r) => { n++; return recCard(container.id, r, n, n === 1, onTarget, label); })));
  container.replaceChildren(head, ...groups);
}

function recCard(prefix, r, n, open, onTarget, label) {
  return h('details', { class: 'rec', id: `${prefix}-${r.id}`, open },
    h('summary', null,
      h('span', { class: 'rec-num' }, String(n)),
      h('span', { class: 'rec-title' }, r.title),
      h('span', { class: 'rec-svcs' }, (r.services || []).map((key) => h('button', {
        type: 'button', class: 'svc-link', onclick: (e) => { e.preventDefault(); e.stopPropagation(); onTarget(key); },
      }, label(key))))),
    h('div', { class: 'rec-body' },
      h('p', null, r.why),
      r.steps && r.steps.length ? h('ol', { class: 'steps' }, r.steps.map((s) => h('li', null, s))) : null,
      (r.snippets || []).map((s) => h('div', { class: 'snippet' },
        h('div', { class: 'snippet-head' }, h('span', null, s.label),
          h('button', { type: 'button', class: 'link', onclick: (e) => copyText(s.code, e.currentTarget, 'Copy') }, 'Copy')),
        h('pre', null, h('code', null, s.code)))),
      r.refs && r.refs.length ? h('p', { class: 'refs' }, 'References: ', r.refs.map((ref, i) => [i ? ' · ' : '', h('a', { href: ref.url, rel: 'noreferrer' }, ref.label)])) : null));
}

export function openRec(containerId, id) {
  const d = $(`${containerId}-${id}`);
  if (!d) return;
  d.open = true;
  d.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' });
  d.querySelector('summary').focus({ preventScroll: true });
}

// Print hooks: views register how to expand themselves for the printed report.
const printHooks = [];
export function onPrint(fn) { printHooks.push(fn); }
let printOpened = [];
addEventListener('beforeprint', () => {
  printHooks.forEach((fn) => fn(true));
  printOpened = [...document.querySelectorAll('details:not([open])')];
  printOpened.forEach((d) => { d.open = true; });
});
addEventListener('afterprint', () => {
  printOpened.forEach((d) => { d.open = false; });
  printHooks.forEach((fn) => fn(false));
});
