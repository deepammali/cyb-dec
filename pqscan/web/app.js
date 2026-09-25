'use strict';

const form = document.getElementById('scan-form');
const hostInput = document.getElementById('host');
const goBtn = document.getElementById('go');
const statusEl = document.getElementById('status');
const resultsEl = document.getElementById('results');
const svcAllBox = document.getElementById('svc-all');
const svcSummary = document.getElementById('svc-summary');

let lastRawData = null;

function selectedServices() {
  if (svcAllBox.checked) return ['all'];
  return Array.from(document.querySelectorAll('input[name="svc"]:checked')).map(el => el.value);
}

function updateSvcSummary() {
  if (svcAllBox.checked) { svcSummary.textContent = 'All'; return; }
  const sel = selectedServices();
  svcSummary.textContent = sel.length === 0 ? 'none' : sel.length === 1 ? sel[0] : `${sel.length} services`;
}

svcAllBox.addEventListener('change', () => {
  document.querySelectorAll('input[name="svc"]').forEach(cb => { cb.disabled = svcAllBox.checked; });
  updateSvcSummary();
});
document.querySelectorAll('input[name="svc"]').forEach(cb => cb.addEventListener('change', updateSvcSummary));

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const host = hostInput.value.trim();
  if (!host) return;

  const svcs = selectedServices();

  resultsEl.hidden = true;
  resultsEl.innerHTML = '';
  lastRawData = null;
  statusEl.hidden = false;
  statusEl.className = 'status';
  statusEl.textContent = `Scanning ${host} …`;
  goBtn.disabled = true;

  try {
    const body = { host };
    if (svcs.length > 0) body.services = svcs;
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data && data.error ? data.error : `request failed (${resp.status})`);
    }
    lastRawData = data;
    statusEl.hidden = true;
    render(data);
  } catch (err) {
    statusEl.className = 'status error';
    statusEl.textContent = 'Error: ' + err.message;
  } finally {
    goBtn.disabled = false;
  }
});

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function badge(verdict, label) {
  return `<span class="badge v-${verdict}">${label}</span>`;
}

function render(hr) {
  resultsEl.innerHTML = '';

  const ts = new Date().toUTCString().replace(' GMT', ' UTC');

  const roll = document.createElement('div');
  roll.className = `rollup b-${hr.verdict}`;
  roll.innerHTML =
    `<div class="rollup-head">` +
      badge(hr.verdict, verdictLabel(hr.verdict)) +
      `<button class="copy-btn" id="copy-json-btn" type="button">Copy JSON</button>` +
    `</div>` +
    `<h2>${escapeHtml(hr.host)}</h2>` +
    `<p class="sum">${escapeHtml(hr.summary || '')}</p>` +
    `<p class="ts">Scanned ${ts}</p>`;
  resultsEl.appendChild(roll);

  document.getElementById('copy-json-btn').addEventListener('click', () => {
    const btn = document.getElementById('copy-json-btn');
    navigator.clipboard.writeText(JSON.stringify(lastRawData, null, 2)).then(() => {
      btn.textContent = 'Copied ✓';
      setTimeout(() => { btn.textContent = 'Copy JSON'; }, 2000);
    }).catch(() => {
      btn.textContent = 'Copy failed';
      setTimeout(() => { btn.textContent = 'Copy JSON'; }, 2000);
    });
  });

  for (const s of (hr.services || [])) {
    const card = document.createElement('div');
    card.className = s.reachable ? 'svc' : 'svc unreachable';

    // Header: service name + port + optional SSH banner chip
    let headerInner =
      `<h3>${escapeHtml(s.service)} <span style="color:var(--ink-soft);font-weight:400">:${s.port}</span>` +
      (s.banner ? ` <span class="banner-chip">${escapeHtml(s.banner)}</span>` : '') +
      `</h3>`;

    // Error band — only when not reachable and error is known
    const errorBand = (!s.reachable && s.error)
      ? `<p class="error-band">⚠ ${escapeHtml(s.error)}</p>`
      : '';

    // Meta: TLS version + cipher, cert sig + expiry, cert subject
    let meta = '';
    if (s.tlsVersion) meta += `${escapeHtml(s.tlsVersion)} · ${escapeHtml(s.cipherSuite || '')}`;
    if (s.certSignatureAlgorithm) {
      meta += (meta ? '<br>' : '') +
        `cert sig: ${escapeHtml(s.certSignatureAlgorithm)}` +
        (s.certNotAfter ? ` (expires ${escapeHtml(s.certNotAfter)})` : '');
    }
    if (s.certSubject) {
      meta += (meta ? '<br>' : '') + `cert: ${escapeHtml(s.certSubject)}`;
    }

    // Negotiated group highlight — ready cards only
    const negotiated = (s.verdict === 'ready' && s.bestPqGroup)
      ? `<p class="negotiated">Negotiated: <span>${escapeHtml(s.bestPqGroup)}</span></p>`
      : '';

    // Group matrix — low-confidence groups get amber pills
    let matrix = '';
    for (const g of (s.groups || [])) {
      let pillCls, pillText;
      if (g.lowConfidence) {
        pillCls = g.supported ? 'pill lowconf-yes' : 'pill lowconf-no';
        pillText = g.supported ? '~YES' : '~no';
      } else {
        pillCls = g.supported ? 'pill yes' : 'pill no';
        pillText = g.supported ? 'YES' : 'no';
      }
      const noteText = g.lowConfidence ? (g.note || 'result is low-confidence') : (g.note || '');
      const note = noteText ? `<span class="note">— ${escapeHtml(noteText)}</span>` : '';
      matrix += `<li><span class="${pillCls}">${pillText}</span><span>${escapeHtml(g.group)}</span>${note}</li>`;
    }

    card.innerHTML =
      `<div class="head">${headerInner}${badge(s.verdict, verdictLabel(s.verdict))}</div>` +
      errorBand +
      (meta ? `<p class="meta">${meta}</p>` : '') +
      negotiated +
      (matrix ? `<ul class="matrix">${matrix}</ul>` : '') +
      formatBriefing(s.briefing || '');

    resultsEl.appendChild(card);
  }
  resultsEl.hidden = false;
}

// Split briefing at "Remediation:" to give it visual prominence.
function formatBriefing(text) {
  if (!text) return '';
  const idx = text.indexOf('Remediation:');
  if (idx === -1) return `<p class="briefing">${escapeHtml(text)}</p>`;
  const before = text.slice(0, idx).trim();
  const after = text.slice(idx + 'Remediation:'.length).trim();
  return (before ? `<p class="briefing">${escapeHtml(before)}</p>` : '') +
    `<p class="remediation"><strong>Remediation:</strong> ${escapeHtml(after)}</p>`;
}

function verdictLabel(v) {
  return v === 'ready' ? 'Quantum-safe'
    : v === 'not_ready' ? 'Not ready'
    : "Couldn't determine";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}
