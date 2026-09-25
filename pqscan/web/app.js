'use strict';

const form = document.getElementById('scan-form');
const hostInput = document.getElementById('host');
const goBtn = document.getElementById('go');
const statusEl = document.getElementById('status');
const resultsEl = document.getElementById('results');
const svcAllBox = document.getElementById('svc-all');
const svcSummary = document.getElementById('svc-summary');

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

  const roll = el('div', `rollup b-${hr.verdict}`);
  roll.innerHTML = badge(hr.verdict, verdictLabel(hr.verdict)) +
    `<h2>${escapeHtml(hr.host)}</h2>` +
    `<p class="sum">${escapeHtml(hr.summary || '')}</p>`;
  resultsEl.appendChild(roll);

  for (const s of (hr.services || [])) {
    const card = el('div', 'svc');
    let meta = '';
    if (s.tlsVersion) meta += `${s.tlsVersion} · ${escapeHtml(s.cipherSuite || '')}`;
    if (s.certSignatureAlgorithm) {
      meta += `${meta ? '<br>' : ''}cert signature: ${escapeHtml(s.certSignatureAlgorithm)}` +
        (s.certNotAfter ? ` (expires ${escapeHtml(s.certNotAfter)})` : '');
    }
    let matrix = '';
    for (const g of (s.groups || [])) {
      const pill = g.supported ? '<span class="pill yes">YES</span>' : '<span class="pill no">no</span>';
      const note = g.note ? `<span class="note">— ${escapeHtml(g.note)}</span>` : '';
      matrix += `<li>${pill}<span>${escapeHtml(g.group)}</span>${note}</li>`;
    }
    card.innerHTML =
      `<div class="head"><h3>${escapeHtml(s.service)} <span style="color:var(--ink-soft);font-weight:400">:${s.port}</span></h3>${badge(s.verdict, verdictLabel(s.verdict))}</div>` +
      (meta ? `<p class="meta">${meta}</p>` : '') +
      (matrix ? `<ul class="matrix">${matrix}</ul>` : '') +
      `<p class="briefing">${escapeHtml(s.briefing || '')}</p>`;
    resultsEl.appendChild(card);
  }
  resultsEl.hidden = false;
}

function verdictLabel(v) {
  return v === 'ready' ? 'Quantum-safe'
    : v === 'not_ready' ? 'Not ready'
    : "Couldn't determine";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
