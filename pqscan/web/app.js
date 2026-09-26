// pqscan web UI entry point: tabs, then each view.
import { $, showFormError } from './core.js';
import { initHosts } from './hosts.js';
import { initFiles } from './files.js';
import { initCapture } from './capture.js';

const TABS = {
  hosts: {
    title: 'Check a host for post-quantum key exchange',
    lede: 'pqscan offers ML-KEM in real handshakes and reports what each server actually chooses, with the evidence behind every result.',
    how: '#how', howLabel: "How it's tested",
  },
  files: {
    title: 'Check data at rest for quantum exposure',
    lede: 'pqscan reads the headers that encrypted files, keys, and certificates declare, and shows which data a future quantum computer could decrypt from a copy taken today.',
    how: '#files-how', howLabel: 'How files are inspected',
  },
  capture: {
    title: 'Check traffic for quantum-exposed connections',
    lede: 'pqscan reads every handshake in a packet capture and shows how each connection set up its keys: which were post-quantum, which were not, and whether the client or the server was the reason.',
    how: '#cap-how', howLabel: 'How traffic is analyzed',
  },
};

function selectTab(name, focus) {
  for (const key of Object.keys(TABS)) {
    const on = key === name;
    const tab = $(`tab-${key}`);
    tab.setAttribute('aria-selected', String(on));
    tab.tabIndex = on ? 0 : -1;
    $(`panel-${key}`).hidden = !on;
  }
  const t = TABS[name];
  $('intro-title').textContent = t.title;
  $('intro-lede').textContent = t.lede;
  $('how-link').textContent = t.howLabel;
  $('how-link').href = t.how;
  if (name !== 'hosts') history.replaceState(null, '', `#${name}`);
  else if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  if (focus) $(`tab-${name}`).focus();
}

function initTabs() {
  const names = Object.keys(TABS);
  for (const name of names) {
    const tab = $(`tab-${name}`);
    tab.addEventListener('click', () => selectTab(name));
    tab.addEventListener('keydown', (e) => {
      const i = names.indexOf(name);
      const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: names.length - 1 }[e.key];
      if (next === undefined) return;
      e.preventDefault();
      selectTab(names[(next + names.length) % names.length], true);
    });
  }
  const fromHash = location.hash.slice(1);
  selectTab(names.includes(fromHash) ? fromHash : 'hosts');
}

(async function boot() {
  initTabs();
  let catalog;
  try {
    const resp = await fetch('api/catalog');
    if (!resp.ok) throw new Error(`catalog request failed (${resp.status})`);
    catalog = await resp.json();
  } catch (err) {
    showFormError('form-error', `Couldn't load the service list: ${err.message}`);
    return;
  }
  initHosts(catalog);
  initFiles(catalog);
  initCapture(catalog);
})();
