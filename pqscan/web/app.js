// pqscan web UI entry point.
import { showFormError } from './core.js';
import { initHosts } from './hosts.js';

(async function boot() {
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
})();
