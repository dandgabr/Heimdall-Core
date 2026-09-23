// A tiny hash router. No dependency and no history API: the SPA is served from
// a single index.html and the server does not need a rewrite rule per client
// route — the fragment never reaches the server, which keeps the Go handler
// trivial and the fallback unconditional.
import { writable } from 'svelte/store';

export const PAGES = [
  { id: 'status', path: '#/status' },
  { id: 'providers', path: '#/providers' },
  { id: 'credentials', path: '#/credentials' },
  { id: 'combos', path: '#/combos' },
  { id: 'quotas', path: '#/quotas' },
  { id: 'gates', path: '#/gates' },
  { id: 'usage', path: '#/usage' },
  { id: 'tokens', path: '#/tokens' },
  { id: 'client-keys', path: '#/client-keys' },
];

const DEFAULT_PAGE = 'status';

export function parseHash(hash) {
  const id = String(hash || '').replace(/^#\/?/, '');
  return PAGES.some((p) => p.id === id) ? id : DEFAULT_PAGE;
}

export const page = writable(parseHash(typeof window !== 'undefined' ? window.location.hash : ''));

export function startRouter() {
  if (typeof window === 'undefined') return () => {};
  const onHash = () => page.set(parseHash(window.location.hash));
  window.addEventListener('hashchange', onHash);
  if (!window.location.hash) window.location.hash = `#/${DEFAULT_PAGE}`;
  onHash();
  return () => window.removeEventListener('hashchange', onHash);
}

export function navigate(id) {
  if (typeof window !== 'undefined') window.location.hash = `#/${id}`;
}
