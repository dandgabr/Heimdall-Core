// Management API client.
//
// Trust model (ADR-SEC-06 §2, §3.4):
//   - the management token is sent as a REQUEST HEADER (Authorization: Bearer),
//     never a cookie and never a query parameter;
//   - the token is held in MEMORY for the session and, at most, mirrored to
//     sessionStorage (origin-scoped, tab-lifetime) so a refresh does not force a
//     re-entry. It is NEVER written to localStorage.
//
// Errors: the server answers with `{error:{code,params}}`; ApiError carries the
// code and params so the UI localises them through the i18n catalog instead of
// displaying a server-sent sentence.
const TOKEN_KEY = 'heimdall.token';

let token = null;

export class ApiError extends Error {
  constructor(code, params, status) {
    super(code);
    this.name = 'ApiError';
    this.code = code;
    this.params = params || {};
    this.status = status;
  }
}

export function setToken(value) {
  token = value || null;
  if (token) {
    try {
      window.sessionStorage.setItem(TOKEN_KEY, token);
    } catch {
      /* sessionStorage disabled: memory-only, which is the stricter mode */
    }
  } else {
    try {
      window.sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* nothing to clear */
    }
  }
}

export function getToken() {
  if (token) return token;
  try {
    token = window.sessionStorage.getItem(TOKEN_KEY);
  } catch {
    token = null;
  }
  return token;
}

export function hasToken() {
  return Boolean(getToken());
}

async function request(method, path, body) {
  const headers = {};
  const current = getToken();
  if (current) headers.Authorization = `Bearer ${current}`;
  const init = { method, headers, credentials: 'same-origin' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const res = await fetch(path, init);

  if (res.status === 204) return null;

  const text = await res.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!res.ok) {
    const err = payload && payload.error ? payload.error : {};
    throw new ApiError(err.code || 'error.internal', err.params, res.status);
  }
  return payload;
}

const get = (path) => request('GET', path);
const post = (path, body) => request('POST', path, body);
const del = (path) => request('DELETE', path);

export const api = {
  status: () => get('/api/mgmt/status'),
  providers: () => get('/api/mgmt/providers').then((r) => r.providers),
  providerTest: (id) => post(`/api/mgmt/providers/${encodeURIComponent(id)}/test`),
  credentials: () => get('/api/mgmt/credentials').then((r) => r.credentials),
  addCredential: (provider, label, key) => post('/api/mgmt/credentials', { provider, label, key }),
  deleteCredential: (id) => post(`/api/mgmt/credentials/${encodeURIComponent(id)}/delete`),
  combos: () => get('/api/mgmt/combos').then((r) => r.combos),
  createCombo: (combo) => post('/api/mgmt/combos', combo),
  deleteCombo: (name) => del(`/api/mgmt/combos/${encodeURIComponent(name)}`),
  quotas: () => get('/api/mgmt/quotas').then((r) => r.quotas),
  gates: () => get('/api/mgmt/gates'),
  usage: () => get('/api/mgmt/usage'),
  rotateToken: () => post('/api/mgmt/token/rotate'),
  clientKeys: () => get('/api/mgmt/client-keys').then((r) => r.client_keys),
  createClientKey: (label) => post('/api/mgmt/client-keys', { label }),
  revokeClientKey: (id) => post(`/api/mgmt/client-keys/${encodeURIComponent(id)}/revoke`),
};
