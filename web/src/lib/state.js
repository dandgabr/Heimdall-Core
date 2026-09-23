// Reactive locale + token state for the SPA.
//
// Kept deliberately small and framework-agnostic where it matters: the pure
// helpers (i18n.format, negotiate, api.*) carry no Svelte import, so they are
// exercised by the Node contract test without a DOM. This module only wires them
// into the Svelte store contract.
import { writable, derived } from 'svelte/store';
import { LANGUAGES, format, negotiate, persistLanguage } from './i18n.js';
import { getToken, setToken, hasToken } from './api.js';

export const locale = writable(negotiate());
export const authenticated = writable(hasToken());

// t is the translator bound to the CURRENT locale; components use `$t(code, params)`.
export const t = derived(locale, ($locale) => (code, params) => format($locale, code, params));

export function setLanguage(tag) {
  if (!LANGUAGES.some((l) => l.tag === tag)) return;
  locale.set(tag);
  persistLanguage(tag);
}

export function login(value) {
  setToken(value);
  authenticated.set(true);
}

export function logout() {
  setToken(null);
  authenticated.set(false);
}

export { LANGUAGES };
