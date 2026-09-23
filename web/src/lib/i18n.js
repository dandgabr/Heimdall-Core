// Localisation for the embedded GUI.
//
// The Management API never sends a localised sentence: it sends
// `{error:{code,params}}` (ADR-0002). This module turns a code into a string
// from the SAME catalogs the backend embeds, so the two surfaces cannot drift.
// The catalogs are generated from internal/i18n/catalogs/*.json at build time.
import { catalogs } from '../i18n/generated/catalogs.js';

export const LANGUAGES = [
  { tag: 'pt-BR', label: 'Português (BR)' },
  { tag: 'en', label: 'English' },
];

const DEFAULT_LANGUAGE = 'en';

// LANGUAGE_KEY holds the user's language CHOICE only — never a secret, so it is
// safe in localStorage (it is a preference, not a credential).
const LANGUAGE_KEY = 'heimdall.lang';

const placeholder = /\{([A-Za-z0-9_.]+)\}/g;

// negotiate picks the initial language: the persisted preference, else the
// browser's Accept-Language hints, else the default. It mirrors the server's
// precedence (Accept-Language -> stored preference -> en).
export function negotiate() {
  const stored = safeGet(LANGUAGE_KEY);
  if (stored && catalogs[stored]) return stored;
  for (const hint of navigator.languages || [navigator.language || '']) {
    if (!hint) continue;
    if (/^pt/i.test(hint) && catalogs['pt-BR']) return 'pt-BR';
    if (/^en/i.test(hint) && catalogs['en']) return 'en';
  }
  return DEFAULT_LANGUAGE;
}

export function persistLanguage(tag) {
  safeSet(LANGUAGE_KEY, tag);
}

// format resolves code in tag and substitutes {named} params. An unknown code
// falls back to the default catalog and then to the code itself, exactly like
// the Go Bundle.Format, so a missing entry surfaces the stable code rather than
// an empty string.
export function format(tag, code, params = {}) {
  if (!code) return '';
  const catalog = catalogs[tag] || catalogs[DEFAULT_LANGUAGE] || {};
  const fallback = catalogs[DEFAULT_LANGUAGE] || {};
  const template = catalog[code] ?? fallback[code] ?? code;
  return template.replace(placeholder, (match, name) => {
    const value = params[name];
    return value === undefined || value === null ? match : String(value);
  });
}

function safeGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* storage disabled: the preference is simply not persisted */
  }
}
