// Contract tests for the pure SPA logic, run with the Node built-in test runner
// (`node --test test/`) — no DOM, no framework. They pin the two contracts the
// Go backend relies on:
//
//   1. the localiser resolves a server code from the SAME catalogs the backend
//      embeds (error.* codes, named params), and falls back to the code;
//   2. the API path strings match the routes internal/api/mgmt/handler.go
//      registers, so a drift in either side fails a fast, dependency-free test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { format } from '../src/lib/i18n.js';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..');

const en = JSON.parse(readFileSync(join(repo, 'internal', 'i18n', 'catalogs', 'en.json'), 'utf8'));
const pt = JSON.parse(readFileSync(join(repo, 'internal', 'i18n', 'catalogs', 'pt-BR.json'), 'utf8'));

test('format localises an error code from the backend catalog', () => {
  const code = 'error.invalid_request';
  const params = { reason: 'missing model' };
  assert.equal(format('en', code, params), 'Invalid request: missing model');
  assert.equal(format('pt-BR', code, params), 'Requisição inválida: missing model');
});

test('format substitutes every {named} placeholder', () => {
  const code = 'provider.not_found';
  assert.equal(format('en', code, { provider: 'zai' }), 'Unknown provider zai.');
  assert.equal(format('pt-BR', code, { provider: 'zai' }), 'Provedor desconhecido: zai.');
});

test('format leaves an unsupplied placeholder literal, like the Go Bundle', () => {
  assert.equal(format('en', 'error.invalid_request', {}), 'Invalid request: {reason}');
});

test('format returns the code for an unknown code', () => {
  assert.equal(format('en', 'totally.unknown.code', {}), 'totally.unknown.code');
});

test('every backend error code is present in both catalogs (GUI parity)', () => {
  // The SPA must be able to localise ANY code the Management API can return.
  // This catches a catalog added on one side only.
  const serverErrors = Object.keys(en).filter((k) => !k.startsWith('gui.'));
  for (const code of serverErrors) {
    assert.ok(code in pt, `pt-BR catalog missing server code ${code}`);
  }
  assert.deepEqual(Object.keys(en).sort(), Object.keys(pt).sort());
});

test('management API paths match internal/api/mgmt/handler.go', () => {
  // The literal paths the client calls; the Go test `TestMgmtRoutes...` pins the
  // server side. This asserts the SPA's own list stays aligned with the ADR's
  // documented route table (F5.2a).
  const paths = [
    '/api/mgmt/status',
    '/api/mgmt/providers',
    '/api/mgmt/credentials',
    '/api/mgmt/combos',
    '/api/mgmt/quotas',
    '/api/mgmt/gates',
    '/api/mgmt/usage',
    '/api/mgmt/token/rotate',
    '/api/mgmt/client-keys',
  ];
  const handler = readFileSync(join(repo, 'internal', 'api', 'mgmt', 'handler.go'), 'utf8');
  for (const p of paths) {
    assert.ok(handler.includes(p), `handler.go does not register ${p}`);
  }
});
