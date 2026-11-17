import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readTheme, refreshTheme } from '../src/theme.js';
import { approvalHint, integratorOrigin } from '../src/origins.js';

const site = 'https://integrator.test';
function manifest(value) {
  return async (url, options) => {
    assert.equal(url.href, site + '/.well-known/countersign.json');
    assert.equal(options.redirect, 'error');
    return Response.json(value);
  };
}

test('display copy, appearance and logo never select the Integrator origin', async () => {
  const first = await readTheme(site, manifest({ version: 1, displayName: 'Example' }));
  const later = await readTheme(site, manifest({ version: 1, displayName: 'Different' }));
  const pairing = refreshTheme({ origin: site, theme: first }, later);
  assert.equal(pairing.theme.name, 'Example');
  assert.equal(pairing.pendingTheme.name, 'Different');
  assert.equal(pairing.origin, site);
  for (const additions of [
    { displayName: 'trusted\u202eevil' }, { logo: 'https://other.test/logo' },
    { colors: { accent: 'red; display:none' } },
  ]) {
    await assert.rejects(readTheme(site, manifest({ version: 1, displayName: 'Example', ...additions })));
  }
});

test('only an exact opaque-ID approval link can wake the Companion', () => {
  const id = '13e33b7d-cbef-4488-8174-30e73ad76d05';
  assert.equal(approvalHint('countersign://approve/' + id), id);
  for (const tail of ['?origin=evil', '#approve', '/more']) {
    assert.equal(approvalHint('countersign://approve/' + id + tail), undefined);
  }
  for (const invalid of ['http://example.test', site + '/any', 'https://person@integrator.test']) {
    assert.throws(() => integratorOrigin(invalid));
  }
});
