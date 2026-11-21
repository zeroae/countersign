// The demo page in Chromium, its /api routes answered from fixtures (as
// scripts/capture_screenshots.mjs does), with the page clock fixed.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';
import { contentSecurityPolicy, files } from '../site-files.js';

const PORTAL = 'https://portal.example';
const DEMO_DIR = new URL('../', import.meta.url);
const NOW = Date.parse('2026-11-17T18:39:41-05:00');
const ID = '85b80155-ac10-487f-a024-5216ec7f8ced';
const SHA256 = 'c64a4b8b8bcdac1a7ac2bedcd13c520f4abfc07d5765d68df67f56ed0058f00b';
const OTHER = '778cf24949d2479a234335d05d81d8b9d578b616e63388254c5650c1d0ab5ec6';
const session = { csrf: 'fixture', vapid: null, user: 'u-42', context: 'close-q3', title: 'Q3 close',
  workload: 'export-981', workload_generation: 1, host: 'ledger.partner.example:443' };
const approved = extra => ({ id: ID, state: 'approved', ready: true, upstream_mtls_accepted: true,
  ingress_closed_count: 0, egress_closed_count: 0, ...extra });

let browser;
before(async () => { browser = await chromium.launch(); });
after(async () => { await browser?.close(); });

async function open(api, path) {
  const context = await browser.newContext({ locale: 'en-US', timezoneId: 'America/New_York' });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  await page.clock.install({ time: NOW });
  const replies = { session: () => session, devices: () => ({ devices: [] }), job: () => ({ result: null }), ...api };
  await page.route(PORTAL + '/**', async route => {
    const url = new URL(route.request().url());
    const headers = { 'Content-Security-Policy': contentSecurityPolicy };
    if (url.pathname.startsWith('/api/')) {
      const reply = replies[url.pathname.slice(5)];
      if (!reply) return route.fulfill({ status: 404, headers, json: {} });
      return route.fulfill({ headers, json: reply() });
    }
    const file = files.get(url.pathname);
    if (!file) return route.fulfill({ status: 404, headers });
    await route.fulfill({ headers, contentType: file[1], body: await readFile(new URL(file[0], DEMO_DIR)) });
  });
  await page.goto(PORTAL + path);
  return page;
}

test('the Access approved page counts down to the grant deadline', async () => {
  const page = await open({ status: () => approved({ expires_at_ms: NOW + 14 * 60_000 + 30_000 }) },
    '/#countersign=' + ID);
  const ends = page.locator('#access-ends');
  await ends.getByText('14:30 left').waitFor();
  assert.match(await ends.innerText(), /6:54 PM/);
  await page.clock.runFor(60_000);
  await ends.getByText('13:30 left').waitFor();
  await page.context().close();
});

// /api/job as integrator.js answers it: the last job's result and the
// Workload's current approval, which the Broker lookup returns.
const ran = (fingerprint, approval) => () => ({ result: { url: 'https://ledger.partner.example/statements/latest',
  ok: true, http_status: 200, fingerprint, subject: 'Demo user', error: null }, approval });
const certificate = { sha256: SHA256, subject: 'CN=Demo user', issuer: 'CN=Countersign demo client-ca',
  not_after_ms: NOW + 86_400_000 };

test('the Job result page compares the fingerprints without a paste box', async () => {
  for (const [fingerprint, shown, hidden] of [[SHA256, '#match', '#mismatch'], [OTHER, '#mismatch', '#match']]) {
    // No approval in this tab: the job's own request started it.
    const page = await open({ job: ran(fingerprint, approved({ expires_at_ms: NOW + 60_000, certificate })) }, '/job');
    await page.locator(shown).waitFor();
    assert.equal(await page.locator(hidden).isVisible(), false, fingerprint);
    assert.equal(await page.locator('textarea').count(), 0, 'no paste box');
    assert.match(await page.locator('#job-approved').innerText(), /c64a\s*4b8b/);
    await page.context().close();
  }
});

test('the Job result page says when the job has no approved certificate to compare', async () => {
  for (const approval of [null, { id: ID, state: 'pending', ready: false }]) {
    const page = await open({ job: ran(SHA256, approval) }, '/job');
    await page.locator('#no-compare').waitFor();
    assert.equal(await page.locator('#match').isVisible(), false);
    assert.equal(await page.locator('#mismatch').isVisible(), false);
    await page.context().close();
  }
});
