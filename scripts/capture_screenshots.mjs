#!/usr/bin/env node
// Capture the handbook screenshots from fixtures.
//
// The real renderers run in Chromium: the Companion's packages/companion/src
// page with a stubbed `window.countersign` preload API, and the demo
// Integrator's site with its /api routes answered from fixture data. No
// Broker, Gateway or certificate store is needed. The clock, locale and time
// zone are fixed so dates in the shots do not age.
//
// Writes docs/assets/screenshots/raw/<name>.png (plus <name>-dark.png where
// the UI has a dark theme) and raw/boxes.json, which records the CSS-pixel
// box of every element scripts/annotate_screenshots.py highlights.
//
//   pnpm screenshots          # capture, then annotate
//   node scripts/capture_screenshots.mjs [--browser /path/to/chromium] [--only name,...]
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { extname } from 'node:path';
import { parseArgs } from 'node:util';
import { chromium } from 'playwright';
import { contentSecurityPolicy, files as siteFiles, manifest } from '../examples/demo-integrator/site-files.js';

const { values: args } = parseArgs({ options: {
  browser: { type: 'string', default: process.env.CHROMIUM_PATH },
  only: { type: 'string' },
} });
const ROOT = new URL('../', import.meta.url);
const RAW = new URL('docs/assets/screenshots/raw/', ROOT);
const COMPANION_SRC = new URL('packages/companion/src/', ROOT);
const DEMO_DIR = new URL('examples/demo-integrator/', ROOT);
const COMPANION = 'https://companion.invalid/';
const PORTAL = 'https://portal.example';
const SCALE = 2;
const NOW = new Date('2026-11-17T18:39:41-05:00');
const environment = { deviceScaleFactor: SCALE, locale: 'en-US', timezoneId: 'America/New_York' };
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png' };

// ---------------------------------------------------------------- fixtures
const fingerprints = {
  first: '778cf24949d2479a234335d05d81d8b9d578b616e63388254c5650c1d0ab5ec6',
  selected: 'c64a4b8b8bcdac1a7ac2bedcd13c520f4abfc07d5765d68df67f56ed0058f00b',
};
const certificate = (reference, fingerprint) => ({
  reference, fingerprint, identity: 'CN=Demo user', issuer: 'CN=Countersign demo client-ca',
  expiresAt: Date.parse('2026-11-19T18:39:30-05:00'),
});
const harborLogo = 'data:image/png;base64,' +
  (await readFile(new URL('site/harbor-ledger.png', DEMO_DIR))).toString('base64');
const harbor = { digest: 'harbor', name: manifest.displayName, copy: manifest.copy,
  accent: manifest.colors.accent, background: manifest.colors.background, dark: manifest.colors.dark, logo: harborLogo };
// A second fictional Integrator, to show that branding belongs to the pairing.
// It sets no dark colours, so the Companion derives them.
const lantern = { digest: 'lantern', name: 'Lantern Audit', copy: 'Engagement evidence room',
  accent: '#d9822b', background: '#fdf6ee', logo: null };
const lanternNext = { digest: 'lantern-2', name: 'Lantern Audit', copy: 'Evidence room for FY26 fieldwork',
  accent: '#7a3e9d', background: '#f4edf9', logo: null };
const AUDIT = 'https://audit.example';
const JOBS = 'https://jobs.example';
const job = { user: 'u-42', context: 'close-q3', title: 'Q3 close reconciliation', workload: 'export-981',
  workload_generation: 1, host: 'ledger.partner.example:443' };
const offer = (extra = {}) => ({
  handle: 'offer-1', received: NOW.getTime() - 5000, pairing: 'harbor', origin: PORTAL, user: job.user,
  context: job.context, theme: harbor, host: job.host, scope: job.host, providerUnavailable: false,
  maxDuration: 28800, defaultDuration: 3600,
  identities: [certificate('first', fingerprints.first), certificate('selected', fingerprints.selected)], ...extra,
});
const lanternOffer = (extra = {}) => offer({ handle: 'offer-2', received: NOW.getTime() - 2000, pairing: 'lantern',
  origin: AUDIT, user: 'analyst-7', context: 'fy26-fieldwork', theme: lantern, host: 'evidence.audit.example:443',
  scope: 'evidence.audit.example:443', identities: [certificate('selected', fingerprints.selected)], ...extra });
const snapshot = (extra = {}) => ({ offers: [], pairings: [], pending: [], confirmation: null, login: true, ...extra });
const approvalId = '85b80155-ac10-487f-a024-5216ec7f8ced';
const binding = pairing => ({ pairing, key: 'k-' + pairing.slice(0, 4), channel_generation: 1 });
const device = { binding: binding('7b9df613-d84e-4c1a-9a0e-2f6b1c3d5e7a'),
  connected: true, connected_at_ms: NOW.getTime() - 600000, observed_address: '198.51.100.24' };
const otherDevice = { binding: binding('91ab3c5e-0f27-4b8e-a6d1-c2e4f8a90b13'), connected: true,
  connected_at_ms: NOW.getTime() - 1680000, observed_address: '203.0.113.24' };
const approval = (id, extra) => ({ id, host: job.host, scope: job.host, context: job.context,
  until: NOW.getTime() + 3600000, fingerprint: fingerprints.selected, revocation: undefined, ready: true, ...extra });
const pairings = [
  { id: 'harbor', origin: PORTAL, user: job.user, status: 'Connected', theme: harbor, pendingTheme: null,
    devices: [{ ...device, self: true }, { ...otherDevice, self: false }],
    notices: [{ id: 'n1', kind: 'concurrent_devices', occurred_at_ms: NOW.getTime() - 1680000,
      observed_address: '203.0.113.24', actor: { pairing: otherDevice.binding.pairing } }],
    approvals: [approval('a1'),
      approval('a2', { host: 'reports.team.example:9444', scope: '*.team.example:9444', until: NOW.getTime() + 5400000,
        revocation: 'pending', ready: false }),
      approval('a3', { context: 'close-q2', until: NOW.getTime() + 1200000, revocation: 'recorded', ready: false })] },
  { id: 'lantern', origin: AUDIT, user: 'analyst-7', status: 'Offline', theme: lantern, pendingTheme: lanternNext,
    devices: [], notices: [], approvals: [] },
  { id: 'jobs', origin: JOBS, user: job.user, status: 'Connected', theme: null, pendingTheme: null,
    devices: [{ ...device, binding: binding('c3d1e8a2-5b7f-4e09-9a61-3f2b8d4c7e15'), self: true }], notices: [],
    approvals: [approval('a4', { context: 'nightly-export', until: NOW.getTime() + 7200000 })] },
];

// ------------------------------------------------------------- page helpers
async function newPage(browser, options) {
  const context = await browser.newContext({ ...environment, ...options });
  const page = await context.newPage();
  await page.clock.setFixedTime(NOW);
  page.setDefaultTimeout(10000);
  return page;
}

// The Companion window, 660 pixels wide like the app, made tall enough that
// nothing scrolls. `state` is the snapshot the main process would return.
async function companion(browser, scheme, state) {
  const page = await newPage(browser, { viewport: { width: 660, height: 760 }, colorScheme: scheme });
  await page.route(COMPANION + '**', async route => {
    const path = new URL(route.request().url()).pathname.slice(1) || 'index.html';
    if (!/^[a-z.]+\.(html|js|css)$/.test(path)) return route.fulfill({ status: 404 });
    await route.fulfill({ body: await readFile(new URL(path, COMPANION_SRC)), contentType: types[extname(path)] });
  });
  // Stands in for preload.cjs. Only snapshot() returns data; the actions do
  // nothing. update() swaps the snapshot and announces it like the main process.
  await page.addInitScript(state => {
    const nothing = async () => {};
    let listener = () => {};
    window.countersign = { snapshot: async () => state, pair: nothing, confirmPair: nothing, decide: nothing,
      deny: nothing, theme: nothing, keepTheme: nothing, appearance: nothing, forgetOthers: nothing, revoke: nothing,
      removeLocal: nothing, forget: nothing, login: nothing, changed: callback => { listener = callback; return () => {}; } };
    window.update = next => { state = next; listener(); };
  }, state);
  await page.goto(COMPANION + 'index.html');
  await page.locator('#content > .view').waitFor();
  // Each newly shown request locks Approve for a second. The page clock is
  // fixed, so move it past the lock.
  await page.clock.setFixedTime(NOW.getTime() + 1500);
  await page.waitForFunction(() => !document.querySelector('#reason')?.textContent.startsWith('Approve unlocks'));
  return page;
}

// Grow the window until the content no longer scrolls.
async function fit(page) {
  const extra = await page.evaluate(() => {
    const content = document.getElementById('content');
    return content.scrollHeight - content.clientHeight;
  });
  if (extra > 0) await page.setViewportSize({ width: 660, height: 760 + extra });
}
const window_ = async page => {
  await fit(page);
  return { x: 0, y: 0, ...page.viewportSize() };
};

// `api` answers the demo backend's /api routes; see examples/demo-integrator/integrator.js.
async function portal(browser, colorScheme, api) {
  const page = await newPage(browser, { viewport: { width: 960, height: 1400 }, colorScheme });
  await page.route(PORTAL + '/**', async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const headers = { 'Content-Security-Policy': contentSecurityPolicy, 'X-Content-Type-Options': 'nosniff' };
    if (path.startsWith('/api/')) {
      const name = path.slice(5);
      const body = request.postDataJSON?.() ?? null;
      const result = name in api ? await api[name](body) : undefined;
      if (result === undefined) return route.fulfill({ status: 404, headers, json: {} });
      return route.fulfill({ headers, contentType: 'application/json', body: JSON.stringify(result) });
    }
    if (!siteFiles.has(path)) return route.fulfill({ status: 404, headers });
    const [file, contentType] = siteFiles.get(path);
    await route.fulfill({ headers, contentType, body: await readFile(new URL(file, DEMO_DIR)) });
  });
  return page;
}

// An approved status as the Broker returns it: the grant's deadline and the
// certificate the user approved.
const approvedStatus = () => ({ id: approvalId, state: 'approved', ready: true, upstream_mtls_accepted: true,
  ingress_closed_count: 0, egress_closed_count: 0, expires_at_ms: NOW.getTime() + 3570000,
  certificate: { sha256: fingerprints.selected, subject: 'CN=Demo user', issuer: 'CN=Countersign demo client-ca',
    not_after_ms: Date.parse('2026-11-19T18:39:30-05:00') } });

function demoApi(extra = {}) {
  return {
    session: () => ({ csrf: 'fixture', vapid: null, ...job }),
    devices: () => ({ devices: [device] }),
    status: () => ({ id: approvalId, state: 'pending', ready: false, upstream_mtls_accepted: false,
      ingress_closed_count: 0, egress_closed_count: 0 }),
    connect: () => ({ id: approvalId, state: 'pending' }),
    job: () => ({ result: null }),
    ...extra,
  };
}

// Union of the boxes of every element matching each selector, in CSS pixels
// relative to `origin`. `{ selector, text: true }` measures just the text a
// block element holds instead of its full width.
async function measure(page, selectors, origin = { x: 0, y: 0 }) {
  const boxes = {};
  for (const [key, spec] of Object.entries(selectors)) {
    const { selector, text = false } = typeof spec === 'string' ? { selector: spec } : spec;
    const rects = await page.locator(selector).evaluateAll((nodes, text) => nodes.map(node => {
      let r = node.getBoundingClientRect();
      if (text) {
        const range = document.createRange();
        range.selectNodeContents(node);
        r = range.getBoundingClientRect();
      }
      return [r.left + scrollX, r.top + scrollY, r.right + scrollX, r.bottom + scrollY];
    }), text);
    if (!rects.length) throw new Error(`No element for ${key}: ${selector}`);
    boxes[key] = [Math.min(...rects.map(r => r[0])) - origin.x, Math.min(...rects.map(r => r[1])) - origin.y,
      Math.max(...rects.map(r => r[2])) - origin.x, Math.max(...rects.map(r => r[3])) - origin.y]
      .map(v => Math.round(v * 10) / 10);
  }
  return boxes;
}

const sidecar = {};
async function capture(page, name, { clip, selectors = {} }) {
  // Drop focus so no focus ring or caret lands in the shot.
  await page.evaluate(() => { document.activeElement?.blur(); return document.fonts.ready; });
  const area = await clip(page);
  const rect = { x: Math.floor(area.x), y: Math.floor(area.y),
    width: Math.ceil(area.width), height: Math.ceil(area.height) };
  await page.screenshot({ path: new URL(name, RAW).pathname, clip: rect, animations: 'disabled', caret: 'hide' });
  sidecar[name] = { scale: SCALE, width: rect.width, height: rect.height, boxes: await measure(page, selectors, rect) };
  console.log('captured', name);
}

// Crop to one element, plus a margin.
const around = (selector, margin = 12) => async page => {
  const box = await page.locator(selector).first().boundingBox();
  return { x: box.x - margin, y: box.y - margin, width: box.width + 2 * margin, height: box.height + 2 * margin };
};
// Crop from the top of the page to the bottom of an element.
const down = (selector, margin = 16) => async page => {
  const box = await page.locator(selector).first().boundingBox();
  const width = await page.evaluate(() => document.documentElement.clientWidth);
  return { x: 0, y: 0, width, height: box.y + box.height + margin };
};
// The whole rendered page, without the viewport's empty remainder. The page
// background continues for `margin` pixels to leave room for callout labels.
const content = async (page, margin = 12) => {
  const height = await page.evaluate(() =>
    Math.max(...[...document.querySelectorAll('body > header, body > main:not([hidden])')]
      .map(node => node.getBoundingClientRect().bottom + scrollY))) + margin;
  const width = await page.evaluate(() => document.documentElement.clientWidth);
  return { x: 0, y: 0, width, height };
};

// ------------------------------------------------------------------- shots
// Each Companion shot runs once per color scheme.
const companionShots = {
  async 'approval-unselected'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ offers: [offer(), lanternOffer()], pairings }));
    await capture(page, name, { clip: window_, selectors: {
      identities: '#requests .certs', actions: '.actions .decision', queue: '#requests .queue',
    } });
  },
  async 'approval-selected'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ offers: [offer()], pairings }));
    await page.locator('#requests .identity').nth(1).locator('input').check();
    await capture(page, name, { clip: window_, selectors: {
      selected: '#requests .identity:has(input:checked)', expiry: '#requests .expires',
      header: '#brand-integrator', plate: '.plate',
      facts: '#requests .verified', presets: '#requests .seg',
    } });
  },
  async 'scope-wildcard'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ pairings, offers: [offer({
      host: 'reports.team.example:9444', scope: '*.team.example:9444',
      identities: [certificate('selected', fingerprints.selected)],
    })] }));
    await capture(page, name, { clip: window_, selectors: {
      scope: '#requests .fact:nth-child(n+4)', warning: '#requests .verified .alert',
    } });
  },
  async 'branding-alternate'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ pairings, offers: [lanternOffer()] }));
    await capture(page, name, { clip: window_, selectors: {
      header: '#brand-integrator', approve: '.actions .primary',
    } });
  },
  async 'branding-none'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ pairings, offers: [offer({
      pairing: 'jobs', origin: JOBS, theme: null, context: 'nightly-export',
      identities: [certificate('selected', fingerprints.selected)],
    })] }));
    await capture(page, name, { clip: window_, selectors: {
      brand: '#brand-countersign', note: { selector: '#requests .nobrand', text: true },
    } });
  },
  async 'queue-switch'(browser, scheme, name) {
    const first = snapshot({ pairings, offers: [offer(), lanternOffer()] });
    const page = await companion(browser, scheme, first);
    // The Harbor Ledger request is decided elsewhere; Lantern Audit's moves up.
    await page.evaluate(next => window.update(next), { ...first, offers: [lanternOffer()] });
    await page.locator('.switch-banner').waitFor();
    await capture(page, name, { clip: window_, selectors: {
      banner: '.switch-banner', approve: '.actions .primary', reason: { selector: '#reason', text: true },
    } });
  },
  async 'pairing-companion'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({
      pending: [{ id: 'harbor', origin: PORTAL, status: 'Pairing code 7B9DF613D8', code: '7B9DF613D8', theme: harbor }],
      confirmation: { id: 'confirmation-1', pairing: 'harbor', origin: PORTAL, user: job.user, code: '7B9DF613D8', theme: harbor },
    }));
    await page.getByRole('button', { name: 'Cancel pairing' }).waitFor();
    await capture(page, name, { clip: window_, selectors: {
      facts: '#pairing .verified', code: '#pairing .code-box',
    } });
  },
  async 'integrators-list'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ pairings }));
    await page.getByRole('button', { name: 'Integrators' }).click();
    await capture(page, name, { clip: window_, selectors: { rows: '#pairs', pair: '#pair' } });
  },
  async 'integrator-detail'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ pairings }));
    await page.getByRole('button', { name: 'Integrators' }).click();
    await page.locator('#pairs .int-row').first().click();
    await capture(page, name, { clip: window_, selectors: {
      notice: '#detail .alert', approvals: '#detail .row:has(.mono:text-is("' + job.host + '"))',
      self: '#detail .tag',
    } });
  },
  async 'branding-review'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ pairings }));
    await page.getByRole('button', { name: 'Integrators' }).click();
    await page.locator('#pairs .int-row').nth(1).click();
    await capture(page, name, { clip: window_, selectors: { review: '#detail .review', buttons: '#detail .review + p + .btnrow button' } });
  },
  async 'dialog-remove'(browser, scheme, name) {
    const page = await companion(browser, scheme, snapshot({ pairings }));
    await page.getByRole('button', { name: 'Integrators' }).click();
    await page.locator('#pairs .int-row').nth(2).click();
    await page.getByRole('button', { name: 'Remove from this computer' }).click();
    await page.locator('dialog[open]').waitFor();
    await capture(page, name, { clip: window_, selectors: { dialog: 'dialog[open]' } });
  },
};

// Each demo shot runs once per color scheme.
const portalShots = {
  async 'pairing-browser'(browser, scheme, name) {
    const page = await portal(browser, scheme, demoApi({ devices: () => ({ devices: [] }) }));
    await page.goto(PORTAL + '/countersign/pair?attempt=fixture-attempt');
    await page.getByLabel('Code from your Companion').fill('7B9DF613D8');
    await capture(page, name, { clip: content, selectors: { code: '#pair .field' } });
  },
  async widget(browser, scheme, name) {
    const page = await portal(browser, scheme, demoApi());
    await page.goto(PORTAL + '/');
    await page.locator('countersign-widget').getByRole('button', { name: 'Request access' }).click();
    await page.getByRole('link', { name: 'Open Companion' }).waitFor();
    await page.getByRole('heading', { name: 'Waiting for your approval' }).waitFor();
    await capture(page, name, { clip: content, selectors: {
      page: '.column > section:not([hidden])', widget: 'countersign-widget',
    } });
  },
  async 'access-active'(browser, scheme, name) {
    const page = await portal(browser, scheme, demoApi({ status: approvedStatus }));
    await page.goto(PORTAL + '/#countersign=' + approvalId);
    await page.getByRole('heading', { name: 'Access approved' }).waitFor();
    await page.locator('#access-ends').getByText('59:30 left').waitFor();
    await capture(page, name, { clip: content, selectors: { progress: '.progress li', ends: '#access-ends-row' } });
  },
  async 'access-ended'(browser, scheme, name) {
    const page = await portal(browser, scheme, demoApi({
      status: approvedStatus,
      revoke: () => null,
    }));
    await page.goto(PORTAL + '/#countersign=' + approvalId);
    await page.getByRole('button', { name: 'Revoke access' }).click();
    await page.getByText('Access was revoked').waitFor();
    await capture(page, name, { clip: content, selectors: { again: 'countersign-widget [data-action="connect"]' } });
  },
  async 'job-result'(browser, scheme, name) {
    const page = await portal(browser, scheme, demoApi({
      status: approvedStatus,
      job: () => ({ result: { url: 'https://ledger.partner.example/statements/latest', ok: true, http_status: 200,
        fingerprint: fingerprints.selected, subject: 'Demo user', error: null } }),
    }));
    await page.goto(PORTAL + '/job#countersign=' + approvalId);
    await page.locator('#match').waitFor();
    await capture(page, name, { clip: content, selectors: { compare: '.pair-cards', match: '#match' } });
  },
};

const only = args.only ? new Set(args.only.split(',')) : null;
await mkdir(RAW, { recursive: true });
const sidecarFile = new URL('boxes.json', RAW);
Object.assign(sidecar, only ? JSON.parse(await readFile(sidecarFile, 'utf8').catch(() => '{}')) : {});
const browser = await chromium.launch(args.browser ? { executablePath: args.browser } : {});
try {
  for (const [name, shot] of [...Object.entries(companionShots), ...Object.entries(portalShots)]) {
    if (only && !only.has(name)) continue;
    await shot(browser, 'light', name + '.png');
    await shot(browser, 'dark', name + '-dark.png');
  }
} finally {
  await browser.close();
}
const ordered = Object.fromEntries(Object.entries(sidecar).sort(([a], [b]) => a.localeCompare(b)));
await writeFile(sidecarFile, JSON.stringify(ordered, null, 2) + '\n');
