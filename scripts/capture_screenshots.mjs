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
const harbor = { digest: 'harbor', name: manifest.displayName, copy: manifest.copy, logo: harborLogo,
  accent: manifest.colors.accent, background: manifest.colors.background };
// A second fictional Integrator, to show that branding belongs to the pairing.
const lantern = { digest: 'lantern', name: 'Lantern Audit', copy: 'Engagement evidence room', logo: null,
  accent: '#9a4a0c', background: '#fbefe2' };
const job = { user: 'u-42', context: 'close-q3', title: 'Q3 close reconciliation', workload: 'export-981',
  workload_generation: 1, host: 'ledger.partner.example:443' };
const offer = (extra = {}) => ({
  handle: 'offer-1', origin: PORTAL, user: job.user, context: job.context, theme: harbor,
  host: job.host, scope: job.host, providerUnavailable: false, maxDuration: 28800, defaultDuration: 3600,
  identities: [certificate('first', fingerprints.first), certificate('selected', fingerprints.selected)], ...extra,
});
const snapshot = (extra = {}) => ({ offers: [], pairings: [], pending: '', confirmation: null, login: false, ...extra });
const approvalId = '85b80155-ac10-487f-a024-5216ec7f8ced';
const device = { binding: { pairing: '7b9df613-d84e-4c1a-9a0e-2f6b1c3d5e7a', key: 'k1', channel_generation: 1 },
  connected: true, connected_at_ms: NOW.getTime() - 600000, observed_address: '198.51.100.24' };

// ------------------------------------------------------------- page helpers
async function newPage(browser, options) {
  const context = await browser.newContext({ ...environment, ...options });
  const page = await context.newPage();
  await page.clock.setFixedTime(NOW);
  page.setDefaultTimeout(10000);
  return page;
}

async function companion(browser, state) {
  const page = await newPage(browser, { viewport: { width: 760, height: 1600 }, colorScheme: 'light' });
  await page.route(COMPANION + '**', async route => {
    const path = new URL(route.request().url()).pathname.slice(1) || 'index.html';
    if (!/^[a-z.]+\.(html|js|css)$/.test(path)) return route.fulfill({ status: 404 });
    await route.fulfill({ body: await readFile(new URL(path, COMPANION_SRC)), contentType: types[extname(path)] });
  });
  // Stands in for preload.cjs. Only snapshot() returns data; the actions do nothing.
  await page.addInitScript(state => {
    const nothing = async () => {};
    window.countersign = { snapshot: async () => state, pair: nothing, confirmPair: nothing, decide: nothing,
      deny: nothing, theme: nothing, forgetOthers: nothing, revoke: nothing, removeLocal: nothing,
      forget: nothing, login: nothing, changed: () => () => {} };
  }, state);
  await page.goto(COMPANION + 'index.html');
  return page;
}

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
const companionShots = {
  async 'approval-unselected'(browser) {
    const page = await companion(browser, snapshot({ offers: [offer()] }));
    await page.locator('#requests article').waitFor();
    await capture(page, 'approval-unselected.png', { clip: around('#requests article', 0), selectors: {
      identities: '#requests label.identity', approve: '#requests button.approve',
      actions: '#requests .actions button',
    } });
  },
  async 'approval-selected'(browser) {
    const page = await companion(browser, snapshot({ offers: [offer()] }));
    await page.locator('#requests label.identity').nth(1).locator('input').check();
    await capture(page, 'approval-selected.png', { clip: around('#requests article', 0), selectors: {
      selected: '#requests label.identity:has(input:checked)',
      expiry: { selector: '#requests article > p:has-text("Expires by")', text: true },
      branding: '#requests .brand',
    } });
  },
  async 'scope-wildcard'(browser) {
    const page = await companion(browser, snapshot({ offers: [offer({
      host: 'reports.team.example:9444', scope: '*.team.example:9444',
      identities: [certificate('selected', fingerprints.selected)],
    })] }));
    await page.locator('#requests article').waitFor();
    await capture(page, 'scope-wildcard.png', { clip: around('#requests article', 0), selectors: {
      scope: { selector: '#requests dl > :is(dt, dd):nth-child(n+7)', text: true },
    } });
  },
  async 'branding-alternate'(browser) {
    const page = await companion(browser, snapshot({ offers: [offer({
      origin: 'https://audit.example', user: 'analyst-7', context: 'fy26-fieldwork', theme: lantern,
      host: 'evidence.audit.example:443', scope: 'evidence.audit.example:443',
      identities: [certificate('selected', fingerprints.selected)],
    })] }));
    await page.locator('#requests article').waitFor();
    await capture(page, 'branding-alternate.png', { clip: around('#requests article', 0), selectors: {
      branding: '#requests .brand',
    } });
  },
  async 'pairing-companion'(browser) {
    const page = await companion(browser, snapshot({
      pending: PORTAL + ' · Pairing code 7B9DF613D8',
      confirmation: { id: 'confirmation-1', origin: PORTAL, user: job.user, code: 'Pairing code 7B9DF613D8' },
    }));
    await page.locator('#origin').fill(PORTAL);
    await page.getByRole('button', { name: 'Cancel pairing' }).waitFor();
    await capture(page, 'pairing-companion.png', { clip: down('#enrollment'), selectors: {
      confirmation: { selector: '#pending > p', text: true },
    } });
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
    const page = await portal(browser, scheme, demoApi({
      status: () => ({ id: approvalId, state: 'approved', ready: true, upstream_mtls_accepted: true,
        ingress_closed_count: 0, egress_closed_count: 0 }),
    }));
    await page.goto(PORTAL + '/#countersign=' + approvalId);
    await page.getByRole('heading', { name: 'Access approved' }).waitFor();
    await capture(page, name, { clip: content, selectors: { progress: '.progress li' } });
  },
  async 'access-ended'(browser, scheme, name) {
    const page = await portal(browser, scheme, demoApi({
      status: () => ({ id: approvalId, state: 'approved', ready: true, upstream_mtls_accepted: true,
        ingress_closed_count: 0, egress_closed_count: 0 }),
      revoke: () => null,
    }));
    await page.goto(PORTAL + '/#countersign=' + approvalId);
    await page.getByRole('button', { name: 'Revoke access' }).click();
    await page.getByText('Access was revoked').waitFor();
    await capture(page, name, { clip: content, selectors: { again: 'countersign-widget [data-action="connect"]' } });
  },
  async 'job-result'(browser, scheme, name) {
    const page = await portal(browser, scheme, demoApi({
      job: () => ({ result: { url: 'https://ledger.partner.example/statements/latest', ok: true, http_status: 200,
        fingerprint: fingerprints.selected, subject: 'Demo user', error: null } }),
    }));
    await page.goto(PORTAL + '/job');
    await page.getByLabel('SHA-256 you selected in the Companion').fill(fingerprints.selected);
    await page.getByRole('button', { name: 'Compare' }).click();
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
  for (const [name, shot] of Object.entries(companionShots)) {
    if (!only || only.has(name)) await shot(browser);
  }
  for (const [name, shot] of Object.entries(portalShots)) {
    if (only && !only.has(name)) continue;
    await shot(browser, 'light', name + '.png');
    await shot(browser, 'dark', name + '-dark.png');
  }
} finally {
  await browser.close();
}
const ordered = Object.fromEntries(Object.entries(sidecar).sort(([a], [b]) => a.localeCompare(b)));
await writeFile(sidecarFile, JSON.stringify(ordered, null, 2) + '\n');
