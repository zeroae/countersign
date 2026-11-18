import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { contrast, countersignPalette, derivePalette, fixedPalette, validTheme, windowPalette } from '../src/palette.js';
import { readTheme, refreshTheme, reviewTheme } from '../src/theme.js';
import { headChange, orderQueue } from '../src/queue.js';

const site = 'https://integrator.test';
const manifest = value => async () => Response.json(value);

// Text pairs and their WCAG AA targets. The band carries white text and must
// clear 7:1; focus rings and other non-text marks need 3:1.
const PAIRS = [
  ['band-ink', 'band', 7], ['band-muted', 'band', 4.5], ['underline', 'band', 4.5], ['band', 'underline', 4.5],
  ['ink', 'ground', 4.5], ['ink', 'surface', 4.5], ['ink', 'accent-soft', 4.5], ['muted', 'ground', 4.5],
  ['muted', 'surface', 4.5], ['accent', 'surface', 4.5], ['accent', 'ground', 4.5], ['on-primary', 'primary', 4.5],
  ['focus', 'ground', 3], ['focus', 'surface', 3], ['hot-ink', 'hot-bg', 4.5], ['chk-ink', 'chk-surface', 4.5],
  ['chk-muted', 'chk-surface', 4.5], ['warn-ink', 'warn-bg', 4.5], ['danger-ink', 'danger-bg', 4.5],
  ['on-danger', 'danger', 4.5], ['note-ink', 'note-bg', 4.5],
];

test('derived palettes clamp every text pair to WCAG AA, however hostile the manifest colours', () => {
  const levels = ['00', '1d', '66', '80', '99', 'cc', 'e6', 'ff'];
  const colors = [];
  for (const r of levels) for (const g of levels) for (const b of levels) colors.push('#' + r + g + b);
  const backgrounds = ['#ffffff', '#000000', '#ffff00', '#e6f0f7', '#202020'];
  let checked = 0;
  for (const accent of colors) for (const background of backgrounds) for (const dark of [false, true]) {
    for (const theme of [{ accent, background }, { accent, background, dark: { accent: background, background: accent } }]) {
      const palette = windowPalette(theme, dark);
      for (const value of Object.values(palette)) assert.match(value, /^(#[0-9a-f]{6}|rgba\([\d,. ]+\))$/);
      for (const [fg, bg, target] of PAIRS) {
        const ratio = contrast(palette[fg], palette[bg]);
        assert.ok(ratio >= target, `${fg} on ${bg} is ${ratio.toFixed(2)} for ${JSON.stringify(theme)} dark=${dark}`);
        checked++;
      }
    }
  }
  assert.ok(checked > 100000);
});

test('the Countersign theme applies without a valid theme, and fixed colours never follow a manifest', () => {
  for (const dark of [false, true]) {
    for (const invalid of [null, undefined, {}, { accent: 'red', background: '#ffffff' },
      { accent: '#ABCDEF', background: '#ffffff' }, { accent: '#123456', background: '#ffffff', dark: { accent: '#123456' } },
      { accent: '#123456', background: 'url(x)' }]) {
      assert.equal(validTheme(invalid), false);
      assert.deepEqual(windowPalette(invalid, dark), windowPalette(null, dark));
    }
    const branded = windowPalette({ accent: '#ff00ff', background: '#00ff00' }, dark);
    for (const [key, value] of Object.entries(fixedPalette(dark))) assert.equal(branded[key], value);
    assert.equal(windowPalette(null, dark).band, countersignPalette(dark).band);
    assert.equal(countersignPalette(dark).band, '#2b0548');
  }
  assert.equal(countersignPalette(false).primary, '#224805');
  assert.equal(countersignPalette(true).primary, '#a1ca7c');
});

test('colors.dark drives the dark palette; without it the dark palette is derived', () => {
  const light = { accent: '#1d5f8a', background: '#e6f0f7' };
  const derived = derivePalette(light, true);
  const teal = derivePalette({ ...light, dark: { accent: '#5cc8bd', background: '#0f1f1e' } }, true);
  assert.notDeepEqual(derived, teal);
  assert.deepEqual(derivePalette(light, false), derivePalette({ ...light, dark: { accent: '#5cc8bd', background: '#0f1f1e' } }, false));
  // Dark grounds stay dark even when a manifest asks for a light one.
  const bright = derivePalette({ ...light, dark: { accent: '#ffffff', background: '#ffffff' } }, true);
  assert.ok(contrast(bright.ground, '#000000') < 3);
});

test('the manifest accepts an optional colors.dark pair, validated like the other colours', async () => {
  const base = { version: 1, displayName: 'Example', colors: { accent: '#164E63', background: '#FFFFFF' } };
  const plain = await readTheme(site, manifest(base));
  assert.equal(Object.hasOwn(plain, 'dark'), false);
  // Manifests without dark colours keep the digest they had before the field existed.
  const { digest, ...fields } = plain;
  assert.deepEqual(Object.keys(fields), ['name', 'copy', 'accent', 'background', 'logo']);
  assert.equal(digest, createHash('sha256').update(JSON.stringify(fields)).digest('hex'));

  const withDark = await readTheme(site, manifest({ ...base, colors: { ...base.colors, dark: { accent: '#5CC8BD', background: '#0f1f1e' } } }));
  assert.deepEqual(withDark.dark, { accent: '#5cc8bd', background: '#0f1f1e' });
  assert.equal(withDark.accent, '#164e63');
  assert.notEqual(withDark.digest, plain.digest);
  const otherDark = await readTheme(site, manifest({ ...base, colors: { ...base.colors, dark: { accent: '#5cc8bd', background: '#101f1e' } } }));
  assert.notEqual(otherDark.digest, withDark.digest);
  // A dark-colour change alone is a branding change that needs review.
  assert.equal(refreshTheme({ theme: withDark, pendingTheme: null }, otherDark).pendingTheme, otherDark);

  for (const dark of [null, '#000000', [], { accent: '#5cc8bd' }, { background: '#0f1f1e' },
    { accent: '#5cc8bd', background: 'black' }, { accent: '#5cc8bd', background: '#0f1f1e;color:red' },
    { accent: 'var(--x)', background: '#0f1f1e' }]) {
    await assert.rejects(readTheme(site, manifest({ ...base, colors: { ...base.colors, dark } })), JSON.stringify(dark));
  }
});

test('Keep current dismisses a branding change until the Integrator changes it again', async () => {
  const { Session } = await import('../src/session.js');
  const theme = await readTheme(site, manifest({ version: 1, displayName: 'Example' }));
  const proposed = await readTheme(site, manifest({ version: 1, displayName: 'Example', copy: 'New copy' }));
  const later = await readTheme(site, manifest({ version: 1, displayName: 'Example', copy: 'Other copy' }));
  let stored = { id: 'local', origin: site, pairing: 'p', theme, pendingTheme: proposed };
  const store = { get: () => structuredClone(stored), update: async (_id, change) => { stored = change(structuredClone(stored)); } };
  const session = new Session({ record: store.get(), store });
  let changed = 0;
  session.on('changed', () => changed++);

  await assert.rejects(session.reviewBrand('stale-digest', false), /Branding changed/);
  assert.equal(stored.pendingTheme.digest, proposed.digest);
  await session.reviewBrand(proposed.digest, false);
  assert.equal(stored.theme.digest, theme.digest);
  assert.equal(stored.pendingTheme, null);
  assert.equal(stored.declinedTheme, proposed.digest);
  assert.equal(session.record.pendingTheme, null);
  assert.equal(changed, 1);
  // The same download on reconnect is not offered again; a further change is.
  assert.equal(refreshTheme(stored, proposed).pendingTheme, null);
  assert.equal(refreshTheme(stored, later).pendingTheme, later);
  assert.equal(refreshTheme(stored, theme).declinedTheme, null);
  await assert.rejects(session.reviewBrand(proposed.digest, true), /Branding changed/);

  stored = refreshTheme(stored, later);
  await session.reviewBrand(later.digest, true);
  assert.equal(stored.theme.digest, later.digest);
  assert.equal(stored.pendingTheme, null);
  assert.throws(() => reviewTheme({ ...stored }, later.digest, true), /Branding changed/);
  session.stop();
});

test('requests queue oldest first and a change of Integrator is announced and locks Approve', () => {
  const offers = [
    { handle: 'c', received: 30, pairing: 'one', origin: 'https://one.example' },
    { handle: 'b', received: 10, pairing: 'two', origin: 'https://two.example:8443' },
    { handle: 'a', received: 30, pairing: 'one', origin: 'https://one.example' },
    { handle: 'd', received: 20, pairing: 'one', origin: 'https://one.example' },
  ];
  assert.deepEqual(orderQueue(offers).map(o => o.handle), ['b', 'd', 'a', 'c']);
  assert.deepEqual(offers.map(o => o.handle), ['c', 'b', 'a', 'd']);

  const [b, d, a] = orderQueue(offers);
  assert.deepEqual(headChange(null, b), { lock: true, banner: null });
  assert.deepEqual(headChange(b, b), { lock: false, banner: null });
  assert.deepEqual(headChange(d, a), { lock: true, banner: null });
  assert.deepEqual(headChange(b, d), { lock: true, banner: 'Now showing a request from one.example' });
  assert.deepEqual(headChange(d, b), { lock: true, banner: 'Now showing a request from two.example:8443' });
  assert.deepEqual(headChange(b, undefined), { lock: false, banner: null });
});
