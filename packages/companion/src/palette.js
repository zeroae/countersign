// Window palettes for the Companion. Shared by the main process (window
// background) and the renderer (CSS custom properties), so it uses no Node or
// DOM APIs.
//
// An Integrator's manifest supplies only an accent and a background colour,
// and optionally a dark pair. Every colour the window uses is derived from
// them in OKLCH and then clamped until text and controls meet WCAG AA
// contrast. Warnings, the verified-origin chip and the countersign plate use
// FIXED colours that no manifest can change.

const HEX = /^#[0-9a-f]{6}$/;

function rgb(hex) { return [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255); }
function lin(c) { return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
function unlin(c) { return c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055; }

export function oklch(hex) {
  const [r, g, b] = rgb(hex).map(lin);
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  const L = 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s;
  const A = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s;
  const B = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s;
  let h = Math.atan2(B, A) * 180 / Math.PI;
  if (h < 0) h += 360;
  return { l: L, c: Math.hypot(A, B), h };
}

function linear(L, C, H) {
  const a = C * Math.cos(H * Math.PI / 180), b = C * Math.sin(H * Math.PI / 180);
  const l = Math.pow(L + 0.3963377774 * a + 0.2158037573 * b, 3);
  const m = Math.pow(L - 0.1055613458 * a - 0.0638541728 * b, 3);
  const s = Math.pow(L - 0.0894841775 * a - 1.2914855480 * b, 3);
  return [4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s];
}

const inGamut = v => v.every(x => x >= -0.0005 && x <= 1.0005);

// sRGB hex for an OKLCH colour. Out-of-gamut colours keep their lightness and
// hue and lose chroma until they fit.
export function hex(L, C, H) {
  L = Math.min(1, Math.max(0, L));
  let v = linear(L, C, H);
  if (!inGamut(v)) {
    let lo = 0, hi = C;
    for (let i = 0; i < 24; i++) {
      const mid = (lo + hi) / 2;
      if (inGamut(linear(L, mid, H))) lo = mid; else hi = mid;
    }
    v = linear(L, lo, H);
  }
  return '#' + v.map(x => Math.round(Math.min(1, Math.max(0, unlin(Math.min(1, Math.max(0, x))))) * 255)
    .toString(16).padStart(2, '0')).join('');
}

function luminance(color) {
  const [r, g, b] = rgb(color).map(lin);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

// WCAG 2 contrast ratio of two hex colours.
export function contrast(a, b) {
  const x = luminance(a), y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

// Step lightness in `dir` until the colour reaches `target` contrast against
// every colour in `against`. At the end of the range it returns black or
// white, which always clears the targets used here.
function fit(L, C, H, against, target, dir) {
  const backgrounds = [].concat(against);
  const ok = color => backgrounds.every(bg => contrast(color, bg) >= target);
  let l = L, out = hex(l, C, H);
  for (let i = 0; i < 120 && !ok(out); i++) {
    l += dir * 0.01;
    if (l < 0 || l > 1) return dir < 0 ? '#000000' : '#ffffff';
    out = hex(l, C, H);
  }
  return out;
}

// Warnings, errors, the queue banner and dialogs' destructive buttons.
export function fixedPalette(dark) {
  return dark
    ? { 'warn-bg': '#3a2a05', 'warn-line': '#f5b544', 'warn-ink': '#ffe2a8', ok: '#a1ca7c', danger: '#f08a7a',
      'on-danger': '#2a0905', 'danger-bg': '#3a1410', 'danger-ink': '#ffd7d0', 'note-bg': '#f2eff5',
      'note-ink': '#1b1424', scrim: 'rgba(0,0,0,.6)' }
    : { 'warn-bg': '#fff1d6', 'warn-line': '#b45309', 'warn-ink': '#4a1f00', ok: '#2f7a12', danger: '#a12a1c',
      'on-danger': '#ffffff', 'danger-bg': '#fdecea', 'danger-ink': '#5c130b', 'note-bg': '#1b1424',
      'note-ink': '#ffffff', scrim: 'rgba(20,12,30,.45)' };
}

// Countersign's own theme: purple band, green Approve.
export function countersignPalette(dark) {
  return dark
    ? { band: '#2b0548', 'band-ink': '#ffffff', 'band-muted': '#ddd0ea', underline: '#a1ca7c', ground: '#17131d',
      surface: '#211b29', raised: '#2a2333', ink: '#f0ebf5', muted: '#b9afc4', line: '#3d3447', accent: '#d2b3ea',
      'accent-soft': '#2f2540', primary: '#a1ca7c', 'on-primary': '#11200a', focus: '#8fb8ff', 'hot-bg': '#3b2a4f',
      'hot-ink': '#ecdcfa' }
    : { band: '#2b0548', 'band-ink': '#ffffff', 'band-muted': '#ddd0ea', underline: '#a1ca7c', ground: '#f5f4f7',
      surface: '#ffffff', raised: '#f3f0f6', ink: '#1b1424', muted: '#554c60', line: '#d9d3e0', accent: '#3d1466',
      'accent-soft': '#f1eaf7', primary: '#224805', 'on-primary': '#ffffff', focus: '#2f6fd6', 'hot-bg': '#ece0f6',
      'hot-ink': '#2b0548' };
}

// The full palette for a validated theme ({accent, background, dark?}).
export function derivePalette(theme, dark) {
  const A = oklch(theme.accent), H = A.h, C = Math.max(A.c, 0.02);
  if (!dark) {
    const Bg = oklch(theme.background), gh = Bg.c > 0.004 ? Bg.h : H;
    const ground = hex(0.972, Math.min(Math.max(Bg.c, 0.008), 0.018), gh);
    const surface = '#ffffff';
    const softC = Math.min(C, 0.04), accentSoft = hex(0.95, softC, H);
    const band = fit(Math.min(A.l, 0.42), Math.min(C, 0.14), H, '#ffffff', 7, -1);
    const hotBg = hex(0.92, Math.min(C, 0.06), H);
    return {
      band, 'band-ink': '#ffffff', 'band-muted': fit(0.88, Math.min(C, 0.05), H, band, 4.5, 1),
      underline: fit(0.82, Math.min(C, 0.13), H, band, 4.5, 1),
      ground, surface, raised: hex(0.95, Math.min(C, 0.02), H), ink: hex(0.23, Math.min(C, 0.03), H),
      muted: fit(0.48, Math.min(C, 0.03), H, [ground, surface, accentSoft], 4.5, -1),
      line: hex(0.86, Math.min(C, 0.035), H),
      accent: fit(A.l, A.c, H, [surface, ground, accentSoft], 4.5, -1), 'accent-soft': accentSoft,
      primary: fit(A.l, A.c, H, '#ffffff', 4.5, -1), 'on-primary': '#ffffff',
      focus: fit(0.58, Math.max(C, 0.12), H, [ground, surface], 3, -1), 'hot-bg': hotBg,
      'hot-ink': fit(0.32, C, H, hotBg, 4.5, -1),
    };
  }
  const src = theme.dark;
  const AD = src ? oklch(src.accent) : { l: Math.max(A.l, 0.78), c: Math.min(A.c, 0.13), h: H };
  const BD = src ? oklch(src.background) : { l: 0.19, c: Math.min(C, 0.02), h: H };
  const gl = Math.min(Math.max(BD.l, 0.15), 0.23), gc = Math.min(BD.c, 0.03);
  const ground = hex(gl, gc, BD.h), surface = hex(gl + 0.05, gc, BD.h);
  const accentSoft = hex(gl + 0.08, Math.min(AD.c, 0.05), AD.h);
  const band = fit(0.34, Math.min(AD.c, 0.10), AD.h, '#ffffff', 7, -1);
  const onPrimary = hex(0.18, Math.min(AD.c, 0.03), AD.h);
  const hotBg = hex(0.32, Math.min(AD.c, 0.07), AD.h);
  return {
    band, 'band-ink': '#ffffff', 'band-muted': fit(0.88, Math.min(AD.c, 0.05), AD.h, band, 4.5, 1),
    underline: fit(0.82, Math.min(AD.c, 0.13), AD.h, band, 4.5, 1),
    ground, surface, raised: hex(gl + 0.09, gc, BD.h), ink: hex(0.95, 0.01, AD.h),
    muted: fit(0.78, Math.min(AD.c, 0.02), AD.h, [ground, surface, accentSoft], 4.5, 1),
    line: hex(gl + 0.17, gc, BD.h),
    accent: fit(Math.max(AD.l, 0.7), AD.c, AD.h, [surface, ground, accentSoft], 4.5, 1), 'accent-soft': accentSoft,
    primary: fit(Math.max(AD.l, 0.72), AD.c, AD.h, onPrimary, 4.5, 1), 'on-primary': onPrimary,
    focus: fit(0.75, Math.max(AD.c, 0.12), AD.h, [ground, surface], 3, 1), 'hot-bg': hotBg,
    'hot-ink': fit(0.92, Math.min(AD.c, 0.05), AD.h, hotBg, 4.5, 1),
  };
}

const validColor = value => typeof value === 'string' && HEX.test(value);

// True for a theme the main process normalized: lowercase six-digit hex only.
export function validTheme(theme) {
  if (!theme || typeof theme !== 'object' || !validColor(theme.accent) || !validColor(theme.background)) return false;
  if (theme.dark === undefined || theme.dark === null) return true;
  return typeof theme.dark === 'object' && validColor(theme.dark.accent) && validColor(theme.dark.background);
}

// Every CSS custom property the window uses. Without a valid theme the
// Countersign palette applies. The request-facts card is tinted only with
// clamped palette colours.
export function windowPalette(theme, dark) {
  const branded = validTheme(theme);
  const palette = { ...fixedPalette(dark), ...(branded ? derivePalette(theme, dark) : countersignPalette(dark)) };
  Object.assign(palette, branded
    ? { 'chk-surface': palette['accent-soft'], 'chk-line': palette.accent, 'chk-ink': palette.ink,
      'chk-muted': palette.muted }
    : dark
      ? { 'chk-surface': '#1d1b21', 'chk-line': '#3a3640', 'chk-ink': '#f2eff5', 'chk-muted': '#b9b3c1' }
      : { 'chk-surface': '#ffffff', 'chk-line': '#cfcad6', 'chk-ink': '#1b1424', 'chk-muted': '#4f4859' });
  return palette;
}
