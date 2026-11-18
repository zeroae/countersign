import { validTheme, windowPalette } from './palette.js';
import { headChange, LOCK_MS, originHost } from './queue.js';

const api = window.countersign;
const $ = id => document.getElementById(id);
const SVG = 'http://www.w3.org/2000/svg';
const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

// Local state. Everything that can approve lives in the main process; this
// only remembers what the person is looking at and has chosen so far.
const view = { tab: null, detail: null, flash: '' };
const choices = new Map(); // offer handle -> { reference, preset, minutes }
let state = null;          // last snapshot
let known = null;          // offer handles already seen
let confirmationSeen = null;
let shown = null;          // the request last drawn in the approval view
let lockedUntil = 0, banner = null, bannerUntil = 0, timer;
let decided = null;        // { offer, approved, until, cert } after this window decided
let originDraft = '';
let confirmed = null;      // enrollment the person confirmed, while it finishes
let appearance;

// ------------------------------------------------------------------ helpers
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function icon(kind) {
  const paths = {
    shield: ['M12 3l7 3v5c0 4.5-3 8.4-7 10-4-1.6-7-5.5-7-10V6z', 'M8.5 12l2.5 2.5 4.5-5'],
    shieldEmpty: ['M12 3l7 3v5c0 4.5-3 8.4-7 10-4-1.6-7-5.5-7-10V6z'],
    warning: ['M12 3l9.5 17h-19z', 'M12 10v4.5', 'M12 17.5v.5'],
    error: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z', 'M12 7.5v5.5', 'M12 16.5v.5'],
    check: ['M5 12.5l4.5 4.5L19 7.5'],
    arrow: ['M4 12h14', 'M13 6l6 6-6 6'],
  };
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', 'ico');
  for (const d of paths[kind]) {
    const path = document.createElementNS(SVG, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

function feedback(text) {
  $('feedback').replaceChildren(...(text ? [icon('error'), element('span', text)] : []));
}

async function run(action) {
  try {
    feedback('');
    await action();
  } catch {
    feedback('This action could not be completed. Check the connection and try again.');
  }
}

function button(label, action, className = 'btn') {
  const node = element('button', label, className);
  node.type = 'button';
  node.addEventListener('click', () => run(async () => {
    await action();
    draw();
  }));
  return node;
}

// FIXED component for warnings and errors: icon, title and text in colours
// no theme sets.
function alert(kind, title, text) {
  const box = element('div', undefined, 'alert ' + kind);
  box.setAttribute('role', kind === 'danger' ? 'alert' : 'note');
  const body = element('p');
  body.append(element('strong', title), document.createTextNode(text));
  box.append(icon(kind === 'danger' ? 'error' : 'warning'), body);
  return box;
}

function fact(term, value, className = '', mono = false) {
  const row = element('div', undefined, ('fact ' + className).trim());
  row.append(element('dt', term), element('dd', value, mono ? 'mono' : undefined));
  return row;
}

function checkedFacts(rows) {
  const section = element('section', undefined, 'verified');
  section.setAttribute('aria-label', 'Checked by Countersign');
  const head = element('p', undefined, 'verified-head');
  head.append(icon('shield'), document.createTextNode('Checked by Countersign'));
  const list = element('dl', undefined, 'facts');
  list.append(...rows);
  section.append(head, list);
  return section;
}

const time = ms => new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
const shortDate = ms => new Date(ms).toLocaleDateString([], { month: 'short', day: 'numeric' });
const dateTime = ms => new Date(ms).toLocaleString([], { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
function day(ms) {
  const start = d => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const diff = Math.round((start(new Date(ms)) - start(new Date())) / 86400000);
  return diff === 0 ? 'today, ' + shortDate(ms) : diff === 1 ? 'tomorrow, ' + shortDate(ms) : shortDate(ms);
}
function span(seconds) {
  if (seconds < 3600) return Math.max(1, Math.round(seconds / 60)) + ' min';
  const hours = Math.floor(seconds / 3600), minutes = Math.round((seconds % 3600) / 60);
  return minutes ? hours + ' h ' + minutes + ' min' : hours + ' h';
}
const groups = hex => hex.match(/.{1,4}/g) ?? [];
const branded = theme => validTheme(theme) && typeof theme.name === 'string';

// ------------------------------------------------------------------ theming
function applyTheme(theme, pairing, host) {
  const palette = windowPalette(branded(theme) ? theme : null, darkQuery.matches);
  for (const [key, value] of Object.entries(palette)) document.documentElement.style.setProperty('--' + key, value);
  const own = branded(theme);
  $('brand-countersign').hidden = own;
  $('brand-integrator').hidden = !own;
  if (own) {
    $('int-name').textContent = theme.name;
    $('int-copy').textContent = theme.copy || '';
    const logo = $('int-logo');
    const png = typeof theme.logo === 'string' && theme.logo.startsWith('data:image/png;base64,');
    logo.hidden = !png;
    if (png) logo.src = theme.logo; else logo.removeAttribute('src');
    $('int-origin').replaceChildren(icon('check'), element('span', host), document.createTextNode(' '), element('b', 'verified'));
    $('int-origin').setAttribute('aria-label', 'Verified origin ' + host);
  }
  const id = own ? pairing : null;
  if (id !== appearance) {
    appearance = id;
    void api.appearance(id).catch(() => {});
  }
}

// --------------------------------------------------------------- approvals
const PRESETS = [{ id: '15m', label: '15 min', seconds: 900 }, { id: '1h', label: '1 h', seconds: 3600 },
  { id: '8h', label: '8 h', seconds: 28800 }, { id: 'custom', label: 'Custom' }];

function choiceFor(offer) {
  let choice = choices.get(offer.handle);
  if (!choice) {
    const preset = PRESETS.find(p => p.seconds === offer.defaultDuration && p.seconds <= offer.maxDuration);
    choice = { reference: null, preset: preset ? preset.id : 'custom',
      minutes: String(Math.max(1, Math.round(Math.min(offer.defaultDuration, offer.maxDuration) / 60))) };
    choices.set(offer.handle, choice);
  }
  if (offer.identities.length === 1) choice.reference = offer.identities[0].reference;
  return choice;
}

function seconds(offer, choice) {
  if (choice.preset !== 'custom') return PRESETS.find(p => p.id === choice.preset).seconds;
  const minutes = Number(choice.minutes);
  return Number.isSafeInteger(minutes) ? minutes * 60 : NaN;
}

// Where the first fingerprint among same-named certificates differs.
function divergence(cert, identities) {
  const others = identities.filter(other => other !== cert && other.identity === cert.identity);
  if (!others.length) return -1;
  let first = 64;
  for (const other of others) {
    let i = 0;
    while (i < 64 && other.fingerprint[i] === cert.fingerprint[i]) i++;
    first = Math.min(first, i);
  }
  return first;
}

function identicon(fingerprint) {
  const hue = parseInt(fingerprint.slice(0, 3), 16) % 360;
  const on = darkQuery.matches ? 'hsl(' + hue + ' 60% 68%)' : 'hsl(' + hue + ' 55% 40%)';
  const grid = element('span', undefined, 'idc');
  grid.setAttribute('aria-hidden', 'true');
  for (let row = 0; row < 5; row++) for (let column = 0; column < 5; column++) {
    const cell = element('span');
    const mirrored = column < 3 ? column : 4 - column;
    if (parseInt(fingerprint[3 + row * 3 + mirrored], 16) % 2 === 0) cell.style.background = on;
    grid.append(cell);
  }
  return grid;
}

function certificateCard(offer, cert, choice) {
  const label = element('label', undefined, 'cert identity');
  const input = element('input');
  input.type = 'radio';
  input.name = 'certificate';
  input.dataset.key = 'cert-' + cert.reference;
  input.checked = choice.reference === cert.reference;
  input.addEventListener('change', () => { choice.reference = cert.reference; draw(); });
  const body = element('span', undefined, 'cert-body');
  const fp = element('span', undefined, 'fp');
  fp.append(element('span', 'SHA-256', 'fp-label'));
  const first = divergence(cert, offer.identities);
  groups(cert.fingerprint).forEach((text, i) => {
    const start = i * 4;
    fp.append(element('span', text, 'fp-g' + (first >= 0 && start + 4 > first && start < first + 8 ? ' hot' : '')));
  });
  body.append(element('span', cert.identity, 'cert-name'),
    element('span', 'Issued by ' + cert.issuer + ' · valid until ' + dateTime(cert.expiresAt), 'cert-meta'), fp);
  label.append(input, identicon(cert.fingerprint), body);
  return label;
}

function approvalView(offer, locked) {
  const pad = element('div', undefined, 'pad');
  pad.id = 'requests';
  if (banner && Date.now() < bannerUntil) {
    const note = element('p', undefined, 'switch-banner');
    note.setAttribute('role', 'status');
    note.append(icon('arrow'), document.createTextNode(banner));
    pad.append(note);
  }
  const waiting = state.offers.length - 1;
  const queue = element('div', undefined, 'queue');
  queue.setAttribute('role', 'status');
  const position = element('span');
  position.append(element('strong', 'Request 1 of ' + state.offers.length), document.createTextNode(' · oldest first'));
  queue.append(position, element('span', waiting ? waiting + ' more waiting' : 'No others waiting'));
  pad.append(queue, element('p', 'Approval request', 'eyebrow'), element('h1', 'Let this job use a client certificate?', 'h1'));

  const wide = offer.scope !== offer.host;
  const facts = checkedFacts([fact('Integrator', offer.origin, 'fact-origin', true), fact('Account', offer.user),
    fact('Context', offer.context), fact('Requested host', offer.host, '', true),
    fact('Approval covers', offer.scope, wide ? 'is-wide' : '', true)]);
  if (wide) facts.append(alert('warning', 'This approval covers more than the requested host.',
    'Any host matching ' + offer.scope + ' can use the certificate until access ends. Deny if you only meant ' + offer.host + '.'));
  pad.append(facts);
  if (!branded(offer.theme)) pad.append(element('p', 'This Integrator has not provided branding, so Countersign\'s own theme is shown.', 'nobrand'));

  const choice = choiceFor(offer);
  const { identities } = offer;
  const selected = identities.find(cert => cert.reference === choice.reference) ?? null;
  const picker = element('fieldset', undefined, 'certs');
  picker.append(element('legend', 'Certificate', 'legend'));
  const sameName = identities.length > 1 && identities.every(cert => cert.identity === identities[0].identity);
  if (sameName) picker.append(element('p', identities.length + ' certificates are named ' + identities[0].identity +
    '. Compare the highlighted part of each fingerprint and the pattern beside it.', 'note'));
  for (const cert of identities) picker.append(certificateCard(offer, cert, choice));
  if (!identities.length) picker.append(offer.providerUnavailable
    ? alert('danger', 'The certificate provider is unavailable', 'Unlock or reconnect it, then request access again from the job. On Linux, check that p11-kit sees the token in this login session.')
    : alert('warning', 'No eligible certificate on this computer', 'A certificate must allow client authentication, have its private key here, and match the issuers this destination accepts. Ask the Integrator which certificate it expects, or deny this request.'));
  pad.append(picker);

  const duration = seconds(offer, choice);
  const validDuration = Number.isSafeInteger(duration) && duration >= 1 && duration <= offer.maxDuration;
  const now = Date.now();
  const end = now + (validDuration ? duration : 0) * 1000;
  const until = selected ? Math.min(end, selected.expiresAt) : end;
  if (identities.length) {
    const group = element('div');
    group.setAttribute('role', 'group');
    group.setAttribute('aria-labelledby', 'duration-title');
    const title = element('p', 'How long?', 'legend');
    title.id = 'duration-title';
    const seg = element('div', undefined, 'seg');
    for (const preset of PRESETS) {
      const node = element('button', preset.label, 'seg-btn');
      node.type = 'button';
      node.dataset.key = 'preset-' + preset.id;
      node.disabled = !!preset.seconds && preset.seconds > offer.maxDuration;
      node.setAttribute('aria-pressed', String(choice.preset === preset.id));
      node.addEventListener('click', () => { choice.preset = preset.id; draw(); });
      seg.append(node);
    }
    group.append(title, seg);
    if (choice.preset === 'custom') {
      const custom = element('div', undefined, 'custom');
      const label = element('label', 'Minutes');
      const input = element('input');
      input.type = 'number';
      input.min = '1';
      input.max = String(Math.floor(offer.maxDuration / 60));
      input.value = choice.minutes;
      input.dataset.key = 'minutes';
      input.addEventListener('input', () => { choice.minutes = input.value; draw(); });
      label.append(input);
      custom.append(label, element('span', 'Up to ' + span(offer.maxDuration), 'hint'));
      group.append(custom);
    }
    if (PRESETS.some(p => p.seconds > offer.maxDuration)) {
      group.append(element('p', 'Your administrator allows up to ' + span(offer.maxDuration) + ', so longer presets are unavailable.', 'small-note'));
    }
    const ends = element('div', undefined, 'expires');
    ends.setAttribute('aria-live', 'polite');
    ends.append(element('span', 'Access ends', 'expires-label'), element('span', validDuration ? time(until) : '—', 'expires-time'),
      element('span', validDuration ? day(until) + ' · in ' + span(Math.round((until - now) / 1000)) : 'Choose a duration', 'expires-day'));
    group.append(ends);
    if (selected && validDuration && selected.expiresAt < end) {
      group.append(alert('warning', 'Shortened to the certificate\'s expiry',
        'This certificate expires at ' + time(selected.expiresAt) + ' ' + day(selected.expiresAt) + ', so access ends then.'));
    }
    pad.append(group);
  }
  pad.append(element('p', 'Until access ends, the Integrator\'s Gateway can read and send traffic to ' + offer.scope + ' using this certificate.', 'consequence'));

  let reason;
  if (locked) reason = 'Approve unlocks in a moment: ' + (banner && Date.now() < bannerUntil ? 'this request is from a different Integrator.' : 'this request just arrived.');
  else if (!identities.length) reason = 'No certificate can be approved for this request. You can deny it.';
  else if (!selected) reason = 'Choose a certificate to continue.';
  else if (!validDuration) reason = 'Choose a duration up to ' + span(offer.maxDuration) + '.';
  else if (until <= now) reason = 'This certificate has expired.';
  else reason = 'Approves ' + selected.identity + ' (' + groups(selected.fingerprint.slice(0, 8)).join(' ') + ') for ' + span(Math.round((until - now) / 1000)) + '.';
  const disabled = locked || !selected || !validDuration || until <= now;

  const actions = element('div', undefined, 'actions');
  const deny = button('Deny', async () => {
    await api.deny(offer.handle);
    decided = { offer, approved: false };
    shown = { handle: offer.handle, pairing: offer.pairing };
  }, 'btn decision');
  const approve = button('Approve', async () => {
    if (Date.now() < lockedUntil) return;
    await api.decide(offer.handle, selected.reference, duration);
    decided = { offer, approved: true, until, cert: selected };
    shown = { handle: offer.handle, pairing: offer.pairing };
  }, 'btn decision primary');
  approve.disabled = disabled;
  approve.dataset.key = 'approve';
  deny.dataset.key = 'deny';
  const why = element('p', reason, 'reason');
  why.id = 'reason';
  actions.append(why, deny, approve);
  return [pad, actions];
}

function resultView() {
  const pad = element('div', undefined, 'pad');
  pad.id = 'requests';
  const { offer, approved, until, cert } = decided;
  const host = originHost(offer.origin);
  pad.append(element('p', approved ? 'Approved' : 'Denied', 'eyebrow'),
    element('h1', approved ? 'The job can use your certificate' : 'Request denied', 'h1'));
  const box = element('div', undefined, 'result');
  if (approved) {
    box.append(element('p', host + ' can use ' + cert.identity + ' (' + groups(cert.fingerprint.slice(0, 8)).join(' ') +
      ') for ' + offer.scope + ' until ' + time(until) + ' ' + day(until) + '.'),
    element('p', 'Waiting for the Gateway. The approval shows Ready for handshakes under Integrators once the first handshake is signed.', 'small-note'));
  } else {
    box.append(element('p', host + ' can request access again after it changes the request.'));
  }
  pad.append(box);
  const next = state.offers[0];
  const row = element('div', undefined, 'btnrow');
  row.append(next
    ? button('Next request · ' + originHost(next.origin), () => { decided = null; draw(); }, 'btn primary')
    : button('View Integrators', () => go('integrators'), 'btn'));
  pad.append(row);
  return [pad];
}

function idleView() {
  const idle = element('div', undefined, 'idle');
  idle.id = 'requests';
  idle.append(icon('shieldEmpty'), element('h1', 'No pending requests'),
    element('p', 'When a job asks to use one of your certificates, it opens here and Countersign notifies you. Closing this window keeps Countersign running in the tray.'));
  if (!state.pairings.length) idle.append(button('Pair an Integrator', () => go('integrators'), 'btn'));
  return [idle];
}

// ------------------------------------------------------------- integrators
function pairingView(enrollment, confirmation) {
  const pad = element('div', undefined, 'pad');
  pad.id = 'pairing';
  const origin = confirmation?.origin ?? enrollment.origin;
  const host = originHost(origin);
  const code = confirmation?.code ?? enrollment?.code;
  pad.append(element('p', 'Pairing request', 'eyebrow'),
    element('h1', confirmation ? 'Confirm this pairing?' : enrollment.id === confirmed ? 'Finishing the pairing' :
      code ? 'Enter this code in your browser' : 'Connecting to ' + host, 'h1'));
  const rows = [fact('Integrator', origin, 'fact-origin', true)];
  if (confirmation) rows.push(fact('Account', confirmation.user));
  pad.append(checkedFacts(rows));
  if (code && enrollment?.id !== confirmed) {
    const box = element('div', undefined, 'code-box');
    const value = element('p', groups(code).join(' '), 'code');
    value.setAttribute('aria-label', 'Pairing code ' + code.split('').join(' '));
    box.append(element('p', 'Pairing code', 'eyebrow'), value, element('p', confirmation
      ? 'Check that your browser shows the same code for this account, then confirm here. If anything differs, cancel.'
      : 'Countersign opened ' + host + ' in your browser. Sign in there and enter this code.', 'small-note'));
    pad.append(box);
  } else if (enrollment?.id === confirmed) {
    pad.append(element('p', 'Waiting for ' + host + ' to finish. The Integrator appears under Paired Integrators once it connects.', 'small-note'));
  } else if (enrollment) {
    pad.append(element('p', enrollment.status, 'small-note'));
  }
  if (!confirmation) return [pad];
  const actions = element('div', undefined, 'actions');
  actions.append(element('p', 'Pairing lets ' + host + ' send you approval requests. It cannot approve anything by itself.', 'reason'),
    button('Cancel pairing', () => api.confirmPair(confirmation.id, false), 'btn outline'),
    button('Confirm pairing', async () => {
      await api.confirmPair(confirmation.id, true);
      confirmed = confirmation.pairing;
      view.detail = null;
    }, 'btn primary'));
  return [pad, actions];
}

function swatch(theme) {
  const chip = element('span', undefined, 'swatch');
  chip.setAttribute('aria-hidden', 'true');
  chip.style.background = windowPalette(branded(theme) ? theme : null, darkQuery.matches).primary;
  return chip;
}

function statusOf(pairing) {
  const node = element('span', undefined, 'status ' + (pairing.status === 'Connected' ? 'st-ok' : 'st-muted'));
  node.append(element('span', undefined, 'dot'), document.createTextNode(pairing.status));
  return node;
}

function flash(pad) {
  if (!view.flash) return;
  const note = element('p', view.flash, 'flash');
  note.setAttribute('role', 'status');
  pad.append(note);
}

function listView() {
  const pad = element('div', undefined, 'pad');
  flash(pad);
  pad.append(element('h1', 'Paired Integrators', 'h1'));
  const list = element('div');
  list.id = 'pairs';
  for (const pairing of state.pairings) {
    const row = element('button', undefined, 'int-row');
    row.type = 'button';
    row.dataset.key = 'pairing-' + pairing.id;
    const title = element('span', undefined, 'card-title');
    const count = pairing.approvals.length;
    const summary = pairing.pendingTheme ? 'branding change to review' : count + (count === 1 ? ' approval' : ' approvals');
    title.append(element('strong', pairing.origin, 'mono'),
      element('span', [branded(pairing.theme) ? pairing.theme.name : null, pairing.user, summary].filter(Boolean).join(' · ')));
    const chevron = element('span', '›', 'chev');
    chevron.setAttribute('aria-hidden', 'true');
    row.append(swatch(pairing.theme), title, statusOf(pairing), chevron);
    row.addEventListener('click', () => { view.detail = pairing.id; view.flash = ''; draw(); });
    list.append(row);
  }
  if (!state.pairings.length) list.append(element('p', 'No Integrators are paired with this computer yet.', 'note'));
  pad.append(list, element('p', state.pairings.length ? 'Pair another Integrator' : 'Pair an Integrator', 'sub'));
  const form = element('form', undefined, 'form');
  form.id = 'pair';
  const label = element('label', 'Integrator origin');
  const input = element('input');
  input.id = 'origin';
  input.type = 'url';
  input.placeholder = 'https://integrator.example';
  input.required = true;
  input.value = originDraft;
  input.dataset.key = 'origin';
  input.addEventListener('input', () => { originDraft = input.value; });
  label.append(input);
  const submit = element('button', 'Pair', 'btn');
  submit.type = 'submit';
  form.append(label, submit);
  form.addEventListener('submit', event => {
    event.preventDefault();
    void run(async () => {
      await api.pair(input.value);
      originDraft = '';
      draw();
    });
  });
  pad.append(form, element('p', 'Countersign opens the Integrator in your browser. Sign in there and enter the code shown here.', 'small-note'));
  return [pad];
}

// A small copy of the header band a branding would draw.
function preview(theme) {
  if (!branded(theme)) return element('p', 'This branding cannot be shown.', 'note');
  const box = element('div', undefined, 'preview');
  const palette = windowPalette(theme, darkQuery.matches);
  const band = element('div', undefined, 'preview-band');
  band.style.background = palette.band;
  if (typeof theme.logo === 'string' && theme.logo.startsWith('data:image/png;base64,')) {
    const logo = element('img');
    logo.alt = '';
    logo.src = theme.logo;
    band.append(logo);
  }
  const text = element('div');
  const copy = element('span', theme.copy || 'No description');
  copy.style.color = palette['band-muted'];
  text.append(element('strong', theme.name), copy);
  band.append(text);
  const colors = element('div', undefined, 'preview-colors');
  const swatchOf = (label, value) => {
    const item = element('span');
    const chip = element('i');
    if (/^#[0-9a-f]{6}$/.test(value)) chip.style.background = value;
    item.append(chip, document.createTextNode(label + ' ' + value));
    return item;
  };
  colors.append(swatchOf('accent', theme.accent), swatchOf('background', theme.background));
  if (theme.dark) colors.append(swatchOf('dark accent', theme.dark.accent), swatchOf('dark background', theme.dark.background));
  box.append(band, colors);
  return box;
}

function openDialog({ title, body, confirm, danger, action }) {
  const dialog = $('dialog');
  $('dialog-title').textContent = title;
  $('dialog-body').textContent = body;
  const ok = $('dialog-confirm');
  ok.textContent = confirm;
  ok.className = 'btn ' + (danger ? 'danger' : 'primary');
  ok.onclick = () => { dialog.close(); void run(action); };
  $('dialog-cancel').onclick = () => dialog.close();
  dialog.showModal();
  $('dialog-cancel').focus();
}

function detailView(pairing) {
  const pad = element('div', undefined, 'pad');
  const host = originHost(pairing.origin);
  const back = element('div', undefined, 'btnrow');
  back.style.margin = '0 0 12px';
  back.append(button('‹ All Integrators', () => { view.detail = null; view.flash = ''; draw(); }, 'btn small'));
  pad.append(back);
  flash(pad);
  const card = element('article', undefined, 'card');
  card.id = 'detail';
  const head = element('div', undefined, 'card-head');
  const title = element('span', undefined, 'card-title');
  title.append(element('strong', pairing.origin, 'mono'),
    element('span', [branded(pairing.theme) ? pairing.theme.name : 'No branding', pairing.user].join(' · ')));
  head.append(swatch(pairing.theme), title, statusOf(pairing));
  card.append(head);

  for (const notice of pairing.notices) {
    card.append(alert('warning', notice.kind === 'concurrent_devices' ? 'Another Companion connected to this account' : 'Companion security event',
      dateTime(notice.occurred_at_ms) + ' from ' + (notice.observed_address || 'an unknown address') +
      (notice.actor?.pairing ? ', device ' + notice.actor.pairing : '') + '. Check the devices below.'));
  }

  if (pairing.pendingTheme) {
    card.append(element('p', 'Branding change to review', 'sub'));
    const review = element('div', undefined, 'review');
    const current = element('div');
    current.append(element('p', 'Current', 'caption'), pairing.theme ? preview(pairing.theme) : element('p', 'No branding', 'note'));
    const proposed = element('div');
    proposed.append(element('p', 'Proposed by ' + host, 'caption'), preview(pairing.pendingTheme));
    review.append(current, proposed);
    card.append(review, element('p', 'Accepting also changes the colours this whole window takes on for ' + host + '.', 'small-note'));
    const row = element('div', undefined, 'btnrow');
    const digest = pairing.pendingTheme.digest;
    row.append(button('Accept new branding', async () => {
      await api.theme(pairing.id, digest);
      view.flash = 'New branding accepted for ' + host + '.';
    }, 'btn small'), button('Keep current', async () => {
      await api.keepTheme(pairing.id, digest);
      view.flash = 'Kept the current branding for ' + host + '.';
    }, 'btn small'));
    card.append(row);
  }

  if (pairing.approvals.length) {
    card.append(element('p', 'Approvals', 'sub'));
    for (const approval of pairing.approvals) {
      const status = approval.revocation === 'pending' ? 'Revocation queued for Broker confirmation' :
        approval.revocation === 'recorded' ? 'Broker recorded revocation. Existing traffic ends at its lease deadline' :
          approval.ready ? 'Ready for handshakes' : 'Approved on this device';
      const tone = approval.revocation === 'pending' ? 'st-warn' : approval.revocation === 'recorded' ? '' : approval.ready ? 'st-ok' : '';
      const row = element('div', undefined, 'row');
      const main = element('div', undefined, 'row-main');
      main.append(element('strong', approval.host, 'mono'),
        element('span', approval.context + ' · covers ' + approval.scope + ' · SHA-256 ' + groups(approval.fingerprint.slice(0, 8)).join(' ')),
        element('span', status + ' · ends ' + time(approval.until) + ' ' + day(approval.until), tone || undefined));
      row.append(main);
      if (approval.revocation !== 'recorded') {
        row.append(button(approval.revocation ? 'Retry revocation' : 'Revoke access', () => api.revoke(pairing.id, approval.id), 'btn small'));
      }
      card.append(row);
    }
  }

  const others = pairing.devices.filter(device => !device.self);
  const disconnect = (devices, all) => () => api.forgetOthers(pairing.id, devices.map(d => d.binding), all);
  if (pairing.devices.length) {
    card.append(element('p', 'Companions on this account', 'sub'));
    for (const device of pairing.devices) {
      const row = element('div', undefined, 'row');
      const main = element('div', undefined, 'row-main');
      const name = element('strong', device.binding.pairing, 'mono');
      if (device.self) name.append(element('span', 'This computer', 'tag'));
      main.append(name, element('span', (device.connected ? 'Connected' : 'Offline') + ' · ' + (device.observed_address || 'Address unavailable')));
      row.append(main);
      if (!device.self) {
        row.append(button('Disconnect device', () => openDialog({
          title: 'Disconnect device ' + device.binding.pairing + '?',
          body: 'Its grants for ' + pairing.origin + ' are revoked. Traffic it already has stops by its current lease deadline.',
          confirm: 'Disconnect device', danger: true, action: async () => {
            await disconnect([device], false)();
            view.flash = 'Disconnect requested for ' + device.binding.pairing + '. Its grants are revoked.';
          },
        }), 'btn small'));
      }
      card.append(row);
    }
  }

  const row = element('div', undefined, 'btnrow');
  if (others.length > 1) {
    row.append(button('Disconnect all other devices', () => openDialog({
      title: 'Disconnect all other devices?',
      body: 'Every other Companion paired to ' + pairing.user + ' at ' + pairing.origin + ' loses its pairing and grants. This computer stays paired.',
      confirm: 'Disconnect all others', danger: true, action: async () => {
        await disconnect(others, true)();
        view.flash = 'Disconnect requested for every other device.';
      },
    }), 'btn small'));
  }
  row.append(button('Revoke pairing at Integrator', () => openDialog({
    title: 'Revoke this pairing at ' + host + '?',
    body: 'Countersign opens ' + pairing.origin + '/countersign/devices in your browser. Choose the pairing to forget there; its grants end with it.',
    confirm: 'Open in browser', danger: false, action: async () => {
      await api.forget(pairing.id);
      view.flash = 'Opened the device page of ' + host + ' in your browser.';
    },
  }), 'btn small'), button('Remove from this computer', () => openDialog({
    title: 'Remove ' + host + ' from this computer?',
    body: 'Deletes this computer\'s pairing key for ' + pairing.origin + '. Access already granted stays active until you revoke it at the Integrator.',
    confirm: 'Remove from this computer', danger: true, action: async () => {
      await api.removeLocal(pairing.id);
      view.detail = null;
      view.flash = 'Removed ' + host + ' from this computer.';
    },
  }), 'btn small'));
  card.append(row);
  pad.append(card);
  return [pad];
}

function settingsView() {
  const pad = element('div', undefined, 'pad');
  pad.append(element('h1', 'Settings', 'h1'));
  const login = element('div', undefined, 'card');
  const label = element('label', undefined, 'check');
  const box = element('input');
  box.type = 'checkbox';
  box.id = 'login';
  box.checked = state.login;
  box.dataset.key = 'login';
  box.addEventListener('change', () => run(() => api.login(box.checked)));
  const text = element('span', 'Start at login');
  text.append(element('span', 'Receive requests as soon as you sign in to this computer.'));
  label.append(box, text);
  login.append(label);
  const appearanceCard = element('div', undefined, 'card');
  appearanceCard.append(element('p', 'Appearance', 'card-title-plain'), element('p',
    'Follows your system\'s light or dark setting. While an Integrator\'s request, pairing or details are open, the window uses that Integrator\'s colours.', 'small-note'));
  const quit = element('div', undefined, 'card');
  quit.append(element('p', 'Closing and quitting', 'card-title-plain'), element('p',
    'Closing this window keeps Countersign in the tray, receiving requests and signing approved handshakes. Choose Quit in the tray to stop it; new handshakes then wait until you reopen it.', 'small-note'));
  pad.append(login, appearanceCard, quit);
  return [pad];
}

// ------------------------------------------------------------------ drawing
function go(tab) {
  if ($('dialog').open) $('dialog').close();
  view.tab = tab;
  view.detail = null;
  view.flash = '';
  decided = null;
  draw();
}

function draw() {
  if (!state) return;
  clearTimeout(timer);
  const focused = document.activeElement?.dataset?.key;
  const enrollment = state.pending[0];
  const confirmation = state.confirmation;
  let parts, theme = null, pairing = null, host = '';

  if (view.tab === 'requests') {
    const head = state.offers[0];
    if (decided) {
      parts = resultView();
      ({ theme, pairing } = decided.offer);
      host = originHost(decided.offer.origin);
    } else if (head) {
      const change = headChange(shown, head);
      if (change.lock) lockedUntil = Date.now() + LOCK_MS;
      if (change.banner) { banner = change.banner; bannerUntil = Date.now() + 3500; }
      shown = { handle: head.handle, pairing: head.pairing };
      parts = approvalView(head, Date.now() < lockedUntil);
      ({ theme, pairing } = head);
      host = originHost(head.origin);
    } else {
      parts = idleView();
    }
  } else if (view.tab === 'integrators') {
    const detail = state.pairings.find(p => p.id === view.detail);
    if (!detail) view.detail = null;
    if (confirmation || enrollment) {
      parts = pairingView(enrollment, confirmation);
      theme = confirmation ? confirmation.theme : enrollment.theme;
      pairing = confirmation ? confirmation.pairing : enrollment.id;
      host = originHost(confirmation?.origin ?? enrollment.origin);
    } else if (detail) {
      parts = detailView(detail);
      ({ theme } = detail);
      pairing = detail.id;
      host = originHost(detail.origin);
    } else {
      parts = listView();
    }
  } else {
    parts = settingsView();
  }

  applyTheme(theme, pairing, host);
  const section = element('section', undefined, 'view');
  section.append(...parts);
  $('content').replaceChildren(section);
  for (const tab of document.querySelectorAll('.tab')) {
    if (tab.dataset.tab === view.tab) tab.setAttribute('aria-current', 'page');
    else tab.removeAttribute('aria-current');
  }
  const count = state.offers.length;
  $('badge').hidden = !count;
  $('badge').textContent = String(count);
  $('badge').setAttribute('aria-label', count + ' pending');
  if (focused) document.querySelector('[data-key="' + CSS.escape(focused) + '"]')?.focus();

  // Re-draw when the Approve lock or the banner runs out.
  const wake = [lockedUntil, bannerUntil].filter(at => at > Date.now());
  if (wake.length) timer = setTimeout(draw, Math.min(...wake) - Date.now() + 20);
}

let revision = 0;
async function refresh() {
  const current = ++revision;
  const next = await api.snapshot();
  if (revision !== current) return;
  const handles = new Set(next.offers.map(offer => offer.handle));
  for (const key of choices.keys()) if (!handles.has(key)) choices.delete(key);
  if (view.tab === null) view.tab = next.pairings.length || next.offers.length ? 'requests' : 'integrators';
  // A new request opens the Requests tab; a pairing to confirm opens Integrators.
  if (known && [...handles].some(handle => !known.has(handle)) && view.tab !== 'requests') {
    if ($('dialog').open) $('dialog').close();
    view.tab = 'requests';
    view.detail = null;
    decided = null;
  }
  known = handles;
  if (next.confirmation && next.confirmation.id !== confirmationSeen && view.tab !== 'integrators') {
    if ($('dialog').open) $('dialog').close();
    view.tab = 'integrators';
  }
  confirmationSeen = next.confirmation?.id ?? null;
  state = next;
  draw();
}

for (const tab of document.querySelectorAll('.tab')) tab.addEventListener('click', () => go(tab.dataset.tab));
darkQuery.addEventListener('change', draw);
api.changed(() => run(refresh));
void run(refresh);
