import { subscribeForPush } from '/widget.js';

// Harbor Ledger demo page. Every state shown here comes from the backend's
// /api routes, which proxy the Broker. The widget only offers pairing, access
// requests and the Companion launch link; this page explains the rest.
const $ = id => document.getElementById(id);
const widget = document.querySelector('countersign-widget');
const PENDING_MS = 10 * 60 * 1000; // the Broker's deadline for a pending offer
const REMEMBER = 'harbor-ledger-approval';
const page = { session: null, devices: [], id: null, status: null, requestedAt: null,
  revoked: false, renewal: false, justPaired: false, timer: 0 };

const show = msg => { $('message').textContent = msg; };
const fill = (selector, value) => { for (const node of document.querySelectorAll(selector)) node.textContent = value; };
const short = id => String(id).slice(0, 8);
const clock = ms => new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

async function post(path, body = {}) {
  const res = await fetch('/api/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json',
    'X-CSRF-Token': page.session?.csrf || '' }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error('Request failed (' + res.status + ').');
  return res.json();
}
function perform(fn) { return e => { e?.preventDefault(); void fn().catch(err => show(err.message)); }; }
function remember(id) {
  try { if (id) sessionStorage.setItem(REMEMBER, id); else sessionStorage.removeItem(REMEMBER); } catch { /* optional */ }
}
function recalled() {
  try { return sessionStorage.getItem(REMEMBER); } catch { return null; }
}

function view() {
  const params = new URL(location.href).searchParams;
  if (location.pathname === '/countersign/pair' && params.has('attempt') && !page.justPaired) return 'pair';
  if (location.pathname === '/countersign/devices') return 'devices';
  if (location.pathname === '/job') return 'job';
  const state = page.status?.state;
  if (!state) return 'home';
  return state === 'pending' ? 'pending' : state === 'approved' ? 'active' : 'ended';
}

function ending(state, host) {
  if (state === 'denied') return ['Access was denied in the Companion', `The job can’t reach ${host}. Nothing was signed with your certificate.`];
  if (state === 'expired') return ['This approval expired', `The request timed out or reached its end. The job can no longer open new connections to ${host}.`];
  if (state === 'replaced') return ['This approval was replaced', 'A renewal took its place. Its own status shows whether access continues.'];
  return page.revoked ?
    ['Access was revoked', `The Broker recorded the revocation. Open connections to ${host} close by their current lease deadline.`] :
    ['Access was withdrawn', `This approval was revoked or cancelled. The job can no longer open new connections to ${host}.`];
}

function render() {
  const { session, devices, status } = page;
  const current = view();
  const paired = devices.length > 0 || page.justPaired;
  const online = devices.some(d => d.connected);
  const device = devices.find(d => d.connected) ?? devices[0];
  const host = session.host;
  for (const section of document.querySelectorAll('[data-view]')) section.hidden = section.dataset.view !== current;
  $('workspace').hidden = current === 'job';
  $('job-view').hidden = current !== 'job';
  for (const link of document.querySelectorAll('[data-nav]')) {
    if (link.dataset.nav === (current === 'job' || current === 'devices' ? current : 'home')) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }

  fill('[data-host]', host);
  fill('[data-user]', session.user);
  fill('[data-origin]', location.origin);
  fill('[data-approval]', page.id ?? '');
  $('user').textContent = session.user;
  $('context-title').textContent = session.title || session.context;
  $('context-id').textContent = session.context;
  $('workload').textContent = session.workload + ' · gen ' + session.workload_generation;
  $('companion').textContent = !paired ? 'Not paired' : !device ? 'Paired' :
    'Paired · ' + short(device.binding.pairing) + (online ? '' : ' · offline');

  const chip = { home: paired ? 'Ready' : 'Not paired', pair: 'Pairing', pending: 'Pending',
    active: 'Running', ended: 'Stopped', devices: paired ? 'Paired' : 'Not paired' }[current];
  $('job-state').textContent = chip ?? '';
  $('job-state').className = 'chip' + (current === 'active' ? ' good' : current === 'ended' ? ' bad' : '');
  $('headline').textContent = { home: paired ? 'Ready to request access' : 'Approve with your desktop',
    pair: 'Pairing', pending: 'Waiting for you', active: 'Access approved', ended: 'Access ended' }[current] ??
    'Approve with your desktop';
  widget.toggleAttribute('paired', paired);

  $('home-title').textContent = paired ? 'Companion paired' : 'Use your client certificate for this job';
  $('home-body').textContent = page.justPaired ?
    'Confirm the account in your Companion too. When it shows Connected, choose Request access to start the job.' :
    paired ? 'Choose Request access when the job needs your certificate. The Companion asks you to pick one and a duration.' :
    `The job connects to ${host} with your installed client certificate. Its private key stays on your computer. ` +
    'Pair the Countersign Companion once, then approve each job when it asks.';

  $('renewal').hidden = !page.renewal;
  $('offline').hidden = online;
  $('offline-body').textContent = 'Open Countersign on your computer. ' + (page.requestedAt ?
    `The request stays pending until it times out at ${clock(page.requestedAt + PENDING_MS)}; after that, request access again.` :
    'A pending request times out after ten minutes; after that, request access again.');

  const done = { approved: status?.state === 'approved', ready: !!status?.ready, upstream: !!status?.upstream_mtls_accepted };
  for (const step of document.querySelectorAll('[data-step]')) step.classList.toggle('done', done[step.dataset.step]);
  const forget = $('forget-link');
  forget.hidden = !device;
  if (device) {
    forget.href = '/countersign/devices?pairing=' + encodeURIComponent(device.binding.pairing);
    forget.textContent = 'Forget Companion ' + short(device.binding.pairing) + ' and revoke its grants';
  }
  const [title, body] = ending(status?.state, host);
  $('ended-title').textContent = title;
  $('ended-body').textContent = body;
  renderDevices();
}

function renderDevices() {
  const target = new URL(location.href).searchParams.get('pairing');
  $('devices').replaceChildren(...page.devices.map(d => {
    const item = document.createElement('li');
    item.classList.toggle('target', d.binding.pairing === target);
    item.textContent = 'Companion ' + short(d.binding.pairing) + ' · ' + (d.connected ? 'Connected' : 'Offline') +
      ' · ' + (d.observed_address || 'Address unavailable');
    return item;
  }));
  if (!page.devices.length) {
    const none = document.createElement('li');
    none.textContent = 'No Companion is paired with this account.';
    $('devices').append(none);
  }
  const chosen = page.devices.find(d => d.binding.pairing === target);
  $('forget').hidden = !chosen;
  if (chosen) $('forget').textContent = 'Forget Companion ' + short(chosen.binding.pairing) + ' and revoke its grants';
}

async function track(id, state) {
  page.id = id;
  page.status = { state };
  page.requestedAt = state === 'pending' ? Date.now() : null;
  page.revoked = false;
  remember(id);
  history.replaceState(null, '', location.pathname + location.search + '#countersign=' + id);
  await refresh();
}

async function refresh() {
  clearTimeout(page.timer);
  page.devices = (await post('devices').catch(() => ({ devices: [] })))?.devices ?? [];
  if (page.id && !page.revoked) {
    try {
      page.status = await post('status', { id: page.id });
    } catch {
      page.id = page.status = null;
      remember(null);
    }
  }
  render();
  if (['pending', 'active'].includes(view())) page.timer = setTimeout(() => void refresh().catch(() => {}), 5000);
}

async function showJob() {
  const { session } = page;
  const { result } = await post('job');
  $('job-eyebrow').textContent = 'Job ' + session.workload + ' · ' + (session.title || session.context);
  $('job-empty').hidden = !!result;
  $('job-peer').hidden = !result?.ok;
  $('job-request').hidden = !result;
  $('job-chip').hidden = !result;
  if (!result) {
    $('job-title').textContent = 'No result yet';
    return;
  }
  $('job-request').textContent = 'GET ' + result.url;
  $('job-title').textContent = result.ok ? 'Response received' : 'Request failed';
  $('job-chip').textContent = result.ok ? 'HTTP ' + (result.http_status ?? 200) : 'Failed';
  $('job-chip').className = 'chip ' + (result.ok ? 'good' : 'bad');
  if (!result.ok) {
    $('job-empty').hidden = false;
    $('job-empty').textContent = result.error || 'The site did not return a response. Check the approval and try again.';
    return;
  }
  $('job-fingerprint').textContent = result.fingerprint;
  $('job-subject').textContent = 'Subject: ' + result.subject;
}

async function load() {
  const res = await fetch('/api/session');
  $('login-view').hidden = res.ok;
  $('nav').hidden = $('account').hidden = !res.ok;
  if (!res.ok) {
    $('workspace').hidden = $('job-view').hidden = true;
    return;
  }
  page.session = await res.json();
  const adapter = {
    pair: async () => { show('Open Countersign, choose Pair, and enter ' + location.origin); },
    connect: async () => {
      const { id, state } = await post('connect');
      page.renewal = false;
      await track(id, state);
      return id;
    },
  };
  if (page.session.vapid && 'serviceWorker' in navigator) adapter.subscribe = async () => {
    if (await Notification.requestPermission() !== 'granted') throw new Error('Notifications unavailable.');
    await navigator.serviceWorker.register('/sw.js', { type: 'module' });
    await subscribeForPush(await navigator.serviceWorker.ready, page.session.vapid, subscription => post('subscribe', { subscription }));
  };
  widget.adapter = adapter;
  page.id = new URLSearchParams(location.hash.slice(1)).get('countersign') || recalled();
  await refresh();
  if (page.status?.state === 'pending') widget.showRequest(page.id);
  if (view() === 'job') await showJob();
}

$('login').onsubmit = perform(async () => {
  await post('login', { password: $('password').value });
  $('login').reset();
  await load();
});
$('pair').onsubmit = perform(async () => {
  await post('pair', { attempt: new URL(location.href).searchParams.get('attempt'), code: $('code').value });
  page.justPaired = true;
  render();
  show('Confirm the account in Countersign.');
});
$('compare').onsubmit = e => {
  e.preventDefault();
  const typed = $('selected').value.replace(/[^0-9a-f]/gi, '').toLowerCase();
  const same = typed === $('job-fingerprint').textContent;
  $('match').hidden = !same;
  $('mismatch').hidden = same || !typed;
};
for (const button of document.querySelectorAll('[data-act=status]')) button.onclick = perform(refresh);
document.querySelector('[data-act=renew]').onclick = perform(async () => {
  const { id } = await post('renew', { id: page.id });
  page.renewal = true;
  await track(id, 'pending');
  widget.showRequest(id);
});
document.querySelector('[data-act=revoke]').onclick = perform(async () => {
  await post('revoke', { id: page.id });
  page.revoked = true;
  page.status = { state: 'cancelled' };
  clearTimeout(page.timer);
  render();
});
document.querySelector('[data-act=again]').onclick = perform(async () => {
  const { id, state } = await post('connect');
  page.renewal = false;
  await track(id, state);
  if (state === 'pending') widget.showRequest(id);
});
$('forget').onclick = perform(async () => {
  const target = page.devices.find(d => d.binding.pairing === new URL(location.href).searchParams.get('pairing'));
  if (!target) return;
  await post('forget', { targets: [target.binding] });
  show('Pairing revoked.');
  await refresh();
});
$('logout').onclick = perform(async () => {
  const registration = await navigator.serviceWorker?.getRegistration();
  const subscription = await registration?.pushManager.getSubscription();
  await post('logout', { endpoint: subscription?.endpoint });
  await subscription?.unsubscribe();
  remember(null);
  location.assign('/');
});
void load().catch(e => show(e.message));
