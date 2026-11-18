const api = window.countersign;
const $ = id => document.getElementById(id);
const selections = new Map();

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

async function run(action) {
  try {
    $('feedback').textContent = '';
    await action();
  } catch {
    $('feedback').textContent = 'This action could not be completed. Check the connection and try again.';
  }
}

function button(label, action, className) {
  const node = element('button', label, className);
  node.type = 'button';
  node.addEventListener('click', () => run(action));
  return node;
}

function branding(theme) {
  const area = element('aside', undefined, 'brand');
  area.ariaLabel = 'Integrator branding';
  if (theme.logo) {
    const logo = element('img');
    logo.alt = '';
    logo.src = theme.logo;
    area.append(logo);
  }
  area.style.borderColor = theme.accent;
  area.style.backgroundColor = theme.background;
  area.append(element('strong', theme.name), element('p', theme.copy));
  return area;
}

function offerCard(offer) {
  const card = element('article');
  if (offer.theme) card.append(branding(offer.theme));
  card.append(element('h3', 'Use a client certificate?'));
  const facts = element('dl');
  for (const [key, value] of [
    ['Verified Integrator', offer.origin], ['Account', offer.user], ['Context', offer.context],
    ['Requested host', offer.host], ['Approval covers', offer.scope],
  ]) facts.append(element('dt', key), element('dd', value));
  card.append(facts);
  const picker = element('fieldset');
  picker.append(element('legend', 'Certificate'));
  const { identities } = offer;
  const previous = selections.get(offer.handle);
  let selection = identities.length === 1 ? identities[0] :
    identities.find(item => item.reference === previous?.reference);
  const duration = element('input');
  duration.type = 'number';
  duration.min = '1';
  duration.max = String(offer.maxDuration);
  duration.value = String(previous?.seconds ?? offer.defaultDuration);
  const expiry = element('p');
  const approve = button('Approve', () => api.decide(offer.handle, selection.reference, Number(duration.value)), 'approve');
  function update() {
    const seconds = Number(duration.value);
    const until = Math.min(Date.now() + seconds * 1000, selection?.expiresAt ?? 0);
    approve.disabled = !selection || !Number.isSafeInteger(seconds) || seconds < 1 ||
      seconds > offer.maxDuration || until <= Date.now();
    expiry.textContent = approve.disabled ? '' : 'Expires by ' + new Date(until).toLocaleString();
    selections.set(offer.handle, { reference: selection?.reference, seconds });
  }
  for (const cert of identities) {
    const label = element('label', undefined, 'identity');
    const input = element('input');
    input.type = 'radio';
    input.name = 'certificate-' + offer.handle;
    input.checked = cert === selection;
    input.addEventListener('change', () => { selection = cert; update(); });
    label.append(input, document.createTextNode(cert.identity), element('div', 'Issued by ' + cert.issuer),
      element('div', 'Valid until ' + new Date(cert.expiresAt).toLocaleString()),
      element('small', 'SHA-256 ' + cert.fingerprint));
    picker.append(label);
  }
  if (!identities.length) picker.append(element('p', offer.providerUnavailable ?
    'The certificate provider is unavailable. Unlock or reconnect it and request access again.' :
    'No eligible installed certificate is available for this request.'));
  const label = element('label', 'Duration (seconds) ');
  label.append(duration);
  duration.addEventListener('input', update);
  update();
  const actions = element('div', undefined, 'actions');
  actions.append(approve, button('Deny', () => api.deny(offer.handle)));
  card.append(picker, label, expiry, element('p', 'The Gateway can read and send traffic to the approved destination until access ends.'), actions);
  return card;
}

let revision = 0;
async function render() {
  const current = ++revision;
  const state = await api.snapshot();
  if (revision !== current) return;
  const handles = new Set(state.offers.map(offer => offer.handle));
  for (const key of selections.keys()) if (!handles.has(key)) selections.delete(key);
  $('requests').replaceChildren(...(state.offers.length ? state.offers.map(offerCard) : [element('p', 'No pending requests.')]));
  $('pairs').replaceChildren(...state.pairings.map(pairing => {
    const card = element('article');
    card.append(element('strong', pairing.origin), element('p', pairing.user + ' · ' + pairing.status));
    if (pairing.pendingTheme) {
      card.append(element('h3', 'Review branding change'));
      if (pairing.theme) card.append(branding(pairing.theme));
      card.append(branding(pairing.pendingTheme), button('Accept new branding', () => api.theme(pairing.id, pairing.pendingTheme.digest)));
    }
    for (const notice of pairing.notices) {
      card.append(element('p', (notice.kind === 'concurrent_devices' ? 'Another Companion connected' : 'Companion security event') +
        ' · ' + new Date(notice.occurred_at_ms).toLocaleString() + ' · ' + (notice.observed_address || 'Address unavailable') +
        ' · ' + (notice.actor?.pairing || '') + ' · ' + notice.kind));
    }
    if (pairing.devices.length) {
      const forget = (devices,all) => {
        const ids = devices.map(d => d.binding);
        if (window.confirm('Forget these pairings and revoke their grants? ' + ids.map(d=>d.pairing).join(', '))) {
          return api.forgetOthers(pairing.id,ids,all);
        }
      };
      for (const d of pairing.devices) {
        card.append(element('p', d.binding.pairing + ' · ' + (d.connected?'Connected':'Offline') +
          ' · ' + (d.observed_address || 'Address unavailable')),button('Disconnect device',()=>forget([d],false)));
      }
      if(pairing.devices.length > 1) card.append(button('Disconnect all other devices',()=>forget(pairing.devices,true)));
    }
    for (const approval of pairing.approvals) {
      const status = approval.revocation === 'pending' ? 'Revocation queued for Broker confirmation' :
        approval.revocation === 'recorded' ? 'Broker recorded revocation. Existing traffic ends at its lease deadline.' :
        approval.ready ? 'Ready for handshakes' : 'Approved on this device';
      card.append(element('h3', approval.host), element('p', approval.context + ' · ' + approval.scope),
        element('small', 'SHA-256 ' + approval.fingerprint),
        element('p', status + ' · Expires ' + new Date(approval.until).toLocaleString()));
      if (approval.revocation !== 'recorded') card.append(button(approval.revocation ? 'Retry revocation' : 'Revoke access', () => api.revoke(pairing.id, approval.id)));
    }
    card.append(button('Remove from this computer', () => {
      if (window.confirm('Delete this local pairing key? Use the Integrator to revoke existing remote access.')) return api.removeLocal(pairing.id);
    }));
    card.append(button('Revoke pairing at Integrator', () => {
      if (window.confirm('Forget the pairing with ' + pairing.origin + ' and revoke its grants?')) return api.forget(pairing.id);
    }));
    return card;
  }));
  $('pending').textContent = state.pending ?? '';
  if (state.confirmation) {
    const c = state.confirmation;
    $('pending').replaceChildren(element('p', c.origin + ' · ' + c.user + ' · ' + c.code),
      button('Confirm pairing', () => api.confirmPair(c.id, true)),
      button('Cancel pairing', () => api.confirmPair(c.id, false)));
  }
  $('login').checked = state.login;
}

$('pair').addEventListener('submit', event => {
  event.preventDefault();
  void run(() => api.pair($('origin').value));
});
$('login').addEventListener('change', () => run(() => api.login($('login').checked)));
api.changed(() => run(render));
void run(render);
