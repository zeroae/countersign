import { EventEmitter } from 'node:events';
import { createHash, randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import WebSocket from 'ws';
import { displayText } from './origins.js';
import { readTheme, refreshTheme } from './theme.js';

function authority(origin) {
  const url = new URL(origin);
  return url.hostname + ':' + (url.port || '443');
}

export class Session extends EventEmitter {
  constructor(options) {
    super();
    Object.assign(this, options);
    this.offers = new Map();
    this.active = new Map();
    this.activations = new Map();
    this.blockedApprovals = new Set();
    this.revokeRequests = new Map();
    this.warned = new Set();
    this.fetches = new Map();
    this.status = 'Offline';
    this.devices = [];
    this.notices = [];
    this.retryMs = 1000;
    this.closed = false;
  }

  open() {
    if (this.closed || this.socket) return;
    const url = new URL('/v1/companion', this.record.origin);
    url.protocol = 'wss:';
    const ws = new WebSocket(url, 'countersign.v1', {
      maxPayload: 1024 * 1024, perMessageDeflate: false, handshakeTimeout: 10000,
      followRedirects: false,
    });
    this.socket = ws;
    const current = () => !this.closed && this.socket === ws && ws.readyState === WebSocket.OPEN;
    let sequence = Promise.resolve();
    let queued = 0;
    ws.on('message', (bytes, binary) => {
      if (binary || ++queued > 64) { ws.terminate(); return; }
      sequence = sequence.then(async () => {
        if (current()) {
          const frame = JSON.parse(this.native.validateBrokerFrame(bytes.toString('utf8')));
          await this.receive(frame, current);
        }
      }).catch(() => ws.terminate()).finally(() => { --queued; });
    });
    ws.once('open', () => {
      this.status = 'Authenticating';
      if (this.record.pairing) this.send('authenticate', { pairing: this.record.pairing, key: this.record.key });
      else this.send('enroll', { public_sec1: this.record.publicSec1 });
      this.emit('changed');
    });
    ws.on('error', () => { /* close handles reconnect */ });
    ws.once('close', () => {
      this.socket = undefined;
      this.device = null;
      this.challenge = null;
      this.fetches.clear();
      this.offers.clear();
      for (const binding of this.active.values()) this.native.retireScope(JSON.stringify(binding));
      this.active.clear();
      this.activations.clear();
      this.revokeRequests.clear();
      this.status = 'Offline';
      this.emit('changed');
      if (!this.closed && this.record.pairing) {
        this.timer = setTimeout(() => this.open(), this.retryMs);
        this.retryMs = Math.min(30000, this.retryMs * 2);
      } else if (!this.record.pairing) this.emit('enroll-failed');
    });
  }

  send(type, body, id = randomUUID()) {
    if (this.closed || this.socket?.readyState !== WebSocket.OPEN) throw new Error('Companion offline.');
    this.socket.send(JSON.stringify({ version: 1, request_id: id, type, body }));
    return id;
  }

  async receive({ type, body, request_id: id }, current) {
    const r = this.record;
    if (type === 'pairing_pending' && !this.device && !r.pairing && !this.attempt) {
      this.attempt = body.attempt;
      this.status = 'Pairing code ' + displayText(body.code, 32);
      this.emit('changed');
      await this.launchPairing(r.origin, body.attempt);
      return;
    }
    if (type === 'challenge' && !this.device && !this.challenge) {
      const a = authority(r.origin);
      if (body.integrator_origin !== a || body.broker_origin !== a || body.expires_at_ms <= Date.now() ||
          body.issued_at_ms > Date.now() + 1000 || body.expires_at_ms - body.issued_at_ms > 60000 ||
          (r.pairing ? body.purpose.reconnect?.pairing !== r.pairing || body.user !== r.user || body.key !== r.key :
            !this.attempt || body.purpose.pair?.attempt !== this.attempt)) throw new Error('Invalid pairing challenge.');
      if (!r.pairing && !await this.confirmAccount(r.origin, displayText(body.user), this.status)) {
        this.stop();
        return;
      }
      const proof = await this.native.provePairing(r.locator, JSON.stringify(body), a);
      if (!current()) return;
      this.challenge = body;
      this.send('proof', { connection: body.connection, compact_jws: proof });
      return;
    }
    if (type === 'authenticated' && this.challenge && !this.device) {
      if (body.key !== this.challenge.key || (r.pairing && body.pairing !== r.pairing)) throw new Error('Wrong pairing.');
      if (!r.pairing) {
        const record = { ...r, user: this.challenge.user, key: body.key, pairing: body.pairing, receipts: {} };
        await this.store.update(r.id, () => record);
        this.record = record;
      }
      this.status = 'Connected';
      this.device = body;
      this.retryMs = 1000;
      this.challenge = null;
      for (const [approval, receipt] of Object.entries(this.record.receipts ?? {})) {
        if (receipt.revocation === 'pending') this.sendRevocation(approval);
      }
      this.updateReminders();
      this.send('inbox', {});
      this.send('devices', {});
      void this.refreshBrand().catch(() => {});
      this.emit('changed');
      return;
    }
    if (!this.device) throw new Error('Unauthenticated message.');
    if (type === 'notify') {
      this.emit('hint', body.id);
      this.fetch(body.id);
    } else if (type === 'inbox') {
      const pending = new Set(body.ids);
      for (const key of this.offers.keys()) if (!pending.has(key)) this.offers.delete(key);
      for (const item of pending) this.fetch(item);
      this.emit('changed');
    } else if (type === 'devices') {
      this.devices = body.devices;
      this.emit('changed');
    } else if (type === 'security_event') {
      this.fetches.delete(id);
      if (!this.notices.some(n => n.id === body.id)) this.notices = [body, ...this.notices].slice(0,20);
      this.send('devices', {});
      this.emit('changed');
    } else if (type === 'offer') {
      const approval = this.fetches.get(id);
      this.fetches.delete(id);
      if (body.binding.approval !== approval || body.workload.user !== r.user ||
          !isDeepStrictEqual(body.binding.device, this.device) || body.expires_at_ms <= Date.now()) return;
      let identities = [], providerUnavailable = false;
      try {
        identities = await this.native.listIdentities(JSON.stringify(body.identity_hints ?? {}));
      } catch {
        providerUnavailable = true;
      }
      if (!current() || body.expires_at_ms <= Date.now()) return;
      this.offers.set(approval, { handle: randomUUID(), body, identities, providerUnavailable });
      this.emit('changed');
    } else if (type === 'revoke_recorded') {
      if (this.revokeRequests.get(id) !== body.id) return;
      await this.store.update(r.id, record => {
        const receipt = record.receipts[body.id];
        if (receipt?.revocation !== 'pending') return record;
        return { ...record, receipts: { ...record.receipts, [body.id]: { ...receipt, revocation: 'recorded' } } };
      });
      this.record = this.store.get(r.id);
      this.revokeRequests.delete(id);
      this.emit('changed');
    } else if (type === 'error') {
      this.revokeRequests.delete(id);
      const key = this.fetches.get(id);
      this.fetches.delete(id);
      if (key) this.offers.delete(key);
      this.emit('changed');
    } else if (type === 'activate') {
      await this.activate(body, id, current);
    } else if (type === 'sign') {
      if (!isDeepStrictEqual(this.active.get(body.binding.grant.grant), body.binding.grant) ||
          body.deadline_ms <= Date.now()) { this.send('cancel', body.binding, id); return; }
      // Keep cancellation and transport events responsive while the native provider waits.
      void this.native.signTls(JSON.stringify(body)).then(signature => {
        if (current() && isDeepStrictEqual(this.active.get(body.binding.grant.grant), body.binding.grant) && body.deadline_ms > Date.now())
          this.send('signed', { binding: body.binding, signature }, id);
      }).catch(() => { if (current()) this.send('cancel', body.binding, id); });
    } else if (type === 'cancel') {
      await this.native.cancelOperation(JSON.stringify(body));
    } else if (type === 'retire') {
      if (isDeepStrictEqual(this.active.get(body.grant),body)) {
        this.active.delete(body.grant);
        this.activations.delete(body.grant);
        this.emit('changed');
        await this.native.retireScope(JSON.stringify(body));
      }
    } else throw new Error('Unsupported control message.');
  }

  fetch(approval) {
    if (this.fetches.size >= 128 || [...this.fetches.values()].includes(approval)) return;
    const id = this.send('fetch', { id: approval });
    this.fetches.set(id, approval);
  }

  async refreshBrand() {
    const now = Date.now();
    if (this.lastRefresh && now - this.lastRefresh < 60000) return;
    this.lastRefresh = now;
    const theme = await readTheme(this.record.origin, fetch, this.decodeLogo);
    await this.store.update(this.record.id, r => {
      if (!r) throw new Error('Pairing retired.');
      return refreshTheme(r, theme);
    });
    this.record = this.store.get(this.record.id);
    this.emit('changed');
  }

  async decide(offer, selection, seconds) {
    const { body } = offer;
    if (this.offers.get(body.binding.approval) !== offer || body.expires_at_ms <= Date.now() ||
        !isDeepStrictEqual(body.binding.device, this.device)) throw new Error('Stale offer.');
    this.offers.delete(body.binding.approval);
    this.emit('changed');
    if (!selection) { this.send('decide', { binding: body.binding, answer: 'deny' }); return; }
    if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > body.max_duration_s) throw new Error('Invalid duration.');
    const selected = offer.identities.find(c => c.selection === selection);
    if (!selected || selected.expiresAtMs <= Date.now()) throw new Error('Select a valid identity.');
    // A provider-backed rediscovery must still report the same leaf. Never
    // substitute the next eligible identity if a token was removed.
    const cert = (await this.native.listIdentities(JSON.stringify(body.identity_hints ?? {}))).find(c =>
      c.certSha256 === selected.certSha256 && c.chain[0] === selected.chain[0]);
    if (!cert || createHash('sha256').update(Buffer.from(cert.chain[0], 'base64')).digest('base64') !== cert.certSha256)
      throw new Error('The selected identity is no longer available.');
    const receipt = { offer: body.binding.offer, workload: body.workload, scope: body.scope,
      host: body.initiating_host, issued: Date.now(), cert: cert.certSha256, until: Math.min(Date.now()+seconds*1000, cert.expiresAtMs) };
    await this.store.update(this.record.id, r => {
      if (!r) throw new Error('Pairing retired.');
      const receipts = Object.fromEntries(Object.entries(r.receipts).filter(([,v]) => v.until > Date.now()));
      return { ...r, receipts: { ...receipts, [body.binding.approval]: receipt } };
    });
    this.record = this.store.get(this.record.id);
    this.updateReminders();
    this.emit('changed');
    if (!isDeepStrictEqual(body.binding.device, this.device)) throw new Error('Connection changed.');
    this.send('decide', { binding: body.binding, answer: { approve: {
      duration_s: seconds, chain: cert.chain, cert_sha256: cert.certSha256,
    } } });
  }

  async activate(body, id, current) {
    const grant = body.grant;
    const receipt = this.store.get(this.record.id)?.receipts?.[body.approval];
    if (receipt?.revocation || this.blockedApprovals.has(body.approval)) return;
    if (!receipt || body.offer !== receipt.offer || grant.cert_sha256 !== receipt.cert ||
        !isDeepStrictEqual(grant.device, this.device) || !isDeepStrictEqual(grant.workload, receipt.workload) ||
        !isDeepStrictEqual(grant.scope, receipt.scope)) throw new Error('Grant does not match local consent.');
    const expiry = Math.min(body.expires_at_ms, receipt.until);
    if (expiry <= Date.now()) throw new Error('Local consent expired.');
    const cert = (await this.native.listIdentities()).find(c => c.certSha256 === receipt.cert);
    if (!cert || !current() || this.blockedApprovals.has(body.approval)) return;
    await this.native.activateScope(JSON.stringify({ ...body, expires_at_ms: expiry }), cert.selection);
    if (!current() || this.blockedApprovals.has(body.approval)) { await this.native.retireScope(JSON.stringify(grant)); return; }
    this.active.set(grant.grant, grant);
    this.activations.set(grant.grant, body.approval);
    this.emit('changed');
    this.send('activated', body, id);
  }

  sendRevocation(approval) {
    if (!this.device || [...this.revokeRequests.values()].includes(approval)) return;
    const request = this.send('revoke_approval', { id: approval });
    this.revokeRequests.set(request, approval);
  }

  async revoke(approval) {
    if (!this.record.receipts?.[approval]) throw new Error('Unknown approval.');
    this.blockedApprovals.add(approval);
    for (const [id, activeApproval] of this.activations) {
      if (activeApproval !== approval) continue;
      const grant = this.active.get(id);
      this.active.delete(id);
      this.activations.delete(id);
      this.native.retireScope(JSON.stringify(grant));
    }
    await this.store.update(this.record.id, record => {
      const receipt = record.receipts[approval];
      if (!receipt || receipt.revocation === 'recorded') return record;
      return { ...record, receipts: { ...record.receipts, [approval]: { ...receipt, revocation: 'pending' } } };
    });
    this.record = this.store.get(this.record.id);
    if (this.record.receipts[approval]?.revocation === 'pending') this.sendRevocation(approval);
    this.updateReminders();
    this.emit('changed');
  }

  updateReminders() {
    clearTimeout(this.warningTimer);
    const now = Date.now();
    let next = Infinity;
    for (const [id, receipt] of Object.entries(this.record.receipts ?? {})) {
      if (receipt.revocation || receipt.until <= now) continue;
      next = Math.min(next, receipt.until);
      if (!receipt.issued || receipt.until - receipt.issued <= 300000 || this.warned.has(id)) continue;
      const warnAt = receipt.until - 300000;
      if (warnAt > now) next = Math.min(next, warnAt);
      else {
        this.warned.add(id);
        this.emit('expiring', id);
      }
    }
    if (Number.isFinite(next)) this.warningTimer = setTimeout(() => {
      this.updateReminders();
      this.emit('changed');
    }, Math.min(2147483647, Math.max(1, next - now)));
  }

  stop() {
    clearTimeout(this.warningTimer);
    this.closed = true;
    clearTimeout(this.timer);
    this.socket?.terminate();
  }
}
