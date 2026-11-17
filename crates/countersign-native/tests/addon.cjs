// Run with a built product addon and a test account's native key store.
// The Linux driver supplies a private, encrypted login keyring.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const addon = require(process.argv[2]);
const mode = process.argv[3];
const recordPath = process.argv[4];

async function main() {
  const exports = [
    'activateScope','cancelOperation','createPairingKey','listIdentities',
    'pairingPublicKey','provePairing','retirePairingKey','retireScope','signTls','validateBrokerFrame'
  ];
  assert.deepEqual(Object.keys(addon).sort(), exports.sort());
  const org = 'test.example:443';
  const receipt = { version: 1, type: 'notify', request_id: 'notice', body: { id: 'opaque' } };
  assert.deepEqual(JSON.parse(addon.validateBrokerFrame(JSON.stringify(receipt))), receipt);
  assert.throws(() => addon.validateBrokerFrame('{"version":1,"version":1,"request_id":"r","type":"notify","body":{"id":"a"}}'));
  if (mode === 'exports') return;
  if (mode === 'create') {
    const entry = await addon.createPairingKey(org);
    assert.equal(Buffer.from(entry.publicSec1,'base64').length, 65);
    fs.writeFileSync(recordPath, JSON.stringify(entry));
    return;
  }
  const entry = JSON.parse(fs.readFileSync(recordPath));
  if (mode === 'locked') {
    await assert.rejects(addon.pairingPublicKey(entry.locator));
    return;
  }
  assert.equal(await addon.pairingPublicKey(entry.locator), entry.publicSec1);
  const pub = Buffer.from(entry.publicSec1,'base64');
  const key = crypto.createPublicKey({ format:'jwk',key:{
    kty:'EC',crv:'P-256',x:pub.subarray(1,33).toString('base64url'),y:pub.subarray(33).toString('base64url')
  }});
  const challenge = {
    purpose: { reconnect: { pairing: 'pairing' } }, integrator_origin:org, broker_origin:org,
    user: 'u', key: crypto.createHash('sha256').update(pub).digest('base64url'), connection: 'test',
    nonce:crypto.randomBytes(32).toString('base64'),issued_at_ms:Date.now()-1000,expires_at_ms:Date.now()+50000,
  };
  const [head,payload,signature] = (await addon.provePairing(entry.locator,JSON.stringify(challenge),org)).split('.');
  assert.equal(JSON.parse(Buffer.from(head,'base64url')).typ,'countersign-device-proof+jws');
  assert.deepEqual(JSON.parse(Buffer.from(payload,'base64url')).challenge, challenge);
  assert.ok(crypto.verify('sha256',Buffer.from(head+'.'+payload),{key,dsaEncoding:'ieee-p1363'},Buffer.from(signature,'base64url')));
  await assert.rejects(addon.provePairing(entry.locator,JSON.stringify(challenge),'other.example'));
  if (mode === 'retire') {
    await addon.retirePairingKey(entry.locator);
    await assert.rejects(addon.pairingPublicKey(entry.locator));
  }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
