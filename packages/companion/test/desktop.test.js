import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readTheme, refreshTheme } from '../src/theme.js';
import { approvalHint, integratorOrigin } from '../src/origins.js';

const site = 'https://integrator.test';
function manifest(value) {
  return async (url, options) => {
    assert.equal(url.href, site + '/.well-known/countersign.json');
    assert.equal(options.redirect, 'error');
    return Response.json(value);
  };
}

test('display copy, appearance and logo never select the Integrator origin', async () => {
  const first = await readTheme(site, manifest({ version: 1, displayName: 'Example' }));
  const later = await readTheme(site, manifest({ version: 1, displayName: 'Different' }));
  const pairing = refreshTheme({ origin: site, theme: first }, later);
  assert.equal(pairing.theme.name, 'Example');
  assert.equal(pairing.pendingTheme.name, 'Different');
  assert.equal(pairing.origin, site);
  for (const additions of [
    { displayName: 'trusted\u202eevil' }, { logo: 'https://other.test/logo' },
    { colors: { accent: 'red; display:none' } },
  ]) {
    await assert.rejects(readTheme(site, manifest({ version: 1, displayName: 'Example', ...additions })));
  }
});

test('only an exact opaque-ID approval link can wake the Companion', () => {
  const id = '13e33b7d-cbef-4488-8174-30e73ad76d05';
  assert.equal(approvalHint('countersign://approve/' + id), id);
  for (const tail of ['?origin=evil', '#approve', '/more']) {
    assert.equal(approvalHint('countersign://approve/' + id + tail), undefined);
  }
  for (const invalid of ['http://example.test', site + '/any', 'https://person@integrator.test']) {
    assert.throws(() => integratorOrigin(invalid));
  }
});

test('offline revocation survives restart and waits for a matching authenticated acknowledgment', async () => {
  const { Session } = await import('../src/session.js');
  const approval = 'f7e8ef3b-240f-40f0-ba15-a3c56a67a07e';
  let stored = {id:'local',origin:site,receipts:{[approval]:{until:Date.now()+60000}}};
  const store = {get:() => structuredClone(stored),update:async (_id,fn) => {stored = fn(structuredClone(stored));}};
  const retired = [];
  const native = {retireScope:binding => retired.push(JSON.parse(binding))};
  const offline = new Session({record:stored,store,native});
  offline.active.set('grant',{grant:'grant'});
  offline.activations.set('grant',approval);
  await offline.revoke(approval);
  assert.deepEqual(retired,[{grant:'grant'}]);
  assert.equal(stored.receipts[approval].revocation,'pending');
  const restored = new Session({record:store.get(),store,native});
  restored.device = {pairing:'device'};
  restored.send = (type, body) => {
    assert.equal(type,'revoke_approval');
    assert.equal(body.id,approval);
    return 'request';
  };
  restored.sendRevocation(approval);
  await restored.receive({type:'revoke_recorded',body:{id:approval},request_id:'old'},() => true);
  assert.equal(stored.receipts[approval].revocation,'pending');
  await restored.receive({type:'revoke_recorded',body:{id:approval},request_id:'request'},() => true);
  assert.equal(stored.receipts[approval].revocation,'recorded');
  offline.stop();
  restored.stop();
});

test('colliding approval IDs stay on their authenticated pairing', async () => {
  const { Session } = await import('../src/session.js');
  const sent = [];
  const makeSession = (pairing, origin) => {
    const session = new Session({ record:{id:pairing,origin,user:'user'}, native:{
      listIdentities:async hints => [{selection:pairing, hints:JSON.parse(hints)}],
    }});
    session.device = {pairing,key:pairing+'-key',channel_generation:1};
    session.send = (type,body) => {sent.push({pairing,type,body}); return 'fetch-'+pairing;};
    return session;
  };
  const a = makeSession('first','https://one.example');
  const b = makeSession('second','https://two.example');
  const id = '4ba58db2-6899-4080-8de5-279d993203bf';
  for (const session of [a,b]) {
    await session.receive({type:'notify',body:{id}},() => true);
  }
  const body = {binding:{approval:id,device:a.device}, workload:{user:'user'}, expires_at_ms:Date.now()+20000};
  await a.receive({type:'offer',body,request_id:'fetch-first'},() => true);
  await b.receive({type:'offer',body,request_id:'fetch-second'},() => true);
  assert.equal(a.offers.get(id).identities[0].selection,'first');
  assert.equal(b.offers.size,0);
  assert.deepEqual(sent.map(v=>[v.pairing,v.type,v.body.id]),[['first','fetch',id],['second','fetch',id]]);
});
