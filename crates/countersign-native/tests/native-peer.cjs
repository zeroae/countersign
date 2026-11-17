// A private pipe to the native integration test. This helper is excluded from installers.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const readline=require('node:readline');
const addon=require(process.env.COUNTERSIGN_CI_ADDON);
const wanted=new Set(JSON.parse(process.env.COUNTERSIGN_CI_FINGERPRINTS));
const hex=cert=>Buffer.from(cert.certSha256,'base64').toString('hex');
async function main(){
  const available=(await addon.listIdentities()).filter(c=>wanted.has(hex(c)));
  assert.equal(available.length,3,'all three installed identities must be available');
  assert.equal(new Set(available.map(c=>c.subject)).size,1);
  const selected=available.at(-1);
  const host='mtls.example:443';
  const grant={
    workload:{integrator:'ci',user:'user',context:'context',workload:'test',workload_generation:1},
    grant:'grant',grant_version:1,worker:'worker',worker_generation:1,
    scope:{entry_id:'site',entry_version:1,pattern:host},
    device:{pairing:'pair',key:'key',channel_generation:1},cert_sha256:selected.certSha256
  };
  const activate={grant,approval:'approval',offer:'offer',expires_at_ms:Date.now()+90_000};
  await addon.activateScope(JSON.stringify(activate),selected.selection);
  console.log(JSON.stringify({chain:selected.chain,fingerprint:hex(selected)}));
  for await (const line of readline.createInterface({input:process.stdin})){
    const {data,tls}=JSON.parse(line);
    const binding={grant,host,tls_connection:'conn',operation:crypto.randomUUID()};
    const request={binding,tls,scheme:'ecdsa_nistp256_sha256',certificate_verify:data,deadline_ms:Date.now()+30_000};
    const wrongHost={...request,binding:{...binding,host:'other.example:443'}};
    await assert.rejects(addon.signTls(JSON.stringify(wrongHost)));
    const sig=await addon.signTls(JSON.stringify(request));
    await assert.rejects(addon.signTls(JSON.stringify(request)));
    console.log(JSON.stringify({signature:sig}));
  }
  await addon.retireScope(JSON.stringify(grant));
}
main().catch(e=>{console.error(e);process.exitCode=1;});
