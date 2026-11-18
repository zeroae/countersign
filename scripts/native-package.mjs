// Assemble only the host's Cargo-built production library with its matching app.
import { copyFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { platform } from 'node:os';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const dir=join(root,'packages','companion','native');
const mode=process.argv[2] || 'release';
if (!['release','debug'].includes(mode)) throw new Error('Expected release or debug.');
const name={darwin:'libcountersign_native.dylib',linux:'libcountersign_native.so',win32:'countersign_native.dll'}[platform()];
await mkdir(dir,{recursive:true});
const path=join(dir,'countersign-native.node');
await copyFile(join(resolve(process.env.CARGO_TARGET_DIR || join(root,'target')),mode,name),path);
const binding=createRequire(import.meta.url)(path);
const expected=['validateBrokerFrame','createPairingKey','pairingPublicKey','provePairing','retirePairingKey',
  'listIdentities','activateScope','signTls','retireScope','cancelOperation'];
for(const key of expected)if(typeof binding[key]!=='function')throw new Error('Missing production export '+key);
for(const key of Object.keys(binding))if(!expected.includes(key))throw new Error('Unexpected native export '+key);
console.log('Validated production native addon for',process.platform,process.arch);
