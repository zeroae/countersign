// Single-account reference Integrator. All ownership and destination choices
// are server-side. A fresh random login secret is provisioned for each demo.
import https from 'node:https';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const env = process.env;
const secrets = env.DEMO_SECRETS || '/demo';
const origin = env.INTEGRATOR_ORIGIN || 'https://localhost:8443';
const upstream = new URL(env.BROKER_URL || 'https://broker:9443');
const workload = {user:'demo-user',context:'demo-context',workload:'demo-curl',workload_generation:1};
const binding = {integrator:'demo',...workload};
const sessions = new Map();
const root = p => fileURLToPath(new URL(p,import.meta.url));
const [ca,cert,key,backendToken,loginSecret] = await Promise.all(
  ['ca.pem','integrator.pem','integrator.key','backend.token','login.secret'].map(f => readFile(secrets+'/'+f)));
const token = () => randomBytes(32).toString('base64url');
const equal = (a,b) => timingSafeEqual(createHash('sha256').update(a).digest(),createHash('sha256').update(b).digest());
const files = new Map([
  ['/', ['site/index.html','text/html']], ['/countersign/pair',['site/index.html','text/html']],
  ['/countersign/devices',['site/index.html','text/html']], ['/app.js',['site/app.js','text/javascript']],
  ['/sw.js',['site/sw.js','text/javascript']], ['/widget.js',['../../packages/widget/src/widget.js','text/javascript']],
  ['/hints.js',['../../packages/widget/src/hints.js','text/javascript']],
  ['/service-worker.js',['../../packages/widget/src/service-worker.js','text/javascript']],
]);

async function broker(path, body) {
  const response = await fetch(new URL('/v1/backend/'+path,upstream), {
    method:'POST',headers:{Authorization:'Bearer '+backendToken.toString().trim(),'Content-Type':'application/json'},
    body: JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error('Broker declined request.',{cause:response.status});
  return response.status===204 ? null : response.json();
}

async function issueToken() {
  const path=env.WORKLOAD_TOKEN_FILE;
  if (!path) return;
  const {token}=await broker('workloads',workload);
  await writeFile(path+'.next',token,{mode:0o640});
  await rename(path+'.next',path);
}
const login = loginSecret.toString().trim();
if (login.length < 32 || backendToken.toString().trim().length < 32) throw new Error('Generate unique demo secrets.');
const manifest = {version:1,displayName:'Demo Integrator',colors:{accent:'#2d594d',background:'#edf4f0'}};
const server=https.createServer({ca,cert,key,maxHeaderSize:8192},async (req,res)=>{
  function json(status,body) {
    res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});
    res.end(JSON.stringify(body));
  }
  try {
    const path = new URL(req.url,origin).pathname;
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('Referrer-Policy','no-referrer');
    if (req.method==='GET' && path==='/.well-known/countersign.json') return json(200,manifest);
    if (req.method==='GET' && files.has(path)) {
      const [file,type]=files.get(path);
      res.writeHead(200,{'Content-Type':type});res.end(await readFile(root(file)));return;
    }
    const cookies=Object.fromEntries((req.headers.cookie||'').split('; ').map(c=>c.split('=')));
    const session=sessions.get(cookies.cs_demo);
    const authenticated=session?.until > Date.now();
    if(req.method==='GET' && path==='/api/session'){
      if(!authenticated)return json(401,{});
      return json(200,{csrf:session.csrf,user:workload.user,context:workload.context,
        vapid:env.VAPID_PUBLIC_KEY || null});
    }
    if(req.method!=='POST'||req.headers.origin!==origin||
      req.headers['content-type']!=='application/json')return json(403,{});
    const chunks=[]; let size=0;
    for await (const chunk of req) {
      size+=chunk.length; if(size>8192)return json(413,{}); chunks.push(chunk);
    }
    const body=JSON.parse(Buffer.concat(chunks));
    if(path==='/api/login'){
      if(typeof body.password!=='string'||!equal(body.password,login))return json(401,{});
      for(const [id,s] of sessions)if(s.until<=Date.now())sessions.delete(id);
      if(sessions.size>=64)return json(429,{});
      const id=token();sessions.set(id,{csrf:token(),until:Date.now()+3600000});
      res.setHeader('Set-Cookie','cs_demo='+id+'; Secure; HttpOnly; SameSite=Strict; Path=/');
      return json(200,{});
    }
    if(!authenticated||req.headers['x-csrf-token']!==session.csrf)return json(403,{});
    let result;
    switch(path){
      case '/api/pair':result=await broker('pairings/confirm',{user:workload.user,attempt:body.attempt,code:body.code});break;
      case '/api/connect':result=await broker('requests',{binding,host:'site.test:9444'});break;
      case '/api/renew':result=await broker('renew',{binding,id:body.id});break;
      case '/api/status':result=await broker('status',{user:workload.user,id:body.id});break;
      case '/api/revoke':result=await broker('revoke',{user:workload.user,id:body.id});break;
      case '/api/devices':result=await broker('devices',{user:workload.user});break;
      case '/api/forget':result=await broker('pairings/forget',{user:workload.user,targets:body.targets});break;
      case '/api/subscribe':result=await broker('push/subscribe',{user:workload.user,subscription:body.subscription});break;
      case '/api/logout':
        if(body.endpoint)await broker('push/unsubscribe',{user:workload.user,endpoint:body.endpoint});
        sessions.delete(cookies.cs_demo);result={};break;
      default:return json(404,{});
    }
    return json(200,result);
  }catch(err){return json(Number.isInteger(err.cause)?err.cause:400,{});}
});

server.on('upgrade',(req,client,head)=>{
  if(req.url!=='/v1/companion'||req.headers.origin || req.headers['sec-websocket-protocol']!=='countersign.v1'){
    client.destroy();return;
  }
  const proxy=https.request(new URL('/v1/companion',upstream),{
    ca,method:'GET',headers:{Upgrade:'websocket',Connection:'Upgrade',
      'Sec-WebSocket-Protocol':'countersign.v1','Sec-WebSocket-Version':'13','Sec-WebSocket-Key':req.headers['sec-websocket-key']},
  });
  proxy.on('upgrade',(reply,serverSocket,pending)=>{
    client.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'+
      'Sec-WebSocket-Accept: '+reply.headers['sec-websocket-accept']+'\r\nSec-WebSocket-Protocol: countersign.v1\r\n\r\n');
    if(head.length)serverSocket.write(head);
    if(pending.length)client.write(pending);
    client.on('error',()=>serverSocket.destroy());serverSocket.on('error',()=>client.destroy());
    client.on('close',()=>serverSocket.destroy());serverSocket.on('close',()=>client.destroy());
    client.pipe(serverSocket).pipe(client);
  });
  proxy.on('response',r=>{r.resume();client.destroy();});
  proxy.on('error',()=>client.destroy());
  proxy.end();
});
server.listen(Number(env.PORT || 8443),env.BIND_ADDRESS || '127.0.0.1');
async function refresh() {
  try { await issueToken(); setTimeout(refresh,60000).unref(); }
  catch { setTimeout(refresh,2000).unref(); }
}
void refresh();
