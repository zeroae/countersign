import { subscribeForPush } from '/widget.js';
const byId=id=>document.getElementById(id);
let session,active,target;
const show=msg=>{byId('message').textContent=msg;};
async function post(path,body={}){
  const res=await fetch('/api/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session?.csrf||''},body:JSON.stringify(body)});
  if(!res.ok)throw new Error('Request failed ('+res.status+').');
  return res.json();
}
function perform(fn){return e=>{e?.preventDefault();void fn().catch(e=>show(e.message));};}
function select(id) { active=id;byId('grant').hidden=false;document.querySelector('countersign-widget').showRequest(id); }
async function load(){
  const res=await fetch('/api/session');
  byId('login').hidden=res.ok;
  byId('session').hidden=!res.ok;
  if(!res.ok)return;
  session=await res.json();
  const params=new URL(location.href).searchParams;
  byId('pair').hidden=!(location.pathname==='/countersign/pair'&&params.has('attempt'));
  byId('forget').hidden=!(location.pathname==='/countersign/devices'&&params.has('pairing'));
  if(!byId('forget').hidden){
    target=(await post('devices')).devices.find(d=>d.binding.pairing===params.get('pairing'))?.binding;
    byId('forget').disabled=!target;
    if(target)byId('forget').textContent='Forget Companion '+target.pairing+' and revoke its grants';
  }
  const adapter={
    pair:async()=>{show('Open Countersign, choose Pair, and enter '+location.origin);},
    connect:async()=>{const result=await post('connect');active=result.id;byId('grant').hidden=false;return active;},
  };
  if(session.vapid && 'serviceWorker' in navigator)adapter.subscribe=async()=>{
    if(await Notification.requestPermission()!=='granted')throw new Error('Notifications unavailable.');
    await navigator.serviceWorker.register('/sw.js',{type:'module'});
    await subscribeForPush(await navigator.serviceWorker.ready,session.vapid,subscription=>post('subscribe',{subscription}));
  };
  document.querySelector('countersign-widget').adapter=adapter;
  const id=new URLSearchParams(location.hash.slice(1)).get('countersign');
  if(id && (await post('status',{id})).state==='pending')select(id);
}
byId('login').onsubmit=perform(async()=>{await post('login',{password:byId('login').elements.password.value});byId('login').reset();await load();});
byId('pair').onsubmit=perform(async()=>{await post('pair',{attempt:new URL(location.href).searchParams.get('attempt'),code:byId('pair').elements.code.value});show('Confirm the account in Countersign.');byId('pair').hidden=true;});
byId('forget').onclick=perform(async()=>{await post('forget',{targets:[target]});show('Pairing revoked.');});
byId('status').onclick=perform(async()=>show((await post('status',{id:active})).state));
byId('renew').onclick=perform(async()=>select((await post('renew',{id:active})).id));
byId('revoke').onclick=perform(async()=>{await post('revoke',{id:active});show('Revocation recorded.');});
byId('logout').onclick=perform(async()=>{
  const registration=await navigator.serviceWorker?.getRegistration();
  const subscription=await registration?.pushManager.getSubscription();
  await post('logout',{endpoint:subscription?.endpoint});await subscription?.unsubscribe();location.assign('/');
});
void load().catch(e=>show(e.message));
