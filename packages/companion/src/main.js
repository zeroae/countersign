import { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, Notification, safeStorage, shell, Tray } from 'electron';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { Session } from './session.js';
import { integratorOrigin, approvalHint, displayText } from './origins.js';
import { readTheme } from './theme.js';
import { startsAtLogin, setStartAtLogin } from './login.js';
import { PairingStore } from './store.js';

const require = createRequire(import.meta.url);
const path = relative => fileURLToPath(new URL(relative, import.meta.url));
const rendererUrl = new URL('index.html', import.meta.url).href;
const sessions = new Map();
let win, tray, store, native, exiting = false, pendingHint, accountConfirmation;
function changed() { if (!win?.isDestroyed()) win?.webContents.send('desktop:changed'); }
function show() { win?.show(); win?.focus(); }
function handleHint(raw) {
  const id = approvalHint(raw);
  if (!id) return;
  pendingHint = id;
  show();
  // A cold start synchronizes each authenticated inbox. Never send the hint
  // to a guessed Broker or use the ID itself as evidence of authorization.
  for (const session of sessions.values()) if (session.device) session.send('inbox', {});
}

function attach(record) {
  const s = new Session({ record, store, native, decodeLogo: bytes => nativeImage.createFromBuffer(bytes),
    launchPairing: async (origin, attempt) => {
      const url = new URL('/countersign/pair', origin);
      url.searchParams.set('attempt', attempt);
      await shell.openExternal(url.href);
    },
    confirmAccount: (origin, user, code) => new Promise(resolve => {
      accountConfirmation?.finish(false);
      const timer = setTimeout(() => confirmation.finish(false), 55000);
      const confirmation = { id: randomUUID(), origin, user, code, finish: answer => {
        clearTimeout(timer);
        if (accountConfirmation === confirmation) accountConfirmation = undefined;
        resolve(answer);
        changed();
      } };
      accountConfirmation = confirmation;
      show();
      changed();
    }),
  });
  sessions.set(record.id, s);
  s.on('changed', () => {
    if (pendingHint) {
      const matches = [...sessions.values()].filter(item => item.offers.has(pendingHint));
      if (matches.length === 1) { pendingHint = undefined; show(); }
    }
    changed();
  });
  s.on('hint', id => {
    if (typeof id !== 'string' || !Notification.isSupported()) return;
    const notice = new Notification({title:'Countersign', body:'A certificate approval request is available.'});
    notice.on('click', show);
    notice.show();
  });
  s.on('expiring', () => {
    if (!Notification.isSupported()) return;
    const notice = new Notification({title:'Countersign', body:'A certificate approval expires within five minutes.'});
    notice.on('click', show);
    notice.show();
  });
  s.updateReminders();
  s.once('enroll-failed', () => {
    if (!s.record.pairing) {
      sessions.delete(record.id);
      void native.retirePairingKey(record.locator).catch(() => {});
      changed();
    }
  });
  s.open();
}

function certLabel(raw) {
  try { return displayText(raw, 1024); }
  catch { return 'See certificate fingerprint'; }
}

function installHandlers() {
  function action(name, callback) {
    ipcMain.handle('desktop:' + name, (event, ...args) => {
      if (event.sender !== win?.webContents || event.senderFrame !== win.webContents.mainFrame ||
          event.senderFrame.url !== rendererUrl) throw new Error('Untrusted frame.');
      return callback(...args);
    });
  }
  function findOffer(handle) {
    for (const s of sessions.values()) {
      for (const offer of s.offers.values()) if (offer.handle === handle) return [s, offer];
    }
    throw new Error('This request has ended.');
  }
  action('snapshot', () => {
    const all = [...sessions.values()];
    return {
      pairings: all.filter(s => s.record.pairing).map(s => ({
        id:s.record.id, origin:s.record.origin, user:s.record.user, status:s.status,
        theme:s.record.theme, pendingTheme:s.record.pendingTheme,
        devices:s.devices.filter(d=>d.binding.pairing!==s.record.pairing),
        notices:s.notices,
        approvals:Object.entries(s.record.receipts ?? {}).filter(([,r]) => r.until > Date.now() || r.revocation === 'pending').map(([id,r]) => ({
          id, host:r.host || r.scope.pattern, scope:r.scope.pattern, context:r.workload.context, until:r.until,
          fingerprint:Buffer.from(r.cert,'base64').toString('hex'), revocation:r.revocation,
          ready:[...s.activations.values()].includes(id),
        })),
      })),
      confirmation: accountConfirmation && {id:accountConfirmation.id,origin:accountConfirmation.origin,
        user:accountConfirmation.user,code:accountConfirmation.code},
      pending: all.filter(s => !s.record.pairing).map(s => s.record.origin + ' · ' + s.status).join('\n'),
      login: startsAtLogin(app),
      offers: all.flatMap(s => [...s.offers.values()].filter(o => o.body.expires_at_ms > Date.now()).map(o => ({
        handle:o.handle, origin:s.record.origin, user:s.record.user, theme:s.record.theme,
        context:o.body.workload.context, host:o.body.initiating_host, scope:o.body.scope.pattern,
        providerUnavailable:o.providerUnavailable,
        maxDuration:o.body.max_duration_s, defaultDuration:o.body.default_duration_s,
        identities:o.identities.map(i => ({reference:i.selection, identity:certLabel(i.subject), issuer:certLabel(i.issuer),
          expiresAt:i.expiresAtMs, fingerprint:Buffer.from(i.certSha256,'base64').toString('hex')})),
      }))),
    };
  });
  let enrolling = false;
  action('pair', async input => {
    const origin = integratorOrigin(input);
    if (enrolling || [...sessions.values()].some(s => !s.record.pairing)) throw new Error('Finish pending enrollment.');
    enrolling = true;
    try {
      const theme = await readTheme(origin, fetch, bytes => nativeImage.createFromBuffer(bytes)).catch(() => null);
      const authority = new URL(origin);
      const { locator, publicSec1 } = await native.createPairingKey(authority.hostname + ':' + (authority.port || '443'));
      attach({ id:randomUUID(), origin, locator, publicSec1, theme, pendingTheme:null });
      changed();
    } finally { enrolling = false; }
  });
  action('confirmPair', (id, answer) => {
    if (!accountConfirmation || id !== accountConfirmation.id || typeof answer !== 'boolean') throw new Error('Stale confirmation.');
    accountConfirmation.finish(answer);
  });
  action('decide', (handle, selection, seconds) => {
    if (typeof selection !== 'string' || !selection) throw new Error('Select a certificate.');
    const [s,offer] = findOffer(handle);
    return s.decide(offer,selection,seconds);
  });
  action('deny', handle => {
    const [s,offer] = findOffer(handle);
    return s.decide(offer,null,0);
  });
  action('login', enabled => {
    if (typeof enabled !== 'boolean') throw new TypeError();
    setStartAtLogin(app, enabled);
  });
  action('theme', async (id,digest) => {
    const s = sessions.get(id);
    if (!s) throw new Error('Unknown pairing.');
    await store.update(id, r => {
      if (!r?.pendingTheme || r.pendingTheme.digest !== digest) throw new Error('Branding changed.');
      return {...r, theme:r.pendingTheme, pendingTheme:null};
    });
    s.record = store.get(id);
    changed();
  });
  action('forgetOthers', (id, ids, all) => {
    const s = sessions.get(id);
    if (!s?.device || !Array.isArray(ids) || !ids.length || typeof all !== 'boolean') throw new Error('Stale devices.');
    const others = s.devices.filter(d => d.binding.pairing !== s.record.pairing);
    const targets = ids.map(({pairing,channel_generation}) => {
      const match = others.find(d=>d.binding.pairing===pairing && d.binding.channel_generation===channel_generation);
      if (!match) throw new Error('Device list changed.');
      return match.binding;
    });
    if (all && targets.length !== others.length) throw new Error('Device list changed.');
    s.send('forget_devices', { targets, all_others:all });
  });
  action('revoke', async (id, approval) => {
    const session = sessions.get(id);
    if (!session?.record.receipts?.[approval]) throw new Error('Unknown approval.');
    await session.revoke(approval);
  });
  action('removeLocal', async id => {
    const session = sessions.get(id);
    if (!session?.record.pairing) throw new Error('Unknown pairing.');
    session.stop();
    await native.retirePairingKey(session.record.locator);
    await store.update(id, () => null);
    sessions.delete(id);
    changed();
  });
  action('forget', async id => {
    const s = sessions.get(id);
    if (!s?.record.pairing) throw new Error('Unknown pairing.');
    // The authenticated site owns remote revocation and its confirmation.
    // Retain the local device until the user has completed the remote action.
    const url = new URL('/countersign/devices',s.record.origin);
    url.searchParams.set('pairing',s.record.pairing);
    await shell.openExternal(url.href);
  });
}

function newWindow() {
  win = new BrowserWindow({width:660,height:760,minWidth:400,minHeight:400,show:false,
    backgroundColor:'#f7f8f6',webPreferences:{preload:path('preload.cjs'),sandbox:true,contextIsolation:true,
      nodeIntegration:false,webSecurity:true,webviewTag:false}});
  win.webContents.setWindowOpenHandler(() => ({action:'deny'}));
  win.webContents.on('will-navigate', event => event.preventDefault());
  win.webContents.session.setPermissionRequestHandler((_contents,_permission,answer) => answer(false));
  win.on('close', event => { if (!exiting) { event.preventDefault(); win.hide(); } });
  win.setMenu(null);
  return win.loadURL(rendererUrl);
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('before-quit', () => { exiting=true; for(const s of sessions.values()) s.stop(); });
  app.on('second-instance', (_event,argv) => { show(); for(const arg of argv) handleHint(arg); });
  app.on('open-url', (event,url) => { event.preventDefault(); handleHint(url); });
  app.on('activate',show);
  app.whenReady().then(async () => {
    native = require('../native/countersign-native.node');
    store = new PairingStore(app.getPath('userData'),safeStorage);
    await store.load();
    installHandlers();
    await newWindow();
    tray = new Tray(nativeImage.createFromPath(path('../assets/tray.png')).resize({width:20,height:20}));
    tray.setToolTip('Countersign');
    tray.setContextMenu(Menu.buildFromTemplate([{label:'Open Countersign',click:show},
      {type:'separator'},{label:'Quit',click:() => app.quit()}]));
    tray.on('click',show);
    if(app.isPackaged) app.setAsDefaultProtocolClient('countersign');
    for(const record of store.list()) attach(record);
    for(const arg of process.argv) handleHint(arg);
    if (!process.argv.includes('--tray') || pendingHint) show();
  }).catch(() => {
    dialog.showErrorBox('Countersign could not start','Check that the matching native addon is installed and the operating system credential store is available.');
    app.quit();
  });
}
