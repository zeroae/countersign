const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('countersign', {
  snapshot: () => ipcRenderer.invoke('desktop:snapshot'),
  pair: origin => ipcRenderer.invoke('desktop:pair', origin),
  confirmPair: (id, answer) => ipcRenderer.invoke('desktop:confirmPair', id, answer),
  decide: (offer, selection, seconds) => ipcRenderer.invoke('desktop:decide', offer, selection, seconds),
  deny: offer => ipcRenderer.invoke('desktop:deny', offer),
  theme: (pairing, digest) => ipcRenderer.invoke('desktop:theme', pairing, digest),
  forgetOthers: (pairing, ids, all) => ipcRenderer.invoke('desktop:forgetOthers', pairing, ids, all),
  forget: pairing => ipcRenderer.invoke('desktop:forget', pairing),
  login: enabled => ipcRenderer.invoke('desktop:login', enabled),
  changed: callback => {
    const listener = () => callback();
    ipcRenderer.on('desktop:changed', listener);
    return () => ipcRenderer.removeListener('desktop:changed', listener);
  },
});
