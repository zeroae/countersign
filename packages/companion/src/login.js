import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

function desktopFile() {
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'autostart', 'countersign-companion.desktop');
}

export function startsAtLogin(app) {
  return process.platform === 'linux' ? existsSync(desktopFile()) : app.getLoginItemSettings().openAtLogin;
}

export function setStartAtLogin(app, enabled) {
  if (!app.isPackaged) throw new Error('Install the Companion to enable login startup.');
  if (process.platform !== 'linux') {
    app.setLoginItemSettings({ openAtLogin: enabled, args: ['--tray'] });
    return;
  }
  const file = desktopFile();
  if (!enabled) {
    rmSync(file, { force: true });
    return;
  }
  const executable = process.env.APPIMAGE || process.execPath;
  if (/[\r\n]/.test(executable)) throw new Error('Invalid installation path.');
  const quoted = executable.replace(/["`$\\]/g, '\\$&').replaceAll('%', '%%');
  mkdirSync(join(file, '..'), { mode: 0o700, recursive: true });
  writeFileSync(file + '.tmp', [
    '[Desktop Entry]', 'Type=Application', 'Name=Countersign',
    `Exec="${quoted}" --tray`, 'Terminal=false', '',
  ].join('\n'), { mode: 0o600 });
  renameSync(file + '.tmp', file);
}
