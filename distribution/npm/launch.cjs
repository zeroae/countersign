#!/usr/bin/env node
const { spawn } = require('node:child_process');
const path = require('node:path');
const { name, version, optionalDependencies } = require('./package.json');

function main() {
  const target = name + '-' + process.platform + '-' + process.arch;
  if (!optionalDependencies[target]) throw new Error('Unsupported target: ' + target);
  let manifest;
  try {
    manifest = require.resolve(target + '/package.json');
  } catch {
    throw new Error('Install ' + name + ' with optional dependencies enabled to obtain ' + target);
  }
  const payload = require(manifest);
  if (payload.version !== version) throw new Error('Unexpected binary package version: ' + payload.version);
  const installer = path.join(path.dirname(manifest), payload.installer);
  if (process.argv.length === 3 && process.argv[2] === '--print-path') {
    console.log(installer);
    return;
  }
  if (process.argv.length > 2) throw new Error('Usage: countersign [--print-path]');
  const child = process.platform === 'darwin'
    ? spawn('/usr/bin/open', [installer], { stdio: 'inherit' })
    : spawn(installer, [], { stdio: 'inherit' });
  child.on('error', error => { console.error(error.message); process.exitCode = 1; });
  child.on('exit', code => { process.exitCode = code ?? 1; });
}
try {
  main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
