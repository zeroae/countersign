import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('..', import.meta.url));
const read = name => readFileSync(here + name, 'utf8');

// The image's servers fail at startup on a local module the Dockerfile leaves out.
test('the image copies every local module the servers import', () => {
  const copied = new Set(read('Dockerfile').split('\n').filter(line => line.startsWith('COPY '))
    .flatMap(line => line.split(/\s+/).slice(1, -1))
    .map(path => path.replace('examples/demo-integrator/', '')));
  const seen = new Set();
  const visit = name => {
    if (seen.has(name)) return;
    seen.add(name);
    for (const [, local] of read(name).matchAll(/from '\.\/([^']+)'/g)) visit(local);
  };
  visit('integrator.js');
  visit('upstream.js');
  assert.deepEqual([...seen].filter(name => !copied.has(name)), []);
});
