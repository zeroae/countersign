import { createHash } from 'node:crypto';
import { displayText, integratorOrigin, sameOriginUrl } from './origins.js';

async function fetchBytes(url, limit, fetcher) {
  const response = await fetcher(url, {
    redirect: 'error',
    credentials: 'omit',
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok || !response.body) throw new Error('Cannot retrieve Integrator theme.');
  const chunks = [];
  let total = 0;
  for await (const chunk of response.body) {
    total += chunk.byteLength;
    if (total > limit) throw new Error('Theme exceeds size limit.');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function color(input) {
  if (typeof input !== 'string' || !/^#[a-fA-F0-9]{6}$/.test(input)) {
    throw new Error('Expected a six-digit theme color.');
  }
  return input.toLowerCase();
}

// Accept PNG only. Check dimensions before the desktop decoder allocates, then
// re-encode the decoded image so that only local raster bytes reach the UI.
async function logoData(origin, locator, fetcher, decodeLogo) {
  const bytes = await fetchBytes(sameOriginUrl(origin, locator), 128 * 1024, fetcher);
  if (bytes.length < 33 || bytes.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a' ||
      bytes.readUInt32BE(8) !== 13 || bytes.toString('ascii', 12, 16) !== 'IHDR') {
    throw new Error('Expected a PNG logo.');
  }
  const width = bytes.readUInt32BE(16);
  const height = bytes.readUInt32BE(20);
  if (!width || !height || width > 512 || height > 512) throw new Error('Invalid logo dimensions.');
  const image = decodeLogo(bytes);
  if (image.isEmpty()) throw new Error('Invalid PNG logo.');
  const logo = image.toPNG();
  if (logo.length > 512 * 1024) throw new Error('Decoded logo too large.');
  return 'data:image/png;base64,' + logo.toString('base64');
}

export async function readTheme(origin, fetcher, decodeLogo) {
  origin = integratorOrigin(origin);
  const bytes = await fetchBytes(new URL('/.well-known/countersign.json', origin), 8192, fetcher);
  const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (manifest.version !== 1) throw new Error('Unsupported theme manifest.');
  const theme = {
    name: displayText(manifest.displayName, 80),
    copy: displayText(manifest.copy ?? '', 240),
    accent: color(manifest.colors?.accent ?? '#164e63'),
    background: color(manifest.colors?.background ?? '#ffffff'),
    logo: manifest.logo === undefined ? null :
      await logoData(origin, displayText(manifest.logo, 1024), fetcher, decodeLogo),
  };
  const digest = createHash('sha256').update(JSON.stringify(theme)).digest('hex');
  return { digest, ...theme };
}

export function refreshTheme(pairing, downloaded) {
  if (pairing.theme?.digest === downloaded.digest) {
    return { ...pairing, pendingTheme: null };
  }
  return { ...pairing, pendingTheme: downloaded };
}
