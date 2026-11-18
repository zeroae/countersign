export function integratorOrigin(input) {
  const url = new URL(input);
  if (url.protocol !== 'https:' || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash || url.origin === 'null') {
    throw new Error('Enter an HTTPS Integrator origin.');
  }
  return url.origin;
}

export function approvalHint(value) {
  const match = /^countersign:\/\/approve\/([a-zA-Z0-9_-]{22,128})$/.exec(value);
  return match?.[1];
}

export function sameOriginUrl(origin, path) {
  const url = new URL(path, origin);
  if (url.origin !== origin || url.username || url.password) {
    throw new Error('Unexpected Integrator origin.');
  }
  return url;
}

export function displayText(text, max = 160) {
  if (typeof text !== 'string' || text.length > max ||
      /[\p{Cc}\p{Cf}\u2028\u2029]/u.test(text)) {
    throw new Error('Invalid display text.');
  }
  return text;
}
