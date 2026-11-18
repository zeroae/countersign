// Static routes of the demo Integrator, relative to this directory. The
// screenshot script (scripts/capture_screenshots.mjs) serves the same map.
export const files = new Map([
  ['/', ['site/index.html','text/html']], ['/countersign/pair',['site/index.html','text/html']],
  ['/countersign/devices',['site/index.html','text/html']], ['/job',['site/index.html','text/html']],
  ['/app.js',['site/app.js','text/javascript']], ['/site.css',['site/site.css','text/css']],
  ['/harbor-ledger.png',['site/harbor-ledger.png','image/png']],
  ['/sw.js',['site/sw.js','text/javascript']], ['/widget.js',['../../packages/widget/src/widget.js','text/javascript']],
  ['/hints.js',['../../packages/widget/src/hints.js','text/javascript']],
  ['/service-worker.js',['../../packages/widget/src/service-worker.js','text/javascript']],
]);

export const contentSecurityPolicy =
  "default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

// The fictional brand the Companion shows for this demo.
export const manifest = {version:1,displayName:'Harbor Ledger',copy:'Client reporting workspace',
  logo:'/harbor-ledger.png',colors:{accent:'#0f6b6b',background:'#eef6f4'}};
