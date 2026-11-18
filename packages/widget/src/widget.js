import { approvalLink, isRequestId } from './hints.js';

// Default look: a Countersign card with a purple band. Every value is a custom
// property or a shadow part, so an Integrator can restyle it from the page.
// light-dark() follows the page's color-scheme; a page that declares none
// keeps the light palette.
const STYLE = `
  :host {
    --_band: var(--countersign-band, #2b0548);
    --_band-ink: var(--countersign-band-ink, #ffffff);
    --_surface: var(--countersign-surface, light-dark(#faf8fc, #1d1724));
    --_line: var(--countersign-line, light-dark(#d9cfe2, #3d3149));
    --_ink: var(--countersign-ink, light-dark(#251c2b, #ece4f2));
    --_muted: var(--countersign-muted, light-dark(#54485e, #c3b5cf));
    --_primary: var(--countersign-primary, light-dark(#224805, #a1ca7c));
    --_primary-ink: var(--countersign-primary-ink, light-dark(#ffffff, #14240a));
    --_link: var(--countersign-accent, light-dark(#442063, #c49bdf));
    display: block;
    font-family: var(--countersign-font, system-ui, sans-serif);
    color: var(--_ink);
  }
  [hidden] { display: none !important; }
  [part=card] { border: 1px solid var(--_line); border-radius: 10px; overflow: hidden; background: var(--_surface); }
  [part=header] { display: flex; align-items: center; gap: 10px; padding: 12px 16px; background: var(--_band); color: var(--_band-ink); }
  [part=mark] { width: 22px; height: 22px; fill: currentColor; flex: none; }
  .divider { width: 1px; height: 20px; background: currentColor; opacity: .7; }
  [part=wordmark] { font-size: 1.125em; font-weight: 300; letter-spacing: .02em; line-height: 1; }
  [part=body] { display: flex; flex-direction: column; gap: 14px; padding: 18px 16px 20px; }
  [part=headline] { margin: 0; font-size: 1.375em; font-weight: 300; line-height: 1.25; }
  [part=actions] { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  button, a { font: inherit; font-size: .9375em; }
  button { min-height: 44px; padding: 0 16px; border-radius: 6px; border: 1px solid var(--_line);
    background: var(--_surface); color: var(--_ink); cursor: pointer; }
  button[part~=primary] { background: var(--_primary); border-color: var(--_primary); color: var(--_primary-ink); font-weight: 600; }
  button:disabled { cursor: default; opacity: .55; }
  a { display: inline-flex; align-items: center; min-height: 44px; padding: 0 4px; color: var(--_link); }
  button:focus-visible, a:focus-visible { outline: 3px solid var(--_link); outline-offset: 2px; }
  [part=status] { margin: 0; font-size: .9375em; line-height: 1.45; color: var(--_muted); }
  [role=status]:empty { display: none; }
`;

// A constructed stylesheet is not an inline <style>, so pages with a strict
// style-src Content Security Policy still get the default look.
let sheet;
function adoptStyles(root) {
  if (typeof CSSStyleSheet === 'function' && 'replaceSync' in CSSStyleSheet.prototype && 'adoptedStyleSheets' in root) {
    if (!sheet) {
      sheet = new CSSStyleSheet();
      sheet.replaceSync(STYLE);
    }
    root.adoptedStyleSheets = [sheet];
  } else {
    const style = root.ownerDocument.createElement('style');
    style.textContent = STYLE;
    root.prepend(style);
  }
}

// The Integrator supplies a session-bound backend adapter. It owns the user,
// Context, CSRF protection and any explanation of a denied request.
export class CountersignWidget extends HTMLElement {
  #adapter;
  #generation = 0;
  #busy = false;

  static observedAttributes = ['paired'];

  constructor() {
    super();
    const root = this.attachShadow({ mode: 'open' });
    root.innerHTML = `
      <div part="card" role="group" aria-label="Countersign">
        <div part="header" aria-hidden="true">
          <svg part="mark" viewBox="0 0 32 32"><rect x="3" y="8" width="18" height="6"/><rect x="11" y="18" width="18" height="6"/></svg>
          <span class="divider"></span>
          <span part="wordmark">countersign</span>
        </div>
        <div part="body">
          <p part="headline"><slot name="headline">Approve with your desktop</slot></p>
          <div part="actions">
            <button type="button" data-action="pair">Pair Companion</button>
            <button type="button" data-action="connect">Request access</button>
            <a part="launch" hidden>Open Companion</a>
            <button type="button" data-action="push" hidden>Enable notifications</button>
          </div>
          <p role="status" part="status"></p>
        </div>
      </div>`;
    adoptStyles(root);
    root.addEventListener('click', event => {
      const action = event.target.closest?.('[data-action]')?.dataset.action;
      if (action) void this.#run(action);
    });
    this.#renderControls();
  }

  // `paired` moves the primary emphasis from Pair Companion to Request access.
  attributeChangedCallback() {
    this.#renderControls();
  }

  set adapter(value) {
    if (value != null &&
        (typeof value.pair !== 'function' || typeof value.connect !== 'function')) {
      throw new TypeError('The adapter must implement pair() and connect()');
    }
    this.#adapter = value;
    this.#reset();
  }

  get adapter() {
    return this.#adapter;
  }

  disconnectedCallback() {
    this.#reset();
  }

  // Call with an owned ID returned by the Integrator backend after the user
  // signs in, including when arriving from a notification click.
  showRequest(id) {
    const link = this.shadowRoot.querySelector('a');
    link.href = approvalLink(id);
    link.hidden = false;
    this.#status('Review this request in your Companion.');
  }

  #reset() {
    this.#generation++;
    this.#busy = false;
    this.shadowRoot.querySelector('a').hidden = true;
    this.shadowRoot.querySelector('a').removeAttribute('href');
    this.#status('');
    this.#renderControls();
  }

  #status(message) {
    this.shadowRoot.querySelector('[role=status]').textContent = message;
  }

  #renderControls() {
    const primary = this.hasAttribute('paired') ? 'connect' : 'pair';
    for (const button of this.shadowRoot.querySelectorAll('button')) {
      const action = button.dataset.action;
      button.setAttribute('part', 'button ' + action + (action === primary ? ' primary' : ''));
      button.disabled = !this.#adapter || this.#busy;
      if (button.dataset.action === 'push') {
        button.hidden = typeof this.#adapter?.subscribe !== 'function';
      }
    }
  }

  async #run(action) {
    if (!this.#adapter || this.#busy) return;
    const generation = this.#generation;
    this.#busy = true;
    this.#renderControls();
    try {
      if (action === 'pair') {
        await this.#adapter.pair();
        if (generation === this.#generation) this.#status('Continue pairing in your Companion.');
      } else if (action === 'connect') {
        this.shadowRoot.querySelector('a').hidden = true;
        const id = await this.#adapter.connect();
        if (generation !== this.#generation) return;
        if (!isRequestId(id)) throw new TypeError('Invalid request ID');
        this.showRequest(id);
      } else if (action === 'push') {
        await this.#adapter.subscribe();
        if (generation === this.#generation) this.#status('Notifications enabled.');
      }
    } catch {
      if (generation === this.#generation) this.#status('This action could not be completed. Try again.');
    } finally {
      if (generation === this.#generation) {
        this.#busy = false;
        this.#renderControls();
      }
    }
  }
}

// Call from the subscription adapter on a user gesture. Hand the result to
// the Integrator backend before reporting successful registration.
export async function subscribeForPush(registration, applicationServerKey, save) {
  const manager = registration.pushManager;
  const subscription = await manager.getSubscription() ??
    await manager.subscribe({ userVisibleOnly: true, applicationServerKey });
  await save(subscription.toJSON());
}

customElements.define('countersign-widget', CountersignWidget);
