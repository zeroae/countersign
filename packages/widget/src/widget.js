import { approvalLink, isRequestId } from './hints.js';

// The Integrator supplies a session-bound backend adapter. It owns the user,
// Context, CSRF protection and any explanation of a denied request.
export class CountersignWidget extends HTMLElement {
  #adapter;
  #generation = 0;
  #busy = false;

  constructor() {
    super();
    const root = this.attachShadow({ mode: 'open' });
    root.innerHTML = `
      <style>
        :host { display: inline-block; font-family: var(--countersign-font, system-ui, sans-serif); }
        [part=actions] { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
        button, a { font: inherit; }
        a { color: var(--countersign-accent, LinkText); }
        [role=status]:empty { display: none; }
      </style>
      <div part="actions">
        <button type="button" data-action="pair">Pair Companion</button>
        <button type="button" data-action="connect">Request access</button>
        <a part="launch" hidden>Open Companion</a>
        <button type="button" data-action="push" hidden>Enable notifications</button>
      </div>
      <p role="status" part="status"></p>`;
    root.addEventListener('click', event => {
      const action = event.target.dataset?.action;
      if (action) void this.#run(action);
    });
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
    for (const button of this.shadowRoot.querySelectorAll('button')) {
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
