import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { Window } from 'happy-dom';
import { installPushHandlers } from '../src/service-worker.js';

const window = new Window({ url: 'https://integrator.test/' });
globalThis.HTMLElement = window.HTMLElement;
globalThis.customElements = window.customElements;
const { subscribeForPush } = await import('../src/widget.js');
after(() => window.close());
const id = 'uOeXd8ifq5um1Xl42w5sYg';
const nextTurn = () => new Promise(resolve => setImmediate(resolve));

function widget(connect) {
  const el = window.document.createElement('countersign-widget');
  window.document.body.append(el);
  el.adapter = { connect, pair: async () => {} };
  return el;
}

test('user can launch an ID-only link after requesting access', async () => {
  const el = widget(async () => id);
  const link = el.shadowRoot.querySelector('a');
  assert.equal(link.hidden, true);
  el.shadowRoot.querySelector('[data-action=connect]').click();
  await nextTurn();
  assert.equal(link.href, 'countersign://approve/' + id);
  assert.equal(link.hidden, false);
  el.remove();
});

test('malformed IDs and responses from a previous account cannot present a link', async () => {
  let complete;
  const el = widget(() => new Promise(resolve => { complete = resolve; }));
  const connect = el.shadowRoot.querySelector('[data-action=connect]');
  const link = el.shadowRoot.querySelector('a');
  connect.click();
  el.adapter = { connect: async () => id + '?broker=other', pair: async () => {} };
  complete(id);
  await nextTurn();
  assert.equal(link.hasAttribute('href'), false);
  connect.click();
  await nextTurn();
  assert.equal(link.hidden, true);
  assert.equal(link.hasAttribute('href'), false);
  el.remove();
});

test('Web Push registration saves the browser subscription to the Integrator', async () => {
  const registration = { pushManager: {
    getSubscription: async () => null,
    subscribe: async options => {
      assert.deepEqual(options, { userVisibleOnly: true, applicationServerKey: 'key' });
      return { toJSON: () => ({ endpoint: 'https://push.test/subscription' }) };
    },
  } };
  let saved;
  await subscribeForPush(registration, 'key', value => { saved = value; });
  assert.equal(saved.endpoint, 'https://push.test/subscription');
});

test('service worker accepts only ID hints and opens a fixed same-origin page', async () => {
  const handlers = {};
  const notices = [];
  const pages = [];
  const worker = {
    location: new URL('https://integrator.test/sw.js'),
    addEventListener: (name, callback) => { handlers[name] = callback; },
    registration: { showNotification: async (...args) => { notices.push(args); } },
    clients: { openWindow: async url => { pages.push(url); } },
  };
  assert.throws(() => installPushHandlers(worker, 'https://other.test/'));
  installPushHandlers(worker, '/access');
  const waits = [];
  const waitUntil = value => waits.push(value);
  for (const value of [{ id, grant: 'fake' }, 'https://other.test/', id]) {
    handlers.push({ data: { json: () => value }, waitUntil });
  }
  await Promise.all(waits);
  assert.equal(notices.length, 1);
  const [, options] = notices[0];
  assert.equal(options.data, id);
  handlers.notificationclick({ notification: { ...options, close() {} }, waitUntil });
  await Promise.all(waits);
  assert.deepEqual(pages, ['https://integrator.test/access#countersign=' + id]);
});
