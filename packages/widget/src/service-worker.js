import { isRequestId } from './hints.js';

// Register in the Integrator's service worker. The server sends a JSON string
// containing only the request ID. The target page does its own session check.
export function installPushHandlers(worker, page) {
  const url = new URL(page, worker.location.href);
  if (url.protocol !== 'https:' || url.origin !== worker.location.origin ||
      url.username || url.password) {
    throw new TypeError('Expected an HTTPS page on the Integrator origin');
  }

  worker.addEventListener('push', event => {
    let id;
    try {
      id = event.data?.json();
    } catch {
      return;
    }
    if (!isRequestId(id)) return;
    event.waitUntil(worker.registration.showNotification('Countersign approval requested', {
      tag: `countersign-${id}`,
      data: id,
    }));
  });

  worker.addEventListener('notificationclick', event => {
    const id = event.notification.data;
    if (!isRequestId(id) || event.notification.tag !== `countersign-${id}`) return;
    const target = new URL(url);
    target.hash = new URLSearchParams({ countersign: id }).toString();
    event.notification.close();
    event.waitUntil(worker.clients.openWindow(target.href));
  });
}
