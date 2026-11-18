// Approval queue rules, shared by the main process and the renderer, so it
// uses no Node or DOM APIs.

// Oldest request first. Requests that arrived in the same millisecond keep a
// stable order.
export function orderQueue(offers) {
  return [...offers].sort((a, b) => a.received - b.received || (a.handle < b.handle ? -1 : a.handle > b.handle ? 1 : 0));
}

export function originHost(origin) {
  return new URL(origin).host;
}

// What the window does when the request on screen changes. Any newly shown
// request locks Approve briefly, so a click meant for the previous screen
// cannot approve it. A request from a different pairing also announces the
// change, because the window's colours change with it.
export function headChange(previous, next) {
  if (!next || next.handle === previous?.handle) return { lock: false, banner: null };
  const switched = !!previous && previous.pairing !== next.pairing;
  return { lock: true, banner: switched ? 'Now showing a request from ' + originHost(next.origin) : null };
}

export const LOCK_MS = 1000;
