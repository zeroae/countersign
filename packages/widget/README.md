# @zeroae/countersign-widget

Add pairing and certificate-approval controls to an authenticated web page in a Countersign integration.

```sh
npm install @zeroae/countersign-widget
```

Import `@zeroae/countersign-widget` to register the `<countersign-widget>` element. Set its `adapter` property to connect it to your backend. The service worker entry point exports `installPushHandlers` for Web Push notifications.

The element renders a Countersign card with a purple header band and its own buttons. It follows the page's `color-scheme` and works under a strict Content Security Policy. Restyle it with `--countersign-*` custom properties and shadow parts such as `::part(card)`, `::part(button)` and `::part(primary)`. Add the `paired` attribute once the account has a paired Companion, and put page-specific text in the `headline` slot.

[Widget and adapter reference](https://zeroae.github.io/countersign/reference/widget/) · [Styling hooks](https://zeroae.github.io/countersign/reference/widget/#style-the-web-controls) · [Demo Integrator](https://github.com/zeroae/countersign/tree/main/examples/demo-integrator)
