<h1><picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/wordmark-white.svg">
  <img src="docs/assets/wordmark.svg" width="360" alt="Countersign">
</picture></h1>

Give a remote job temporary access to an HTTPS service that requires a client certificate installed on your desktop. You choose the certificate, destination scope, and duration in the Companion. Your machine signs the TLS handshake. Your Integrator’s Gateway completes it and can read the traffic.

<img src="docs/assets/screenshots/approval-selected.png" width="520" alt="Countersign approval on Linux showing the verified Integrator, requested host, two certificates, a selected fingerprint, duration, and Approve and Deny controls.">

**[Try it with curl](docs/try.md).** Pair the Companion with the demo Integrator, pick one of the installed certificates, and compare its fingerprint with the one returned by the mTLS site. The demo runs its services and curl in Docker Compose. The Companion runs on your Linux desktop.

## Use Countersign

| If you… | Start here |
|---|---|
| Received a pairing or approval request | [Install and use the Companion](docs/companion.md) |
| Own the application that starts jobs for users | [Integrate your service](docs/integrate.md) |
| Run the Gateway and Broker | [Self-host and operate](docs/operate.md) |
| Need to know where keys and plaintext go | [Architecture and trust diagram](docs/architecture.md) |
| Need evidence for a particular OS, provider, or installer | [Tested platforms](docs/reference/support.md) |

## How the handshake works

[![Countersign architecture showing the Workload and Gateway, the separate TLS connection to the protected site, and the desktop signing through the Broker.](docs/assets/diagrams/architecture.svg)](docs/architecture.md)

Each Integrator hosts its own Broker and Gateway. Solid arrows carry the job's traffic. Dashed arrows carry authorization and signing messages. One desktop Companion can pair with several Integrators. The default Gateway runs beside one Workload. A shared Gateway is also available for Linux hosts.

## Read the handbook locally

From the checkout, run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-docs.txt
.venv/bin/python -m mkdocs serve
```

Open the local address printed by MkDocs. For native builds, installers, and the local conda package, see [Develop and release](docs/develop.md).

## License

[MIT](LICENSE), copyright 2026 Zero A.E., LLC.
