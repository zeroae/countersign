# Control protocol

The desktop speaks `countersign.v1` over an outbound WebSocket at `/v1/companion` on its paired HTTPS origin. The Gateway sends one versioned frame in each HTTPS POST under `/v1/gateway/`. Integrator application backends use a separate [Broker API](api.md).

## Frame

This authenticated Companion request lists the opaque IDs in its inbox.

```json
{"version":1,"request_id":"list-1","type":"inbox","body":{}}
```

The envelope has four required fields. `request_id` correlates a request and reply on the channel. The decoder chooses the permitted message types for that direction, rejects unsupported versions and unknown fields, and bounds the original JSON before decoding the body. Treat IDs in notifications as lookup hints. An authenticated fetch returns the authoritative offer. [Envelope and message definitions](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-protocol/src/wire/mod.rs)

| Wire value | Bound or encoding |
|---|---|
| Frame and nesting | At most 1 MiB and 24 JSON nesting levels |
| Opaque ID | 1–256 UTF-8 bytes, without control characters |
| Fingerprint | 32 SHA-256 bytes, standard base64 on the wire. The UI displays hex. |
| Public DER chain | 1–16 certificates, at most 256 KiB decoded in total |
| TLS signing input / signature | Nonempty base64 strings, at most 256 KiB / 2,048 bytes decoded |
| Device proof | Compact JWS, base64url without padding, signed by the pairing key |

The protocol uses Unix milliseconds for absolute times and separate numeric fields for duration and lease budget. [Wire value validation](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-protocol/src/wire/values.rs)

## Companion channel

| Stage | Traffic | Binding checked |
|---|---|---|
| Pair or reconnect | `enroll` with a public P-256 key, or `authenticate` with the existing pairing and key IDs. Answer the Broker's `challenge` with `proof`. | One challenge binds the origin, user, key, connection, purpose, nonce and expiry. Pairing also requires authenticated browser and local confirmation. Reconnecting establishes a new channel generation. |
| Find requests | `notify` or `inbox`, followed by `fetch` → `offer`. | The offer carries its own ID, approval version, target device, Workload, initiating host, effective scope, certificate hints and duration limits. |
| Decide | `decide` on that offer with approval, denial or cancellation. | Approval includes the selected public chain, fingerprint and duration. A concurrent decision on another eligible Companion can win first. |
| Activate | The Broker sends `activate`. The winning Companion checks its local approval receipt and replies `activated`. | The grant binds the winning device, job, worker, destination scope and certificate. The Broker reports readiness separately from a committed approval. |
| Sign | `sign` → `signed`, or `cancel` / `error`. | Each operation carries the full grant, exact host, TLS connection and operation ID. The request names the TLS version, signature scheme, handshake input and deadline. |
| Retire or revoke | The Broker can send `retire`. The Companion can send `revoke_approval` and receives `revoke_recorded` once recorded. | An offline queued action stays distinguishable from a recorded revocation. |

## Gateway operations

The Gateway supplies a Workload bearer token and its boot identity in `X-Countersign-Gateway-Instance`. A shared Gateway also supplies its independent service credential in `X-Countersign-Gateway`. The Broker checks the token audience, Workload generation and scope. A single process cannot claim an existing grant assigned to another supervisor.

| POST suffix | Message type | Use |
|---|---|---|
| `connect`, `lookup` | `connect`, `lookup` | Admit a Workload and host, then retrieve the pending or activated decision. |
| `lease` | `renew_lease` | Request a bounded lease for one ingress or egress enforcer, instance, generation and sequence. |
| `sign`, `cancel` | `sign`, `cancel` | Request or cancel the signature for one handshake. The Broker holds an independent lease while relaying it. |
| `watch` | `watch` | Wait for retirement of the bound grant. All traffic relays still maintain lease deadlines. |
| `observed` | `observed` | Report upstream mTLS acceptance or a socket closure for a particular connection and enforcer. |

An approval ID alone cannot address a signer. A changed pairing channel, certificate, Workload or worker generation changes the binding. Late signatures are discarded after cancellation, expiry or loss of that binding. The Gateway verifies correlation and the returned signature before using it in TLS. [Gateway operations](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-broker/src/service/gateway.rs) · [Protocol compatibility and rejection tests](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-protocol/tests/wire.rs)
