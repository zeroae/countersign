# Broker HTTP API

The Integrator's backend authenticates users, checks Context ownership and selects the Workload and destination. Call the Broker over HTTPS with `Content-Type: application/json` and exactly one `Authorization: Bearer <credential>` header. The backend routes take plain JSON objects. The Gateway routes take versioned protocol frames. [Integration walkthrough](../integrate.md) · [Wire protocol](protocol.md)

| Caller | Credential | Routes |
| --- | --- | --- |
| Integrator backend | Secret from `backend_token_file` | `POST /v1/backend/*` |
| Integrator administrator | Separate secret from `admin_token_file` | `POST /v1/admin/control` |
| Sidecar Gateway | Short-lived Workload token with audience `countersign:broker:workload` | `POST /v1/gateway/*` |
| Shared Gateway | Workload token with audience `countersign:gateway:workload`, plus its own `X-Countersign-Gateway` service credential | `POST /v1/gateway/*` |
| Companion | Fresh pairing-key proof on its outbound WebSocket | `GET /v1/companion` upgrade, subprotocol `countersign.v1` |

Both Gateway modes send a stable boot UUID in `X-Countersign-Gateway-Instance`. Keep all backend, administrator and Gateway service credentials out of browser responses. [Credential verification](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-broker/src/credentials.rs)

## Bind the Workload

```http
POST /v1/backend/workloads HTTP/1.1
Content-Type: application/json
Authorization: Bearer <backend credential>

{"user":"u-42","context":"close-q3","workload":"export-981","workload_generation":1,"mode":"sidecar"}
```

The Broker returns HTTP 200 with the following shape. Token and timestamp values below are illustrative.

```json
{
  "binding": {
    "integrator": "finance",
    "user": "u-42",
    "context": "close-q3",
    "workload": "export-981",
    "workload_generation": 1
  },
  "token": "<signed Workload JWT>",
  "expires_at_ms": 1794960120000
}
```

Reuse the entire returned `binding` in subsequent calls. `mode` defaults to `sidecar`. Shared mode requires a configured Gateway service credential. A token lasts 120 seconds. Reissue for the same live generation to refresh it. Replacing a Workload with a higher generation withdraws its old approvals. A retired generation cannot be reopened. Each Broker boot starts a fresh token epoch. [Workload and approval handlers](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-broker/src/service/backend.rs)

## Backend operations

All paths in this table start with `/v1/backend/` and use POST. A 204 response has an empty body. For `renew`, `status` and `revoke`, pass the **approval ID** returned by `requests` or `renew`.

| Path | JSON request fields | Success |
| --- | --- | --- |
| `pairings/confirm` | `user`, `attempt` from the pairing page URL, `code` entered by the user | 204. The Companion can proceed to its own account confirmation and key proof. An incorrect code consumes the attempt. |
| `devices` | `user` | 200 with `{"devices":[…]}`. Each item carries `binding`, `connected`, `connected_at_ms` and nullable `observed_address`. |
| `pairings/forget` | `user`, `targets` array of current device bindings | 200 with the remaining devices. Removes the target pairings and withdraws their grants. |
| `requests` | `binding`, `host` such as `ledger.partner.example:443` | 200 with `{"id":"…","state":"pending"}` or an existing matching approved record. An explicit request can retry a previously denied, cancelled or expired scope. |
| `status` | `user`, `id` | 200 with the status and observations described below. |
| `renew` | `binding`, `id` of the live approved request | 200 with the new pending approval ID. The previous grant remains usable until its deadline or a successful replacement. |
| `revoke` | `user`, `id` | 204. Records withdrawal and cancels an outstanding renewal for that approval. Repeat calls for the same owned record are idempotent. |
| `workloads/retire` | `binding` | 204. Retires that Workload generation. |
| `contexts/close` | `user`, `context` | 204. Closes that user's Context and withdraws its pending and active approvals. |
| `push/subscribe` | `user`, `subscription` containing `endpoint` and `keys` (`p256dh`, `auth`) | 204. Requires configured Web Push, valid subscription keys and an allowed HTTPS push host. |
| `push/unsubscribe` | `user`, `endpoint` | 204. Removes the owner's subscription. |

Take device bindings directly from a fresh `devices` response. Each contains `pairing`, `key` and `channel_generation`. Show the user the selected devices before calling `pairings/forget`. A reconnect changes the generation. If the snapshot is stale, refresh the list and confirm the selection again. [Device and access controls](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-broker/src/service/controls.rs) · [Web Push registration](widget.md#web-push)

## Read approval status

```json
{
  "id": "85b80155-ac10-487f-a024-5216ec7f8ced",
  "state": "approved",
  "ready": true,
  "expires_at_ms": 1795470000000,
  "certificate": {
    "sha256": "c64a4b8b8bcdac1a7ac2bedcd13c520f4abfc07d5765d68df67f56ed0058f00b"
  },
  "upstream_mtls_accepted": false,
  "ingress_closed_count": 0,
  "egress_closed_count": 0
}
```

- `state` is `pending`, `approved`, `denied`, `cancelled`, `expired` or `replaced`. A pending offer has a ten-minute deadline. A successful renewal changes the predecessor's state to `replaced`.
- `ready` means the winning Companion acknowledged activation and its matching channel is currently connected. An approved grant can have `ready: false` while that Companion is offline.
- `expires_at_ms` and `certificate` describe the grant the user approved. They appear once an approval has a grant, and stay after it ends (`expired`, `cancelled` or `replaced`); a renewal's successor has its own approval ID and its own values. They are absent when the approval never had a grant: it is `pending`, `denied`, or it was `expired` or `cancelled` before anyone approved it. They are also absent once the [audit retention](config.md) period removes an ended approval's grant record.
- `expires_at_ms` is the deadline the user approved, in milliseconds since the Unix epoch, in whole seconds. It is not always when access ends: a revocation, a renewal or a Gateway lease can end it sooner, and `state` says whether the grant is still in force.
- `certificate.sha256` is the lowercase hex SHA-256 of the client certificate the user selected (its DER encoding). It is the fingerprint the Companion shows, without its spaces, of the certificate the protected site receives in the handshake.
- `upstream_mtls_accepted` is historical. It becomes true after the Gateway reports receiving upstream HTTP response headers on an authenticated connection.
- `ingress_closed_count` and `egress_closed_count` count distinct reported socket closures on the two legs. Reports are best effort. Enforcers cut traffic at their local lease deadline even if they cannot report back. [Gateway observations](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-broker/src/service/observations.rs)

## Administrator controls

`POST /v1/admin/control` returns 204. Each row is a complete example body. Changing the boolean to `false` clears that restriction. Previously withdrawn approvals require fresh consent.

| Effect | JSON body |
| --- | --- |
| Block the account | `{"operation":"account","user":"u-42","blocked":true}` |
| Deny an account access to a configured destination entry | `{"operation":"destination","user":"u-42","entry":"ledger","denied":true}` |
| Stop issuer-dependent access across the Integrator | `{"operation":"issuer","stopped":true}` |
| Engage the Integrator emergency stop | `{"operation":"emergency","stopped":true}` |

## Handle failed calls

Broker application errors use a plain-text code. JSON decoding or request-size errors can also be returned by the HTTP layer.

| HTTP | Broker code | Caller action |
| --- | --- | --- |
| 400 | `invalid_request` | Check the payload shape, exact host and variant for this endpoint. |
| 401 | `unauthenticated` | Check the credential class, audience and expiry. Refresh a Workload token through the backend. |
| 403 | `denied` | Recheck ownership, active generation, permission and device binding. |
| 404 | `unavailable` | The referenced item is unavailable in this authenticated scope. For Push registration, also check whether a sender is configured. |
| 409 | `already_resolved` | Fetch current status or a fresh device snapshot before acting again. |
| 410 | `expired` | Refresh status. A user can explicitly request another approval. |
| 429 | `busy` | Back off within the original request deadline. |
| 503 | `authority_unavailable` | Restore Broker or storage availability. |

The route table and error mapping are defined with the Broker HTTP service. [HTTP error mapping and route registration](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/crates/countersign-broker/src/service/mod.rs)
