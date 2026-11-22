# Service configuration

The Broker and Gateway take a JSON file as a positional argument. Paths in the file are local to the process, including its container mount namespace. Use absolute paths. Unknown fields fail deserialization. The reference Broker uses one SQLite database per Integrator and verified origin. [Operating guide](../operate.md) · [Integrator guide](../integrate.md)

## Commands and Workload environment

| Command | Effect |
| --- | --- |
| `countersign-broker /config/broker.json` | Opens the database, starts a new authority epoch, applies configuration and listens. |
| `countersign-broker --recover-backup /config/broker.json` | Runs offline after a restore. Fences previous authority and leaves emergency stop enabled. |
| `countersign-gateway serve /config/gateway.json` | Probes the chosen worker sandbox and exits if it cannot start, opens the configured issuer, publishes the sidecar public CA when applicable, and listens. |
| `countersign-gateway env /config/gateway.json` | Writes shell-quoted exports using `proxy_url` and `ca_output`. The launcher supplies these values to the Workload. |

For the sidecar configuration on this page, the helper exports these four values.

```sh
export HTTPS_PROXY='http://gateway:8080'
export SSL_CERT_FILE='/trust/sidecar.pem'
export REQUESTS_CA_BUNDLE='/trust/sidecar.pem'
export NODE_EXTRA_CA_CERTS='/trust/sidecar.pem'
```

Configure proxy use in the HTTP client or adapter the Workload runs. Clear any `NO_PROXY` bypass for the protected site. The Compose curl Workload also sets `CURL_CA_BUNDLE` to that public PEM. With an HTTPS shared proxy, configure the client to trust the listener certificate as well as the intercepted site's proxy leaf, for example with curl's `--proxy-cacert` and `--cacert` respectively.

## Broker

This example uses the demo's destination, service names and mounted paths. The reference launcher substitutes the configured desktop-facing port for `8443`. Each executable runs in its own container. [Demo configuration generator](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/examples/demo-integrator/compose_demo.py)

```json
{
  "origin": "localhost:8443",
  "listen": "0.0.0.0:9443",
  "integrator": "demo",
  "database": "/state/broker.db",
  "backend_token_file": "/config/backend.token",
  "workload_hmac_key_file": "/config/workload.hmac",
  "client_ca_file": "/config/client-ca.pem",
  "tls": {
    "certificate_path": "/config/broker.pem",
    "key_path": "/config/broker.key"
  },
  "destinations": [
    {"id": "demo-site", "version": 1, "pattern": "site.test:9444"}
  ]
}
```

| Field | Required or default | Meaning |
| --- | --- | --- |
| `origin` | Required | Verified Integrator DNS authority in `host:port` form. An omitted port means 443. Use the origin the user pairs with. |
| `listen` | Required | Listener IP address and port. A plain HTTP listener must be loopback, behind Integrator HTTPS ingress. |
| `integrator` | Required | Stable opaque Integrator ID. The database records this ID and origin. |
| `database` | Required | SQLite file. The Broker needs write access to its directory for the database and sibling lock file. |
| `backend_token_file` | Required | Private text bearer secret shared by the Broker and the authenticated Integrator backend. |
| `workload_hmac_key_file` | Required | Private raw bytes used to derive the boot-specific HS256 signing key. |
| `gateway_token_file` | Optional | Separate text service secret required for shared-mode Gateway authentication. |
| `admin_token_file` | Optional | Separate text service secret for `POST /v1/admin/control`. Set it to operate or clear stops. |
| `client_ca_file` | Required | Default PEM trust anchors for native client chains. Per-entry `client_trust.ca_file` overrides the path. |
| `destinations` | Required | Array of Broker destination entries. Fields are listed below. |
| `max_duration_s` | `28800` | Positive maximum approval duration in seconds. The suggested duration is the smaller of one hour and this maximum. |
| `audit_retention_days` | `30` | Positive retention in days for audit and security history. |
| `tls` | Optional | Object with required `certificate_path` (PEM listener chain) and `key_path` (PEM private key). Required for a non-loopback bind. |
| `web_push` | Optional | Enables ID-only offline notifications. Set `vapid_key_file` to a private unpadded base64url 32-byte P-256 scalar, `contact` to a `mailto:` URI and `allowed_hosts` to a nonempty list of exact push-service domains. |

Use independent random values for the HMAC key and each bearer secret. The service enforces a 32-byte minimum and rejects reused values. Keep the token files readable only by the services that use them. These commands create the required secrets in a new, private Broker configuration directory.

```sh
umask 077
openssl rand -hex 32 > backend.token
openssl rand 32 > workload.hmac
```

## Gateway

This sidecar example assumes the Gateway's private Workload-facing address is `172.22.0.2` and the site resolves to `172.23.0.4`. Use the actual interface address and site prefix for your network. The Compose launcher discovers both. The `workload` object matches the binding returned by the demo Integrator's authenticated backend call.

```json
{
  "listen": "172.22.0.2:8080",
  "proxy_url": "http://gateway:8080",
  "ca_output": "/trust/sidecar.pem",
  "broker_url": "https://broker:9443",
  "broker_ca": "/config/ca.pem",
  "workload_token": "/credential/workload.jwt",
  "workload": {
    "integrator": "demo",
    "user": "demo-user",
    "context": "demo-context",
    "workload": "demo-curl",
    "workload_generation": 1
  },
  "destinations": [
    {
      "id": "demo-site",
      "version": 1,
      "pattern": "site.test:9444",
      "private_networks": ["172.23.0.4/32"],
      "roots": "/config/ca.pem"
    }
  ]
}
```

| Field | Required or default | Meaning |
| --- | --- | --- |
| `listen` | Required | Listener IP address and port. Choose a private Workload endpoint in sidecar mode. |
| `proxy_url` | Required | Workload-facing listener origin. Use `http` for sidecars and `https` for shared mode. |
| `broker_url` | Required | HTTPS origin for the Broker. Both URL fields accept an origin with an optional port and root path. Credentials, query strings and fragments cause an error. |
| `broker_ca` | Required | PEM anchors for the Broker's TLS listener or its HTTPS ingress. |
| `ca_output` | Required in both modes | The sidecar writes its public CA here. Create the parent directory before startup. In shared mode supply the path of the public trust PEM you distribute. The helper uses this path in both modes. |
| `workload_token` | Sidecar only, required | Private file containing the backend-issued Workload bearer token. The Gateway rereads it on Broker calls. |
| `workload` | Sidecar only, required | Object containing `integrator`, `user`, `context`, `workload` IDs and a positive `workload_generation`. |
| `destinations` | Required | Array of Gateway entries. A sidecar needs at least one to construct its CA constraints. |
| `denied_networks` | `[]` | Additional IPv4 or IPv6 CIDRs to block: for every destination on a direct route, and for the egress proxy's own addresses. |
| `egress_proxy` | Omitted → every destination connects directly | The egress proxy: an `http` URL with a host and a port, such as `http://proxy.internal:3128`. Every destination goes through it, unless its rule says `"egress": "direct"`. The Gateway resolves the proxy's host through system DNS on every connection, drops any answer inside `denied_networks`, and sends a plain-text `CONNECT` with the site's name and port and no credentials. It resolves nothing for the site: the egress proxy does, and its ACLs are that site's address policy. An `https` URL, a URL with credentials, a path, a query or fragment, or a missing port fails loading. The Gateway never takes the egress proxy from a proxy environment variable such as `HTTPS_PROXY`, never tries a proxied destination directly, and always reaches the Broker directly. [Reach sites through an egress proxy](../operate.md#reach-sites-through-an-egress-proxy) |
| `clock_uncertainty_ms` | `1000` | Allowed UTC difference from the Broker, in milliseconds, from 0 through 29999. The Gateway subtracts the margin from absolute deadlines and checks its local clock against monotonic elapsed time. |
| `worker_sandbox` | `"namespaces"` | The worker sandbox for every grant worker, in sidecar and shared mode. `"namespaces"` is the namespace sandbox: bubblewrap gives each grant worker its own filesystem, process and network view, and the grant worker then confines itself with a seccomp allow-list, Landlock and non-dumpable memory. It needs `/usr/bin/bwrap` and a host that lets the Gateway create namespaces. `"filter"` is the filter sandbox: the same confinement without the namespaces, for a host that refuses them, such as ECS Fargate. It needs no bubblewrap. Any other value fails loading. The Gateway never switches from one to the other. [Choose a worker sandbox](../operate.md#choose-a-worker-sandbox) |
| `shared` | Omitted → sidecar | Shared-mode object. Requires PEM `listener_cert` and `listener_key`, a `gateway_token` file holding the Broker's matching service secret, and a `ca` source below. Omit both sidecar Workload fields. |

### Destination entries

Use a unique stable `id`, positive `version`, and unique `pattern` at both services. Patterns are DNS authorities with an optional port (default 443), e.g. `api.example.org:443` or `*.example.org:443`. The wildcard consumes one whole leftmost label. Exact entries take precedence. A downstream CONNECT requires an explicit port.

| Field | Process | Default and purpose |
| --- | --- | --- |
| `whole_wildcard` | Broker | `false`. Set to `true` on a wildcard entry to offer a grant for the wildcard scope. |
| `client_trust` | Broker | Optional object. `ca_file` selects alternative PEM client roots. `user_fingerprints` maps user IDs to allowed leaf SHA-256 fingerprints (standard padded base64 of 32 bytes). Omission permits identities passing the other checks. A supplied map requires a match for that user. `revocation` configures status imports. |
| `approval` | Gateway | `"exact_host"`. Set to `"whole_wildcard"` only for a wildcard with the corresponding Broker setting. |
| `private_networks` | Gateway | `[]`. For an exact private destination on a direct route, list allowed CIDRs. When present, every DNS answer must be within the configured prefixes and pass the address safety checks. With `egress_proxy` set, a rule that has `private_networks` and no `"egress": "direct"` fails loading, because nobody would check them: remove the field, or set `"egress": "direct"`. |
| `egress` | Gateway | Omitted → through `egress_proxy` when it is set, else direct. `"direct"` connects to the site directly, with the Gateway's own address policy, even when `egress_proxy` is set. Without `egress_proxy` it changes nothing. Any other value fails loading. |
| `roots` | Gateway | Required PEM server trust anchors for this site's upstream certificate. |
| `revocation` | Gateway | Optional strict status imports for the upstream server chain. |

### Strict status evidence

These JSON values can be used for the Broker's `destinations[].client_trust.revocation` or the Gateway's `destinations[].revocation`. Select evidence for the chain validated by that service.

```json
{"kind":"crl","files":["/status/issuing-ca.crl"]}
```

```json
{"kind":"ocsp","files":["/status/leaf.ocsp","/status/intermediate.ocsp"],"max_age_s":3600}
```

Supply 1–32 paths that the service can read and only trusted administrators can replace. Each file contains a complete DER object of at most 4 MiB. Publish replacements atomically. The CRL profile expects a complete direct CRL per issuer, with fresh `nextUpdate`. For OCSP, supply signed good status for each non-anchor certificate in the ordered chain. `max_age_s` is optional and positive. It caps freshness at `thisUpdate + max_age_s` and supplies a deadline for responses that omit `nextUpdate`. Without a maximum age, `nextUpdate` is required. In either mode the service also checks the certificate path and validity. The operator supplies updated evidence independently of Countersign.

### Shared issuers

Set exactly one source in `shared.ca`. A local issuer uses a certificate chain and its matching signing key.

```json
{"type":"local","cert":"/issuer/proxy-ca-chain.pem","key":"/issuer/proxy-ca.key"}
```

Put the signing CA first and trust anchor last in the PEM chain. Supply a matching PEM private key. A self-signed issuing root can occupy both roles. The signing CA must be currently valid, carry CA basic constraints and permit certificate signing.

For a remote issuer the Gateway calls ACM-PCA `IssueCertificate` followed by `GetCertificate`. The example identifiers below describe an AWS P-256 CA with a server-auth end-entity template. Supply your actual authority, algorithm and template. [AWS Private CA template definitions](https://docs.aws.amazon.com/privateca/latest/userguide/template-definitions.html)

```json
{
  "type": "acm_pca",
  "profile": "proxy-issuer",
  "region": "us-east-1",
  "ca_arn": "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-4234-8234-123456789012",
  "template": "arn:aws:acm-pca:::template/EndEntityServerAuthCertificate/V1",
  "signing_algorithm": "SHA256WITHECDSA",
  "roots": "/issuer/proxy-roots.pem"
}
```

| Remote field | Required or default | Meaning |
| --- | --- | --- |
| `ca_arn`, `template` | Required | The authority identifier and template accepted by that endpoint. The template must issue the worker's exact DNS SAN and a server-auth leaf within the absolute expiry requested. |
| `signing_algorithm` | Required | ACM-PCA enum value compatible with the configured CA key. |
| `roots` | Required | PEM trust anchors for checking the issued leaf chain. These validate the proxy leaf. The SDK handles HTTPS transport to the issuer separately. |
| `profile`, `region` | Optional | AWS shared profile and region. Omitted values come from the SDK's configuration chain. Credentials remain with the Gateway supervisor. |
| `endpoint` | Optional | Explicit HTTPS issuer URL. Overrides endpoint selection from the shared SDK configuration. |
| `expected_uri` | Optional | Use only for a template that must add exactly this URI SAN alongside the one allowed DNS SAN. |

For AWS Private CA, use the configured account, region and credentials. For an ACM-PCA-compatible deployment such as ZAE-ZCM, select its authority and template in the same JSON and set up the standard AWS shared config. The example below is a Gateway service account's `~/.aws/config`. Use the actual endpoint, deployment ID and credential helper profile.

```ini
[profile proxy-issuer]
region = us-east-1
credential_process = zcm-creds --endpoint https://abcdefghij.execute-api.us-east-1.amazonaws.com/ --server-id example-deployment --profile work
services = proxy-services

[services proxy-services]
acm_pca =
  endpoint_url = https://abcdefghij.execute-api.us-east-1.amazonaws.com/
```

The service key in this profile is `acm_pca`. Keep the helper and its credentials accessible only to the supervisor. A controlled SDK fixture checks endpoint selection, issued leaf validation and TLS use. Operational qualification requires the real issuing service and its template. [ZAE-ZCM profile documentation](https://github.com/zeroae/zae-zcm#configure-a-profile)
