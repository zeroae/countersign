# Operate a self-hosted Gateway and Broker

Run one Broker for the Integrator's HTTPS origin. Start with a sidecar for each Workload that needs its own proxy. Use shared mode when you can distribute a common proxy trust anchor, authenticate each Workload on an HTTPS listener and operate Linux worker isolation for multiple users. In both modes the Gateway sees HTTP plaintext and owns the traffic keys. The user's identity key stays with the native provider on their machine. [Architecture](architecture.md) · [Configuration reference](reference/config.md)

To run the services from a checkout, build the two container targets from the repository root. The runnable demo wires the images to separate networks and volumes. [Run the demo](try.md)

```sh
docker build -f distribution/Dockerfile --target broker -t countersign-broker:local .
docker build -f distribution/Dockerfile --target gateway -t countersign-gateway:local .
```

## Choose the network and trust boundaries

Each parent calls the Integrator's Broker over TLS. The Companion maintains its own outbound authenticated connection to that Broker. The parent retains the real downstream and upstream sockets. A worker receives connected local streams and creates the downstream leaf key. It negotiates both TLS legs and asks the Broker, through its parent, for a scoped client signature. A worker has private mount, PID and network namespaces. A new approval gets its own worker, including when the same user selects the same certificate for another Context.

### Sidecar

![Sidecar process diagram. A single Workload reads the public CA from a read-only mount and reaches its Gateway over a private link.](assets/diagrams/sidecar.svg#gh-light-mode-only)![Sidecar process diagram. A single Workload reads the public CA from a read-only mount and reaches its Gateway over a private link.](assets/diagrams/sidecar-dark.svg#gh-dark-mode-only)

1. Put the Gateway and its one Workload on a private link. Bind `listen` only to the Workload-facing interface. Anyone who can connect to a sidecar listener can act as its Workload. In the Compose demo the upstream site shares the Gateway's backend network and cannot connect to its proxy port.
2. Mount the Workload credential and configuration into the Gateway. Give the Gateway write access to a separate public trust directory. Mount that directory read-only at the same path in the Workload. Use separate principals and PID/mount namespaces, remove tracing privileges and keep the container engine socket outside the Workload. Protect the host's memory and swap according to the sensitivity of the traffic.
3. Start `countersign-gateway serve gateway.json`. Startup probes an actual sandboxed worker. The sidecar creates a new CA and atomically publishes its public PEM at `ca_output`. Its CA key lives in parent memory until exit. The CA encodes critical DNS name constraints and excludes all IPv4 and IPv6 ranges. A wildcard constraint uses the bare DNS suffix, such as `corp.example`. The Gateway separately checks the exact port, label depth and apex policy. Client software is responsible for enforcing the constraint. The Gateway enforces destination policy and issues an exact-host leaf on every connection.
4. Run `countersign-gateway env gateway.json` in the launcher and pass its exports to the Workload. Restrict direct egress if the job must use Countersign for a site. Check that the actual Workload UID can read the PEM and reach the proxy, and that it cannot read the private credential, Gateway memory or descriptors. The demo launcher performs these checks before sending curl traffic.

Keep the Linux supervisor unprivileged. It requires `/usr/bin/bwrap` and permission to create user, mount, PID and network namespaces. On Ubuntu with restricted user namespaces the distribution supplies an opt-in `bwrap-userns-restrict` AppArmor profile in `apparmor-profiles`. Check both the host policy and the container's seccomp/AppArmor policy. The demo's container exceptions apply only to its Gateway. [Compose deployment and access checks](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/examples/demo-integrator/compose_demo.py) · [Service mounts and networks](https://github.com/zeroae/countersign/blob/fbb5aa7c951f8b70a238f3351140aa44a6184adf/examples/demo-integrator/compose.yaml)

### Shared Gateway

![Shared Gateway process diagram. Authenticated Workloads use distinct grant workers. The supervisor owns the sockets and issuer credentials.](assets/diagrams/shared.svg#gh-light-mode-only)![Shared Gateway process diagram. Authenticated Workloads use distinct grant workers. The supervisor owns the sockets and issuer credentials.](assets/diagrams/shared-dark.svg#gh-dark-mode-only)

Use `shared.listener_cert` and `shared.listener_key` for the HTTPS proxy listener. Configure the same independent Gateway service secret in the Gateway and Broker. The Workload or its private adapter presents a Gateway-audience bearer token on CONNECT. Give the Workload public trust for both the HTTPS proxy listener and the exact-host leaves the proxy will issue.

For example, an adapter can put one `Proxy-Authorization: Bearer <workload-token>` line in a private, short-lived header file for curl to read on the proxy hop.

```sh
curl --noproxy '' --proxy https://gateway.corp.example:8443 \
  --proxy-cacert /trust/listener-roots.pem \
  --proxy-header @/run/workload/proxy-headers \
  --cacert /trust/proxy-issuer.pem https://site.test:9444/
```

Choose a local issuing CA or an ACM-PCA-compatible service. For the local source, mount the issuer certificate chain and matching signing key only into the Gateway parent. For a remote source, let the parent obtain standard AWS SDK credentials. Grant issuance and retrieval for the intended authority and template. The issuer signs the worker's public CSR. The Gateway checks the resulting chain, public key, DNS SAN, server-auth usage and grant expiry before returning it to the worker. AWS Private CA and ZAE-ZCM use this same path. The configuration reference includes the standard profile and service endpoint settings. [Shared CA configuration](reference/config.md#shared-issuers)

Maintain affinity between a live grant and the Gateway supervisor that first admitted it. A replacement process has a fresh boot identity. Retire the old grant and obtain a fresh approval when moving its Workload. The two-user integration fixture exercises concurrent workers and cutoff on Linux. A production shared deployment, its confinement policy and a live issuing service need qualification in their target environment.

## Start the Broker and issue credentials

Create a service-owned SQLite state directory and private files for the backend token and Workload HMAC key. For shared mode add a Gateway service token. Provision an independent administrator token to enable stop and recovery operations. Keep each secret at least 32 bytes long and distinct. Put only public client-certificate trust anchors in `client_ca_file`.

Start `countersign-broker broker.json`. Serve the Integrator site and its theme manifest over HTTPS at the verified origin. Route `/v1/companion` to the Broker with WebSocket upgrades and subprotocol `countersign.v1`. Keep backend, Gateway and admin routes on the appropriate service ingress. The Broker can terminate TLS itself or listen on loopback behind HTTPS ingress. The Gateway always verifies TLS to its configured Broker URL. [Integrator setup](integrate.md) · [Broker settings](reference/config.md#broker)

The authenticated Integrator backend derives the user, Context and Workload instance, then calls `POST /v1/backend/workloads` with its backend credential. The Broker returns a token, binding and absolute expiry. Tokens last 120 seconds. For a sidecar, atomically replace the private token file before expiry with a token for the same binding and generation. The demo refreshes it every 60 seconds. In shared mode a CONNECT uses its original bearer token for subsequent Broker calls. Present a fresh token on a new CONNECT before continuing with an expiring credential. A higher generation retires the former instance. When a job finishes, the backend can retire its exact binding with `/v1/backend/workloads/retire`.

## Set destinations and approval scope

Configure matching rule IDs, versions, patterns and approval scopes at the Broker and Gateway. An exact rule wins over a wildcard. For example, `*.corp.example:443` matches `api.corp.example:443` only one label below the suffix. The apex, deeper names and other ports require their own entries. By default the prompt covers only the exact host. To offer approval across the wildcard, set `whole_wildcard: true` at the Broker and `approval: "whole_wildcard"` at the Gateway. Each intercepted host still receives its own leaf.

For an internal site, specify its exact DNS name and port and put its allowed addresses in `private_networks`. The parent validates the entire DNS answer set, including IPv4-mapped IPv6, before pinning one socket address. A mixed allowed/forbidden answer fails the connection. Add site-specific infrastructure and control-plane ranges to `denied_networks`. The Gateway also rejects special-use addresses including loopback, link-local, shared carrier space and known metadata endpoints. Within TLS it checks SNI and the authority of each HTTP request. [Destination fields](reference/config.md#destination-entries)

## Maintain trust and stop access

Broker client trust determines which native certificate can represent a user. Gateway destination trust determines which server can receive a signature for a handshake. Supply signed DER CRLs or OCSP responses on the appropriate side when strict status checking is required. Arrange an external importer to verify its data source and atomically replace the files before expiry. Use a directory mount so file replacement is visible. A missing, stale or revoked result denies use. The Gateway rereads upstream roots and status during each handshake and at ten-second revalidation intervals. A shortened validity deadline cuts off idle connections as well as active traffic. [Status evidence formats](reference/config.md#strict-status-evidence)

Use a controlled cutover for changes to destination policy, issuer credentials or trust anchors.

1. Stop new protected jobs. Use an authenticated admin POST to `/v1/admin/control`. `{"operation":"issuer","stopped":true}` withdraws pending and approved authority across this Broker. `{"operation":"emergency","stopped":true}` stops access across the Integrator. For a narrower response use `{"operation":"destination","user":"USER","entry":"ENTRY","denied":true}` or `{"operation":"account","user":"USER","blocked":true}`.
2. Allow time for existing leases to expire, or stop affected Gateway processes to close their sockets. The Gateway watches for retirements and enforces independent ingress and egress leases with a 30-second maximum budget. A stop reported by the Broker records intent. Socket-closure observations identify connections on which the Gateway actually reported cutoff.
3. Replace files, bump changed destination rule versions at both services and restart affected processes. Recreate sidecars to generate a fresh constrained CA. For shared issuers, distribute the corresponding public trust to Workloads and verify the expected issuer, chain and exact SAN in a test connection.
4. Clear the same admin control with its boolean set to `false`, mint fresh Workload tokens and have users approve new work. Clearing a stop permits new grants. Earlier revoked grants remain terminal.

## Back up and recover the Broker

One Broker owns a database at a time. The database records the Integrator ID and verified origin and uses an adjacent lock file. Protect the state directory, backups, service credentials and status imports. Take a consistent SQLite backup into a private backup directory.

```sh
umask 077
sqlite3 /state/broker.db ".backup '/backup/broker.db'"
```

Stop the Broker before restoring the snapshot. Restore it under the owning service account with the same Integrator ID and verified origin. Run recovery to completion before starting the listener.

```sh
countersign-broker --recover-backup /config/broker.json
countersign-broker /config/broker.json
```

Recovery fences saved authority, removes saved enrollment and push subscriptions, retires saved Workload bindings and sets emergency stop. Review access changes since the snapshot, reestablish pairings and subscriptions, and use fresh Workload identities or higher generations. Clear emergency stop when ready to admit new approvals. Choose a new Context ID if the restored one is closed. An ordinary Broker restart cancels pending and approved grants and invalidates the previous boot's Workload tokens. Its device enrollments survive.

## Audit and troubleshoot

Use the backend's authenticated `POST /v1/backend/status` with the server-derived user and approval ID. Read the decision `state`, current `ready`, historical `upstream_mtls_accepted`, and reported ingress/egress closure counts separately. The Gateway records acceptance after it receives an HTTP response from the authenticated site. A site can return an HTTP error over an accepted mTLS connection.

Operators with authorized database access can inspect approval events without exporting private credential or subscription records. The default audit retention is 30 days. [Ownership, status and control APIs](reference/api.md)

```sh
sqlite3 -readonly /state/broker.db \
  "SELECT datetime(occurred_at,'unixepoch'), approval, kind FROM audit ORDER BY occurred_at DESC LIMIT 20;"
```

| Symptom | Where to look |
| --- | --- |
| Gateway exits with a worker sandbox startup error | Run under the intended service UID. Check bubblewrap availability, user namespace policy, library mounts and the container security profile. Verify the packaged Gateway rather than testing as root. |
| CONNECT returns 407 | Shared clients need an HTTPS proxy and one proxy bearer header. Check the token audience, expiry, broker boot, and separate service credential. |
| CONNECT returns 403 or keeps asking for approval | Compare rule ID, version, port, grant scope, memberships and stop controls. A denied or expired prompt requires an explicit retry. Check that the Companion is paired, online and can access the selected identity. |
| CONNECT returns 429, 503 or 504 | Inspect limits per grant/user, Broker availability, worker fencing, clock synchronization and pending approval. Capture the safe `Countersign-Error` and `Countersign-Request-ID` response headers for correlation. |
| CONNECT succeeds, then TLS closes | Check the Workload's current public proxy CA, exact hostname/SNI, server roots/status, issuer profile, client-certificate request and native provider. Check the owned status before treating a TLS failure as an application response. |
| A long session closes | Check grant, certificate, status and token deadlines, lease renewal, host clock drift and revocation. Closing the Companion prevents new signatures. An established connection continues while its remote authority remains valid. |
