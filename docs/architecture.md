# Architecture and trust

The Gateway is the TLS client the protected site sees. The user's desktop supplies the client-certificate signature for that handshake. The Gateway holds traffic keys for both connections and sees the job's HTTP requests and responses. Trust the Integrator that operates it with anything the job can read or send under the grant.

![System architecture. The Workload connects to the Gateway over TLS, and the Gateway connects to the protected site over separate mTLS. The Integrator backend and Gateway contact their Broker. The desktop Companion connects out to the Broker and signs through its native key provider.](assets/diagrams/architecture.svg#gh-light-mode-only)![System architecture. The Workload connects to the Gateway over TLS, and the Gateway connects to the protected site over separate mTLS. The Integrator backend and Gateway contact their Broker. The desktop Companion connects out to the Broker and signs through its native key provider.](assets/diagrams/architecture-dark.svg#gh-dark-mode-only)

Solid arrows show the application's traffic. Dashed arrows show control connections and local signing. Every Integrator runs its own Broker and Gateway. A single Companion can maintain outbound connections to multiple paired Brokers. [Trace the first protected request](integrate.md#make-the-first-protected-request)

## Follow a request across the two connections

1. **Workload → Gateway.** curl, Python or another HTTPS client asks its configured proxy to CONNECT to a DNS name and port. The Gateway checks the protected destination and Workload binding with the Broker. For an admitted grant, its worker presents a fresh leaf for the exact intercepted host. The Workload validates this leaf against the proxy CA the Integrator supplied.
2. **Gateway → protected site.** The Gateway opens a separate connection to the pinned destination. It authenticates the upstream server under that destination's trust policy. When the server requests client authentication, rustls asks for a signature over the TLS handshake input.
3. **Gateway → Broker → Companion.** The Broker checks the live grant and signing operation, then routes the request to the desktop that approved it. The Companion verifies its local approval and invokes the native key provider. The selected public certificate chain and the resulting signature let the Gateway finish the handshake. The client private key stays in its provider.
4. **Site → Workload.** The site authenticates the client's certificate and applies its own application permissions. The worker relays the response over the downstream TLS connection. The Broker handles authorization and signing messages. Application bodies travel through the Gateway.

## Who holds what

| Component | What it holds or sees | What you trust it to do |
|---|---|---|
| Integrator backend | Authenticated account, Context ownership, job generation, service credential | Bind each job to the correct user and Context, authorize its destinations, deliver credentials privately. |
| Workload | Job data, proxy address, public trust bundle. In shared mode it or its private adapter also has a Workload credential. | Use the configured proxy. The Integrator controls direct network access from the job. |
| Gateway | Downstream and upstream traffic keys, plaintext, scoped signing requests. The parent holds issuer access. | Enforce exact authorities, isolate grants, authenticate the upstream site and close both sockets when authority lapses. A compromised Gateway could send other requests to an approved site. |
| Broker | Pairings, account bindings, decisions, selected public chain, grants, audit and current signing operations | Authenticate both services and devices, enforce ownership and deadlines, and send a signing request only to its winning device. |
| Companion and native provider | Device pairing key and access to installed client identities | Display the actual origin and scope, require consent, and sign with the approved local key. Trust also extends to the user's OS, token provider and desktop session. |
| Protected site | Client certificate and the HTTP request it receives | Decide what that certificate can do. The site may issue its own cookies or persist writes beyond the TLS session. |

The widget lives on the Integrator's site. An OS notification, a deep link or Web Push carries an opaque ID. The Companion fetches the corresponding request on its authenticated connection. Branding comes from the accepted manifest for that pairing. The Integrator cannot supply the approval controls or substitute a different verified origin.

## The sidecar CA shares a host with the job

A new sidecar creates its CA key in memory. It writes the *public certificate* to the volume the Workload reads. The Gateway and Workload need separate process and filesystem permissions. A privileged job that can inspect the Gateway process, trace it, or control the container runtime can defeat that boundary. The Compose demonstration tests isolation from inside the Workload. [Sidecar process boundaries and operating requirements](operate.md#sidecar)

The CA has a critical DNS name constraint for each permitted suffix and excludes all IPv4 and IPv6 addresses. For `*.team.example:443` the encoded DNS constraint is `team.example`. X.509 permits the apex and subdomains under that suffix. Gateway policy is narrower: it matches one additional label, checks the port and resolves exact-host overrides. Every issued leaf names one exact host. Clients are responsible for validating their trust store and certificate constraints. Restart the sidecar with a new CA when its destination policy changes.

In shared mode the supervisor uses a local issuing key or an ACM-PCA-compatible issuer and authenticates the connecting Workload. In both modes a Linux worker is assigned to one grant. Streams, sockets, TLS sessions and certificate selection cannot move into another user's grant, including when two users contact the same host. [Shared Gateway operation](operate.md#shared-gateway)

## When access ends

An **approval duration** bounds how long the job may use the selected identity. A **lease** is a shorter permission the traffic and signing relays need to keep working. The Broker checks current authority on renewal. Traffic leases have a maximum budget of 30 seconds, measured conservatively from when the enforcer sent the request. The Gateway attempts renewal about every ten seconds. An earlier grant, certificate or validation deadline wins, including for an idle connection.

![Lease timeline in two cases. Case 1, the user quits the Companion: fresh signatures stop while existing traffic may renew. Case 2, the user revokes: after the Broker records it, it refuses renewal, and outstanding traffic stops by the earlier of a retirement notice and the current lease deadline.](assets/diagrams/access-ends.svg#gh-light-mode-only)![Lease timeline in two cases. Case 1, the user quits the Companion: fresh signatures stop while existing traffic may renew. Case 2, the user revokes: after the Broker records it, it refuses renewal, and outstanding traffic stops by the earlier of a retirement notice and the current lease deadline.](assets/diagrams/access-ends-dark.svg#gh-dark-mode-only)

An offline Companion can queue a revocation. The cutoff guarantee starts when the Broker **records** it. A retirement notice can close the sockets sooner. Lost notices, a stalled worker or an unreachable Broker cannot extend an issued lease. The Integrator can check the recorded decision and any reported socket closures separately. Bytes a site has already received, sessions it established independently and changes it already committed remain subject to that site's own controls. [Status and observations](reference/api.md#read-approval-status)

The name “countersign” also appears in COSE for a signature over another secured message. This project delegates the TLS client-authentication signature in an ordinary mTLS handshake.
