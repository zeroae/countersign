---
status: proposed
date: 2026-11-21
supersedes: none
---

# The egress proxy resolves the site and carries its address policy

The design record has the trusted Gateway parent resolve a protected site's name, check every DNS answer against the site's address policy, and connect to the pinned address "without a second DNS resolution". That assumes the Gateway has a direct route to the site. In some networks it has none: the only way out is an HTTP proxy the operator runs, which authorizes each `CONNECT` by hostname and port and passes the TLS bytes through unread (#46). We add the **egress proxy** and, for the routes that use it, move name resolution and address policy from the Gateway to that proxy. This changes the design record's rule for those routes only.

## Decision

1. **One egress proxy per Gateway.** The Gateway field `egress_proxy` holds its URL, such as `http://proxy.internal:3128`. The proxy leg is a plain-text HTTP `CONNECT` with no proxy authentication. The Gateway refuses to start on an `https` URL or one that carries credentials.
2. **It is the default route.** When `egress_proxy` is set, every destination goes through it unless its rule says `"egress": "direct"`. When it is absent, every destination connects directly, as before. Sidecar and shared mode behave alike.
3. **On a proxied route the Gateway resolves nothing.** It sends `CONNECT` with the site's canonical name and port. The egress proxy resolves the name, and its ACLs decide which names and addresses get a tunnel. `private_networks`, `denied_networks` and the Gateway's special-use blocks are not applied to the site's address on that route.
4. **Everything above the route is unchanged.** A site still needs a destination rule at the Gateway and the Broker, a grant and its leases. The Gateway still verifies the site's certificate against the hostname and the rule's roots before any client-certificate signature is made.
5. **A rule with `private_networks` on a proxied route is refused at startup.** The error names the rule and both fixes: remove the field, or set `"egress": "direct"`. A private site reached through the egress proxy takes a rule without `private_networks`. At startup the Gateway logs which destinations leave their address policy to the egress proxy.
6. **The egress proxy's own address is operator configuration.** It is a DNS name and port, resolved through system DNS on every connection. It is exempt from `private_networks` and the special-use blocks, because it normally sits on a private address. `denied_networks` still applies to it.
7. **The Gateway never falls back to a direct connection.** Every failure of the proxied leg returns 502 to the Workload, and the `Countersign-Error` header says which:
   - `proxy_denied`: the egress proxy refused the `CONNECT` (a 4xx answer).
   - `upstream_failure`: the egress proxy answered that it could not reach the site (a 5xx answer). A direct route reports an unreachable site the same way.
   - `proxy_unavailable`: the egress proxy could not be reached, timed out or gave no usable answer.

   The egress proxy's own response body is not passed on.

## Considered options

- **Resolve at the Gateway and send `CONNECT` with the pinned address.** Rejected: it keeps the pinning, but a proxy that authorizes by hostname cannot do so, and the Gateway needs external DNS that such a network may not give it.
- **Resolve and check at the Gateway, then send `CONNECT` with the name.** Rejected: the egress proxy resolves a second time, so the Gateway's check does not bind the address the proxy dials. It would look like a control and not be one.
- **One setting for the whole Gateway, with no per-destination route.** Rejected: one Gateway may reach an internal site directly and an external one through the egress proxy.
- **A route on every rule, with no default.** Rejected: an operator who sends everything through the egress proxy would repeat the route on each rule.
- **Treat `private_networks` as implying a direct route, or accept and ignore it on a proxied route.** Rejected: the first fails only at request time, after a user has approved, in a network with no direct route. The second leaves a field in the config that promises a check nobody performs.

## Consequences

- On a proxied route the operator's proxy ACLs are the address policy. They must block cloud metadata, link-local and loopback addresses, and pin a private site to its prefixes where the operator wants that. The operator guide shows example ACLs and says where resolution and address policy happen on each route.
- The Gateway cannot stop the egress proxy from opening a connection to any address its ACLs allow. A tunnel to the wrong machine still receives no signature, because the certificate check comes first.
- The Gateway refuses a wildcard rule for a private site on a direct route. Through the egress proxy it cannot tell that a site is private, so a wildcard rule reaches private hosts if the proxy allows them.
- Approval still comes before the connection. A user can approve and the request then fail at the egress proxy, as it can today at an unreachable site.
- The destination list stays. Letting the egress proxy alone decide which sites a Gateway admits is a separate decision (#48).
- Proxy authentication and a TLS-wrapped proxy leg wait until a site needs them.
- The design record's resolution paragraph changes to name both routes.
