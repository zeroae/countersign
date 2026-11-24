# Spec #49: Reach protected sites through an operator's egress proxy

- Status: accepted
- Epic: E2 Reach protected sites through an operator's egress proxy
- Written by: sodre
- Exported: 2026-11-24, by `.claude/plugins/foresight/scripts/export-spec.py 49`

This file is the spec's text as its issue held it when the spec closed. It is never edited.

---

## Problem Statement

An operator cannot run the Countersign Gateway in a network where the only way out is a proxy. In FINsight the Gateway is a sidecar in a Fargate task. The task reaches the Broker directly, but for an external HTTPS site it must go through Squid behind an internal load balancer. Squid authorizes the requested hostname and port and passes the TLS bytes through unread (#46).

The Gateway has no setting for that. Its supervisor resolves the site's name itself, checks every DNS answer against the site's address policy, and opens a direct TCP connection to the pinned address. With no direct route, the Workload's `CONNECT` returns 502 with `Countersign-Error: upstream_failure`, possibly only after the 120-second deadline.

The design record requires that order ("connect to the selected IP and port without a second DNS resolution"), so the Gateway cannot simply hand the name to a proxy without a decision about who then enforces the address policy.

## Solution

The operator names an **egress proxy** in the Gateway configuration: the HTTP proxy the Gateway must go through to reach a protected site.

- One line, `egress_proxy`, sends every destination through it. A rule that should connect directly says `"egress": "direct"`.
- On a proxied route the Gateway sends `CONNECT` with the site's name and port and resolves nothing. The egress proxy resolves the name, and its ACLs decide which names and addresses get a tunnel.
- Everything else stays with Countersign: the site still needs its destination rule at the Gateway and the Broker, the user still approves, and the Gateway still verifies the site's certificate before the user's certificate is used.
- The Gateway never falls back to a direct connection. When the proxied leg fails, the Workload's response says whether the egress proxy refused, could not reach the site, or was itself unavailable.

ADR 0003 records the decision. A regression test runs on every pull request, and a Compose variant of the demo qualifies the Gateway against a real Squid.

## User Stories

1. As an operator whose only route out is a proxy, I want to set `egress_proxy` once, so that every protected site is reached through it.
2. As an operator, I want every destination to use the egress proxy by default, so that I do not repeat the route on each rule.
3. As an operator with one internal site on a direct route, I want to set `"egress": "direct"` on that rule, so that one Gateway serves both routes.
4. As an operator with no egress proxy, I want my configuration and my Gateway's behaviour unchanged, so that upgrading costs me nothing.
5. As an operator, I want the Gateway to send the site's name to the egress proxy, so that my proxy can authorize by hostname.
6. As an operator in a network without external DNS, I want the Gateway to resolve nothing on a proxied route, so that it works where only the proxy can resolve.
7. As an operator, I want a private site to be reachable through the egress proxy with a rule that has no `private_networks`, so that internal sites behind my proxy work too.
8. As an operator, I want a wildcard rule to work through the egress proxy, so that one rule covers a group of hosts my proxy allows.
9. As an operator, I want the Gateway to refuse to start when a proxied rule has `private_networks`, so that my config never claims an address check nobody performs.
10. As an operator, I want that error to name the rule and both fixes, so that I can correct it without reading the code.
11. As an operator adding `egress_proxy` to an existing config, I want every private rule that has not chosen a route to stop startup, so that I decide each one.
12. As an operator, I want an `https` egress proxy URL refused at startup, so that I do not believe the proxy leg is encrypted when it is not.
13. As an operator, I want an egress proxy URL with credentials refused at startup, so that I do not believe the Gateway authenticates to the proxy when it does not.
14. As an operator, I want an unknown `egress` value to fail configuration loading, so that a typo cannot choose a route I did not mean.
15. As an operator, I want `countersign-gateway env` to refuse the same configurations as `serve`, so that my launcher finds the mistake before the Gateway starts.
16. As an operator, I want startup to log which destinations leave their address policy to the egress proxy, so that I can see where each check happens.
17. As an operator, I want the egress proxy's name resolved on every connection, so that a load balancer whose addresses change keeps working.
18. As an operator, I want the egress proxy allowed on a private address, so that an internal load balancer works without extra configuration.
19. As an operator, I want `denied_networks` still applied to the egress proxy's address, so that my block on a control-plane range holds for every socket the Gateway opens.
20. As an operator, I want a refusal by my proxy reported as `proxy_denied`, so that I look at my proxy's ACLs.
21. As an operator, I want an unreachable or silent proxy reported as `proxy_unavailable`, so that I look at the proxy and the network to it.
22. As an operator, I want the proxy's "could not reach the site" answer reported as `upstream_failure`, so that a site outage reads the same on both routes.
23. As an operator, I want each of these to carry `Countersign-Request-ID`, so that I can match a Workload's failure to the Gateway's log line.
24. As an operator, I want the operator guide to say how to set the egress proxy, so that I can configure it from the guide.
25. As an operator, I want the guide to say where name resolution and address policy happen on each route, so that I know what my proxy is now responsible for.
26. As an operator, I want example Squid ACLs in the guide, including blocks for metadata, link-local and loopback addresses, so that I do not leave open what the Gateway used to block.
27. As an operator, I want the guide to show how to pin a private site to its prefixes at the proxy, so that I can keep the check `private_networks` gave me.
28. As an operator, I want the configuration reference to describe `egress_proxy` and `egress`, so that I can configure them from the reference alone.
29. As an operator, I want the troubleshooting table to cover the two new error values, so that I can act on them.
30. As an operator running shared mode, I want the egress proxy to work there as in a sidecar, so that both deployment modes are available.
31. As a Workload author, I want my client configuration unchanged, so that the same `HTTPS_PROXY` and trust settings work on both routes.
32. As a Workload author, I want a failed proxied request to end with a status and an error value, never a hang until the deadline when the proxy has answered, so that my job fails fast.
33. As a Workload author, I want the proxy's own error page kept from my job, so that I never parse a third party's HTML as a site response.
34. As a user approving a grant, I want the prompt, the grant and the cutoff to work the same on a proxied route, so that my approval means the same thing.
35. As a user who revokes a grant, I want a proxied connection cut off as a direct one is, so that revocation does not depend on the route.
36. As a security reviewer, I want the Gateway never to fall back from the egress proxy to a direct connection, so that a proxy outage or refusal cannot become a way around it.
37. As a security reviewer, I want the site's certificate verified against the hostname and the rule's roots before any signature, so that a tunnel to the wrong machine receives nothing.
38. As a security reviewer, I want a site still to need its destination rule at the Gateway and the Broker, so that the egress proxy narrows what is reachable and never widens it.
39. As a security reviewer, I want the egress proxy to carry only encrypted bytes, so that it never sees the user's traffic or the client handshake in the clear.
40. As a security reviewer, I want the grant worker and the worker sandbox unchanged, so that the supervisor remains the only process that opens a socket.
41. As a security reviewer, I want ADR 0003 to say which checks move to the egress proxy and which stay, so that the changed contract is checkable.
42. As a security reviewer, I want the Gateway to ignore proxy environment variables on this leg, so that only the reviewed configuration chooses the route.
43. As a reader of the design record, I want its resolution paragraph to name both routes, so that the record matches the product.
44. As a Gateway maintainer, I want the runtime test to pass a request through a test-only `CONNECT` proxy on every pull request, so that the proxied route cannot break unnoticed.
45. As a Gateway maintainer, I want that test to prove the site saw no connection when the proxy refused or was unreachable, so that "no direct fallback" is tested, not assumed.
46. As a Gateway maintainer, I want that test to prove the proxy received the site's name and not an address, so that hostname authorization keeps working.
47. As a Gateway maintainer, I want that test to run one Gateway with a proxied and a direct destination, so that the default and the opt-out are both exercised.
48. As a Gateway maintainer, I want that test to reject a site certificate for the wrong hostname through an allowed tunnel, so that the certificate check is proven on the proxied route.
49. As a Gateway maintainer, I want a Compose variant with a real Squid that I can run before a release, so that the Gateway is qualified against the proxy operators use.
50. As a Gateway maintainer, I want that variant's check to correlate Squid's log, the certificate the site saw and the flag the Workload read from one run, so that a pass means the bytes took the proxied path.
51. As a Gateway maintainer, I want the glossary to define egress proxy, so that code, docs and issues use one term.
52. As the reporter of #46, I want a documented, passing Compose configuration, so that I can repeat it on Fargate 1.4.0 with the filter sandbox.
53. As an Integrator, I want the demo walkthrough unchanged unless I ask for the Squid variant, so that trying Countersign stays as simple as it is.

## Implementation Decisions

- **ADR 0003 binds this work.** It is `proposed`, and the first pull request lands it as `accepted` together with the glossary entry. Use the glossary's term, **egress proxy**; avoid "upstream proxy", "outbound proxy" and "Squid" as the name of the concept.
- **Configuration, top level.** The Gateway configuration gains an optional `egress_proxy`: a URL with the `http` scheme, a host and a port, such as `http://proxy.internal:3128`. Loading fails on an `https` scheme and on a URL that carries credentials, and each error names the cause.
- **Configuration, per destination.** A destination rule gains an optional `egress`, whose only value is `"direct"`. Any other value fails loading, like every unknown field today.
  - `egress_proxy` set: every destination goes through it, except a rule with `"egress": "direct"`.
  - `egress_proxy` absent: every destination connects directly, as today. `"egress": "direct"` is accepted and changes nothing.
- **`private_networks` on a proxied rule fails loading.** The error names the rule and both fixes: remove the field, or set `"egress": "direct"`. The existing refusal of a wildcard rule with `private_networks` is unchanged.
- **Both commands validate.** `env` and `serve` refuse the same configurations.
- **Both modes.** Sidecar and shared mode take the same fields and behave alike.
- **The proxied leg.** For a proxied destination the supervisor, where it opens the direct connection today:
  1. resolves the egress proxy's host through system DNS, on every connection, and refuses any answer inside `denied_networks`. `private_networks` and the special-use blocks do not apply to the proxy's address;
  2. connects and sends a plain-text `CONNECT` with the site's canonical name and port, with no proxy credentials;
  3. reads a bounded response head. On a 2xx answer the socket takes the place the direct socket has today, and any bytes after the head belong to the tunnel.

  The supervisor does not resolve the site's name on this route. The per-connection deadline covers the whole leg.
- **What does not change.** Destination policy, Broker admission, the grant, both leases, the grant worker, the worker sandbox, and the verification of the site's certificate against the hostname and the rule's roots and revocation evidence. Approval still comes before the connection. Each Workload `CONNECT` opens its own tunnel; none is reused.
- **No fallback.** A proxied destination is never tried directly, whatever the failure.
- **Failures.** Each returns 502 to the Workload with `Countersign-Request-ID`, and the egress proxy's response body is never passed on.

  | What happened | `Countersign-Error` |
  |---|---|
  | The egress proxy refused the `CONNECT` (a 4xx answer) | `proxy_denied` |
  | The egress proxy answered that it could not reach the site (a 5xx answer) | `upstream_failure` |
  | The egress proxy could not be reached, timed out, gave no usable answer, or resolved only to denied addresses | `proxy_unavailable` |

  The Compose qualification confirms which answers a real Squid gives for an ACL refusal and for an unreachable site.
- **Environment.** The Gateway takes the egress proxy only from its configuration. It reads no proxy environment variable for this leg, and the Broker leg stays direct.
- **Startup log.** When an egress proxy is set, startup logs its host and port and the rule IDs of the destinations that leave their address policy to it.
- **The Compose variant.** The demo gains an opt-in variant; the default walkthrough is unchanged.
  - The Gateway shares a network with the Broker and Squid. The site is on a network only Squid shares.
  - Squid runs from a pinned image, allows `CONNECT` only to the site's hostname and port, and does no TLS interception.
  - The demo's `--verify` mode reads Squid's access log.
- **Documentation.**
  - The operator guide gains a section on reaching sites through an egress proxy. It says where name resolution and address policy happen on each route, and gives example Squid ACLs: allow by hostname and port, block metadata, link-local and loopback addresses, and pin a private site to its prefixes.
  - The configuration reference describes `egress_proxy` and `egress`.
  - The troubleshooting table covers `proxy_denied` and `proxy_unavailable`.
  - The architecture page's trust boundaries name the egress proxy.
  - The design record's resolution paragraph names both routes.
  - The developer guide says how to run the Squid variant and records the Squid version it was qualified against.
- **Flag: none.** The change is an opt-in configuration field whose absence keeps today's behaviour, and the repository has no release-flag rule.

## Testing Decisions

- **What makes a good test here:** it checks what a Workload, an operator, the egress proxy and the site can each observe. Assert the status and headers the Workload gets, the request line the proxy received, the connections and certificate the site saw, and what the Gateway logs and how it refuses a configuration. Never assert how the supervisor builds the request or parses the answer.
- **Seam 1: the real Gateway binary, end to end.** Extend the existing runtime test, which runs the real `countersign-gateway serve` against a test grant authority and an mTLS site. It gains a small test-only `CONNECT` proxy that records each request line and can be told to allow, refuse or be absent. No new seam is added below it. Cases:
  - **Allowed.** The Workload reads the site's response through the proxied route. The site saw the approved client certificate. The proxy's recorded request names the site's hostname and port, and the Gateway had no way to resolve that name itself.
  - **Refused.** The Workload gets 502 with `proxy_denied`. The site saw no connection.
  - **Site unreachable from the proxy.** The Workload gets 502 with `upstream_failure`.
  - **Proxy unreachable.** The Workload gets 502 with `proxy_unavailable`. The site saw no connection, although the Gateway could have reached it directly.
  - **Wrong hostname.** The proxy tunnels to a site whose certificate is for another name. The request fails and no client-certificate signature is made.
  - **Default and opt-out together.** One Gateway serves a proxied destination and a direct one with `private_networks`; each takes its own route.
  - **Cutoff.** A retired grant cuts a proxied connection as it cuts a direct one.
  - **Configuration loading.** `private_networks` on a proxied rule, an `https` proxy URL, a proxy URL with credentials and an unknown `egress` value each fail, and the first three name their cause. A configuration without `egress_proxy` loads as before.
  - **Startup log.** It names the egress proxy and the destinations that leave address policy to it.

  It runs in both modes and under both worker sandboxes wherever the runtime test already does.
- **Seam 2: the Compose demo with a real Squid.** The demo's `--verify` mode drives the real Companion and browser against the variant, by hand before a release. No workflow runs it, as none runs the Compose demo today. From one run it correlates three observations: Squid's log line for the `CONNECT` to the site's hostname and port, the certificate fingerprint the site saw, and the flag the Workload read. It then checks a destination Squid refuses, and a stopped Squid; in both the Workload fails and the site sees no connection.
- **Prior art:** the runtime test's site and grant-authority fixtures, its configuration-loading check and its startup-failure check, for seam 1. The Compose demo's `--verify` mode for seam 2.

## Out of Scope

- Repeating the run on Fargate 1.4.0 with the filter sandbox. The reporter does that from the documented Compose configuration; Countersign's part ends at Compose for now.
- Proxy authentication and a TLS-wrapped proxy leg.
- More than one egress proxy, or a proxy URL per rule.
- Letting the egress proxy alone decide which sites a Gateway admits, with no destination list (#48).
- Sending the Broker leg through the egress proxy.
- Running the Squid qualification in a hosted workflow.
- Any change to the grant worker, the worker sandbox, the sidecar CA or the approval prompt.

## Further Notes

- Origin: #46, a site report from the FINsight deployment, triaged ready-for-human until this design settled who enforces the address policy on a proxied route. #46 is done when the Compose configuration passes and is documented.
- What the operator takes on, and the documentation must say plainly:
  - On a proxied route the proxy's ACLs are the address policy. The Gateway no longer blocks metadata, link-local or loopback addresses for those sites.
  - The Gateway cannot stop the egress proxy from opening a connection to any address its ACLs allow. Such a tunnel receives no signature unless the machine presents a valid certificate for the hostname.
  - The Gateway refuses a wildcard rule for a private site on a direct route. Through the egress proxy it cannot tell that a site is private, so a wildcard rule reaches private hosts if the proxy allows them.
  - A user can approve and the request then fail at the egress proxy, as it can today at an unreachable site.
- Options considered and rejected, recorded in ADR 0003:
  - The Gateway resolves and sends `CONNECT` with the pinned address: a proxy that authorizes by hostname cannot, and the Gateway needs DNS the network may not give it.
  - The Gateway resolves and checks, then sends the name: the proxy resolves again, so the check does not bind the address it dials.
  - `private_networks` implying a direct route, or being ignored on a proxied one: the first fails only after a user has approved, the second leaves a field that promises a check nobody performs.
- Risk the tests must catch: a failure path that retries directly. Every negative case in seam 1 asserts what the site saw, not only what the Workload got.
