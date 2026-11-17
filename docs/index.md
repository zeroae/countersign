# Countersign

A remote job can authenticate to an mTLS site using a client certificate on your desktop. You approve a particular certificate, host and duration. The desktop signs each new handshake through the operating system’s key provider. The Integrator runs the Gateway that carries the job’s traffic.

[Run the demo and verify a certificate fingerprint](try.md)

## Where to start

| Your task | Guide |
|---|---|
| Decide whether to approve a request or end access | [Use the Companion](companion.md) |
| Give a job access on behalf of a signed-in user | [Integrate a service](integrate.md) |
| Configure protected hosts, run the services, or recover a Broker | [Self-host and operate](operate.md) |
| Trace the two TLS connections and the signing request | [Architecture and trust](architecture.md) |
| Find a supported combination of OS, architecture and provider | [Tested platforms](reference/support.md) |
| Build the app or reproduce a qualification run | [Develop and release](develop.md) |

Looking up a field? See the [configuration reference](reference/config.md), [Broker API](reference/api.md), [widget and theme manifest](reference/widget.md), or [control protocol](reference/protocol.md).
