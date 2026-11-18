# countersign-gateway

Run a forward proxy for workloads that need a desktop client certificate. The Gateway terminates the workload connection and delegates upstream TLS handshake signatures through the Broker. Run it as a sidecar for one workload or configure a shared issuer.

```sh
cargo install --locked countersign-gateway
```

[Try it with curl](https://zeroae.github.io/countersign/try/) · [Gateway configuration](https://zeroae.github.io/countersign/reference/config/) · [Trust boundaries](https://zeroae.github.io/countersign/architecture/)
