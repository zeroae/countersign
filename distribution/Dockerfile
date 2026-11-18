FROM rust:1.99-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock LICENSE ./
COPY crates ./crates
RUN cargo build --locked --release -p countersign-broker -p countersign-gateway

FROM debian:bookworm-slim AS broker
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/countersign-broker /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/countersign-broker"]

FROM debian:bookworm-slim AS gateway
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates bubblewrap && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/countersign-gateway /usr/local/bin/
USER 65531:65531
ENTRYPOINT ["/usr/local/bin/countersign-gateway"]
