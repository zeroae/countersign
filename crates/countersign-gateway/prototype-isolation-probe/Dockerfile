# PROTOTYPE for issue #18. Adds the probe to a Gateway image so it runs as the
# Gateway's own user with the Gateway's own bubblewrap.
#
# Fargate (the reporter's image, linux/amd64):
#   docker buildx build --platform linux/amd64 -t <registry>/isolation-probe .
# Local, on top of a locally built Gateway:
#   docker build --build-arg GATEWAY_IMAGE=countersign-demo/gateway:local -t isolation-probe .
#   docker run --rm isolation-probe
ARG GATEWAY_IMAGE=ghcr.io/zeroae/countersign-gateway:v0.2.0

FROM rust:1.99-bookworm AS build
WORKDIR /probe
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM ${GATEWAY_IMAGE}
COPY --from=build /probe/target/release/isolation-probe /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/isolation-probe"]
