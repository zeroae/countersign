# PROTOTYPE for issue #18. Adds the probe to a Gateway image so it runs as the
# Gateway's own user with the Gateway's own bubblewrap.
#
# The probe is cross-compiled on the build host, and the final stage only copies
# a file, so building linux/amd64 needs no emulation.
#
# Fargate (the reporter's image, linux/amd64):
#   docker buildx build --platform linux/amd64 -t <registry>/isolation-probe --push .
# Local, on top of a locally built Gateway:
#   docker build --build-arg GATEWAY_IMAGE=countersign-demo/gateway:local -t isolation-probe .
#   docker run --rm isolation-probe
ARG GATEWAY_IMAGE=ghcr.io/zeroae/countersign-gateway:v0.2.0

FROM --platform=$BUILDPLATFORM rust:1.99-bookworm AS build
ARG BUILDARCH
ARG TARGETARCH
WORKDIR /probe
COPY Cargo.toml ./
COPY src ./src
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu; cc=x86_64-linux-gnu-gcc; pkg=gcc-x86-64-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu; cc=aarch64-linux-gnu-gcc; pkg=gcc-aarch64-linux-gnu ;; \
      *) echo "unsupported $TARGETARCH"; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update && apt-get install -y --no-install-recommends "$pkg" "libc6-dev-$TARGETARCH-cross"; \
      rustup target add "$target"; \
      export "CARGO_TARGET_$(echo "$target" | tr a-z- A-Z_)_LINKER=$cc"; \
    fi; \
    cargo build --release --target "$target"; \
    cp "target/$target/release/isolation-probe" /isolation-probe

FROM ${GATEWAY_IMAGE}
COPY --from=build /isolation-probe /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/isolation-probe"]
