# The Fargate qualification image: the Gateway, the worker sandbox containment
# test and the runtime test, with what the runtime test needs and no bubblewrap.
# It is a qualification tool. The Gateway image is distribution/Dockerfile.
#
# Build it with run.sh, from the repository root as context. Every RUN is in a
# stage that runs on the build host's architecture, and the last stage only
# copies files, so building linux/amd64 on an arm64 host (or the reverse) needs
# no emulation.
FROM --platform=$BUILDPLATFORM rust:1.99-bookworm AS build
ARG BUILDARCH
ARG TARGETARCH
WORKDIR /build
COPY Cargo.toml Cargo.lock LICENSE ./
COPY crates ./crates
# The containment test holds the Gateway executable's path from its build, so
# the Gateway is staged at the path cargo built it at.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu; gnu=x86_64-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu; gnu=aarch64-linux-gnu ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends "gcc-$(echo "$gnu" | tr _ -)" "libc6-dev-$TARGETARCH-cross"; \
      rustup target add "$target"; \
      export "CARGO_TARGET_$(echo "$target" | tr a-z- A-Z_)_LINKER=$gnu-gcc"; \
    fi; \
    built() { \
      cargo "$@" --locked --release --target "$target" -p countersign-gateway --message-format=json \
        >/tmp/built.json; \
      sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' /tmp/built.json; \
    }; \
    gateway=$(built build --bin countersign-gateway); \
    containment=$(built test --no-run --test worker_sandbox | grep /deps/worker_sandbox-); \
    test -x "$gateway"; test -x "$containment"; \
    mkdir -p "/stage$(dirname "$gateway")" /stage/usr/local/bin /stage/qualification; \
    cp "$gateway" "/stage$gateway"; \
    ln -s "$gateway" /stage/usr/local/bin/countersign-gateway; \
    cp "$containment" /stage/usr/local/bin/worker-sandbox-containment; \
    cp crates/countersign-gateway/tests/runtime.py /stage/qualification/

# What the runtime test needs beyond the base image's Python and curl, fetched
# for the target architecture and unpacked, never run.
FROM --platform=$BUILDPLATFORM python:3.12-slim-bookworm AS needs
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) machine=x86_64 ;; \
      arm64) machine=aarch64 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    pip install --no-cache-dir --target /stage/qualification/python --only-binary=:all: \
      --python-version 3.12 --implementation cp \
      --platform "manylinux_2_28_$machine" --platform "manylinux_2_17_$machine" --platform "manylinux2014_$machine" \
      cryptography==50.0.2; \
    dpkg --add-architecture "$TARGETARCH"; \
    apt-get update; \
    cd /tmp; \
    apt-get download "libnss-wrapper:$TARGETARCH"; \
    dpkg-deb -x libnss-wrapper_*.deb /stage

FROM python:3.12-bookworm
ARG REVISION=unknown
COPY --from=build /stage/ /
COPY --from=needs /stage/ /
COPY qualification/fargate/qualify.sh /qualification/
ENV PYTHONPATH=/qualification/python PYTHONUNBUFFERED=1 COUNTERSIGN_REVISION=$REVISION
# The Gateway image's user: not root, and with no capability.
USER 65531:65531
ENTRYPOINT ["/qualification/qualify.sh"]
