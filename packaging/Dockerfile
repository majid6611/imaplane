# Native builds inside the target package family's userland, not cross-labelled host binaries.
ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE} AS build
ARG RUST_VERSION=1.85.1
RUN if [ -f /etc/debian_version ]; then \
      apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev curl ca-certificates python3; \
    else \
      dnf install -y gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl-minimal ca-certificates python3 tar gzip; \
    fi
ENV CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup PATH=/opt/cargo/bin:${PATH}
RUN curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs -o /tmp/rustup.sh && \
    sh /tmp/rustup.sh -y --profile minimal --default-toolchain ${RUST_VERSION} --no-modify-path
WORKDIR /src
ENV CARGO_BUILD_JOBS=2
COPY Cargo.toml Cargo.lock ./
# Build-time SQLite flags (fdatasync); scripts/check-elf.py verifies the resulting binary actually uses them.
COPY .cargo .cargo
COPY vendor vendor
COPY src src
COPY tests/*.rs tests/
# Cargo.toml declares an example under tests/support (the schema-5 upgrade helper); the build fails without it.
COPY tests/support tests/support
RUN cargo test --locked && cargo build --release --locked && mkdir /output && \
    cp target/release/imaplane /output/imaplane && /output/imaplane --version
COPY LICENSE /src/LICENSE
COPY scripts/collect-licenses.py /tmp/collect-licenses.py
RUN cargo metadata --locked --format-version 1 --filter-platform "$(rustc -vV | sed -n 's/^host: //p')" > /tmp/metadata.json && \
    python3 /tmp/collect-licenses.py /tmp/metadata.json /output/THIRD_PARTY_LICENSES.txt "$(rustc --print sysroot)"
FROM scratch AS artifact
COPY --from=build /output/ /

# Isolated integration-lab tools; production package targets are unchanged.
FROM debian:bookworm-slim AS lab
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 python3
COPY --from=build /output/imaplane /usr/local/bin/imaplane
ENTRYPOINT ["/usr/local/bin/imaplane"]
