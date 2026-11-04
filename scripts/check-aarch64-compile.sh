#!/usr/bin/env bash
# Compile-check (NOT run) the architecture-sensitive new code for aarch64-unknown-linux-gnu.
#
# This machine class has no ARM64 emulation, so the code cannot be executed here; this script only
# proves that the parts most likely to differ by architecture still type-check there:
#   * src/spool.rs (libc statfs/statvfs/O_TMPFILE/linkat/fstat use), with its tests, via a scratch
#     crate that stubs its two crate-internal dependencies;
#   * the vendored IMAP client library including the streaming module (TLS feature disabled, since
#     cross-compiling OpenSSL needs target libraries).
# The whole IMAPLANE crate is NOT checked here (it links OpenSSL); the release workflow builds and
# tests arm64 packages natively on GitHub's arm64 runners.
# Requires Docker and an image with rustup and cargo (default: a local image named imaplane-dev).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dev_image="${IMAPLANE_DEV_IMAGE:-imaplane-dev:1.85.1}"
stable_image="${IMAPLANE_STABLE_IMAGE:-imaplane-dev:stable}"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/src"
cp "$root/src/spool.rs" "$scratch/src/spool.rs"
cat >"$scratch/Cargo.toml" <<'TOML'
[package]
name = "spool-arm-check"
version = "0.0.0"
edition = "2024"
[dependencies]
libc = "0.2"
sha2 = "0.10"
[dev-dependencies]
tempfile = "3"
TOML
cat >"$scratch/src/lib.rs" <<'RS'
pub mod fault { pub fn point(_: &str) {} }
pub mod journal { pub fn fingerprint(b: &[u8]) -> String { use sha2::{Digest, Sha256}; format!("{:x}", Sha256::digest(b)) } }
pub mod spool;
RS
echo "== src/spool.rs and its tests (aarch64-unknown-linux-gnu)"
docker run --rm -v "$scratch":/src:ro "$dev_image" sh -c '
  cp -r /src /tmp/crate && cd /tmp/crate &&
  rustup target add aarch64-unknown-linux-gnu >/dev/null 2>&1 &&
  cargo check --tests --target aarch64-unknown-linux-gnu 2>&1 | tail -2'
echo "== vendored IMAP client library incl. streaming (aarch64-unknown-linux-gnu, no TLS feature)"
docker run --rm -v "$root/vendor":/src:ro "$stable_image" sh -c '
  cp -r /src /tmp/v && cd /tmp/v/imap && rm -f Cargo.lock &&
  rustup target add --toolchain stable aarch64-unknown-linux-gnu >/dev/null 2>&1 &&
  cargo +stable check --lib --no-default-features --target aarch64-unknown-linux-gnu 2>&1 | tail -2'
echo "compile-check finished (no code was executed on ARM64)"
