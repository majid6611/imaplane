#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
format=${1:?usage: build-packages.sh deb|rpm amd64|arm64}
arch=${2:?architecture required}
case "$format" in
  deb) base=debian:bookworm-slim ;;
  rpm) base=rockylinux:9 ;;
  *) echo 'Expected deb or rpm' >&2; exit 1 ;;
esac
case "$(uname -m):$arch" in
  x86_64:amd64|aarch64:arm64) ;;
  *) echo 'Use a native runner for the requested architecture; refusing to mislabel a binary' >&2; exit 1 ;;
esac
export ARCH="$arch"
export VERSION
VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml","rb"))["package"]["version"])')
export NOTICES="$PWD/dist/build-$format-$arch/THIRD_PARTY_LICENSES.txt"
export BINARY="$PWD/dist/build-$format-$arch/imaplane"
docker buildx build --file packaging/Dockerfile --build-arg "BASE_IMAGE=$base" --target artifact --output "type=local,dest=dist/build-$format-$arch" .
python3 scripts/check-elf.py "$BINARY" "$arch"
python3 scripts/install-nfpm.py target/tools
nfpm="$PWD/target/tools/nfpm"
mkdir -p dist/packages
"$nfpm" package --config packaging/nfpm.yaml --packager "$format" --target "dist/packages/imaplane_${VERSION}_${arch}.${format}"
