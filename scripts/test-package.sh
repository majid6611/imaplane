#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
package=$(realpath "${1:?package path required}")
case "$package" in
  *.deb)
    docker run --rm -v "$package:/tmp/imaplane.deb:ro" debian:bookworm-slim sh -ec '
      mkdir -m 700 /root/imaplane-state
      echo keep-me > /root/imaplane-state/sentinel
      apt-get update >/dev/null
      apt-get -o "Dpkg::Options::=--path-include=/usr/share/doc/imaplane*" install -y /tmp/imaplane.deb >/dev/null
      imaplane --version
      imaplane migrate --help >/dev/null
      test -f /usr/share/doc/imaplane/examples/migration.toml
      test -s /usr/share/doc/imaplane/THIRD_PARTY_LICENSES.txt
      test -x /usr/bin/imaplane-oauth-token
      test -s /usr/share/doc/imaplane/docs/WAL_JOURNAL.md
      test -s /usr/share/doc/imaplane/docs/GMAIL_DUPLICATE_MERGE_DESIGN.md
      apt-get remove -y imaplane >/dev/null
      test "$(cat /root/imaplane-state/sentinel)" = keep-me
      test ! -e /usr/bin/imaplane
      test ! -e /usr/bin/imaplane-oauth-token
    ' ;;
  *.rpm)
    docker run --rm -v "$package:/tmp/imaplane.rpm:ro" rockylinux:9 sh -ec '
      mkdir -m 700 /root/imaplane-state
      echo keep-me > /root/imaplane-state/sentinel
      dnf --disablerepo="*" install -y /tmp/imaplane.rpm >/dev/null
      imaplane --version
      imaplane migrate --help >/dev/null
      test -f /usr/share/doc/imaplane/examples/migration.toml
      test -s /usr/share/doc/imaplane/THIRD_PARTY_LICENSES.txt
      test -x /usr/bin/imaplane-oauth-token
      test -s /usr/share/doc/imaplane/docs/WAL_JOURNAL.md
      test -s /usr/share/doc/imaplane/docs/GMAIL_DUPLICATE_MERGE_DESIGN.md
      dnf --disablerepo="*" remove -y imaplane >/dev/null
      test "$(cat /root/imaplane-state/sentinel)" = keep-me
      test ! -e /usr/bin/imaplane
      test ! -e /usr/bin/imaplane-oauth-token
    ' ;;
  *) echo 'Expected DEB or RPM' >&2; exit 1 ;;
esac
