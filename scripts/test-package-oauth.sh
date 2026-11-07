#!/usr/bin/env bash
# Installs a DEB or RPM in a clean container, adds python3 (the package only *recommends* it) and runs the
# black-box OAuth helper security test against the installed /usr/bin/imaplane-oauth-token. Loopback only.
set -euo pipefail
cd "$(dirname "$0")/.."
package=$(realpath "${1:?package path required}")
test_py=$(realpath tests/local/oauth_cli_security.py)
check='
  test -x /usr/bin/imaplane-oauth-token
  test "$(stat -c %a /usr/bin/imaplane-oauth-token)" = 755
  test -s /usr/share/doc/imaplane/docs/OAUTH_TOKEN_HELPER.md
  python3 --version
  python3 /tmp/oauth_cli_security.py /usr/bin/imaplane-oauth-token
  imaplane-oauth-token --help | grep -q refresh
'
case "$package" in
  *.deb)
    docker run --rm -v "$package:/tmp/imaplane.deb:ro" -v "$test_py:/tmp/oauth_cli_security.py:ro" debian:bookworm-slim sh -ec '
      apt-get update >/dev/null
      apt-get -o "Dpkg::Options::=--path-include=/usr/share/doc/imaplane*" install -y /tmp/imaplane.deb python3 >/dev/null
      '"$check" ;;
  *.rpm)
    docker run --rm -v "$package:/tmp/imaplane.rpm:ro" -v "$test_py:/tmp/oauth_cli_security.py:ro" rockylinux:9 sh -ec '
      dnf install -y /tmp/imaplane.rpm python3 >/dev/null
      '"$check" ;;
  *) echo 'Expected DEB or RPM' >&2; exit 1 ;;
esac
