# The OAuth token helper (`imaplane-oauth-token`)

IMAPLANE's XOAUTH2 mode reads a short-lived **access token** from `access_token_file` on every
connection and never refreshes it. The packages ship a small helper that obtains a refresh token
once (browser consent, loopback redirect, PKCE) and then keeps the access-token file fresh.
In a source checkout the same program is `scripts/oauth_token.py`.

**Status:** the flow is tested against a loopback fake token endpoint only. Gmail was never
contacted and Microsoft 365 is untested; treat both as unverified until a disposable-account test.

## Requirements

- `python3` (3.8 or newer) — **standard library only**, no pip packages. The DEB/RPM packages
  *recommend* `python3` but do not require it, because IMAPLANE itself does not need Python.
  Install it with `apt install python3` or `dnf install python3`.
- A Desktop-app OAuth client (Google: download `client.json`, see `GOOGLE_OAUTH_SETUP.md`;
  Microsoft: a public client id and a tenant).
- A browser on the same machine (the redirect is `http://127.0.0.1:<port>`).

## Usage

```sh
umask 077                                    # keep every file you create private
# 1. once: consent in a browser, store the refresh token (and a first access token)
imaplane-oauth-token authorize --provider google --client-json client.json \
    --login-hint you@gmail.com --refresh-token-file refresh.token --access-token-file access.token

# 2. before/while migrating: refresh the access token file (add --loop to keep it fresh)
imaplane-oauth-token refresh --provider google --client-json client.json \
    --refresh-token-file refresh.token --access-token-file access.token --loop
```

Point `access_token_file` of the IMAPLANE configuration at `access.token` and set
`auth = "xoauth2"`. Microsoft: `--provider microsoft --client-id <id> --tenant <tenant>`.

## What it guarantees

- Client-secret, refresh-token and access-token files must be **regular files (not symlinks) owned
  by you with mode 0600 or 0400**; anything else is refused before any network use.
- Token files are written to a private temporary file in the same directory, synced, and
  atomically renamed into place with mode 0600, so IMAPLANE never reads a partial token. If the
  helper is killed at the wrong moment a `.token-*` file (mode 0600) may be left beside the
  token file; it can be deleted.
- Secrets are **never printed, logged or placed on the command line**. Only file paths and public
  ids appear in argv. Only an allowlisted OAuth `error` code (such as `invalid_grant`) is ever
  echoed from a failed response.
- Endpoints must be `https` (plain `http` is accepted only for `127.0.0.1`, used by tests).
- A failed `--loop` refresh keeps the previous access token and retries; `invalid_grant` (revoked
  or expired refresh token) is final.

The refresh token is as powerful as the account's mail: keep `refresh.token`, `client.json` and the
access token in a private directory, and revoke the app's access when the migration is finished.

## Tests

`tests/local/test_provider_tools.py` (unit, fake provider) and `tests/local/oauth_cli_security.py`
(black-box: file modes, atomic replacement, no secret in stdout/stderr/argv, refusal of open or
symlinked files). `scripts/test-package-oauth.sh <package>` runs the latter against the installed
`/usr/bin/imaplane-oauth-token` in a clean container.
