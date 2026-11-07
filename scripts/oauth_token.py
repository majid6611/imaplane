#!/usr/bin/env python3
"""OAuth 2.0 token helper for IMAPLANE's XOAUTH2 mode (Python stdlib only).

IMAPLANE reads an access token from `access_token_file` at every connect and never
refreshes it itself. This tool obtains a refresh token once (browser consent) and
keeps an access-token file fresh.

  oauth_token.py authorize --provider google --client-json client.json \\
        --login-hint you@gmail.com --refresh-token-file refresh.token
  oauth_token.py refresh   --provider google --client-json client.json \\
        --refresh-token-file refresh.token --access-token-file access.token [--loop]

Providers: google (tested design, loopback + PKCE for a Desktop-app client) and
microsoft (same flow, UNTESTED against the live service).

Safety: tokens go only to 0600 files written atomically (tmp + rename, so IMAPLANE
never reads a partial token); they are never printed, logged or placed in argv.
Client-secret and token files must be regular files (not symlinks), owned by you and mode 0600/0400.
Endpoints must be https (plain http only for 127.0.0.1, used by the tests).
Only an allowlisted OAuth `error` code is ever echoed from a failed response.
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PROVIDERS = {
    'google': {
        'auth_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'scope': 'https://mail.google.com/',
        'redirect_host': '127.0.0.1',
        'extra_auth': {'access_type': 'offline', 'prompt': 'consent'},
    },
    'microsoft': {
        'auth_url': 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
        'token_url': 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
        'scope': 'https://outlook.office365.com/IMAP.AccessAsUser.All offline_access',
        'redirect_host': 'localhost',
        'extra_auth': {},
    },
}
SAFE_ERROR = re.compile(r'^[a-z_]{1,40}$')
MAX_FILE = 16384


class OAuthError(Exception):
    pass


def read_private(path, label):
    """Read a small credential file: a regular file (never a symlink) owned by you, mode 0600/0400.
    The checks are made on the opened descriptor, so the file cannot be swapped between check and read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise OAuthError(f'{label} file must be a regular file (not a symlink) owned by you with mode 0600 or 0400') from exc
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.getuid():
            raise OAuthError(f'{label} file must be a regular file (not a symlink) owned by you with mode 0600 or 0400')
        data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise OAuthError(f'{label} file is too large')
    return data.decode('utf-8').strip()


def write_private(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.token-')
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def check_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == 'https':
        return url
    if parsed.scheme == 'http' and parsed.hostname == '127.0.0.1':
        return url  # tests only; never a real provider
    raise OAuthError('endpoint must be https (or http on 127.0.0.1 for tests)')


def load_client(args):
    """Return (client_id, client_secret or None). The client id is not a secret."""
    if args.client_json:
        data = json.loads(read_private(args.client_json, 'client JSON'))
        section = data.get('installed')
        if not isinstance(section, dict) or not section.get('client_id'):
            raise OAuthError('client JSON must be a Desktop-app client ("installed" section)')
        return section['client_id'], section.get('client_secret')
    if args.client_id:
        secret = read_private(args.client_secret_file, 'client secret') if args.client_secret_file else None
        return args.client_id, secret
    raise OAuthError('give --client-json (Google) or --client-id (Microsoft)')


def endpoints(args):
    preset = PROVIDERS[args.provider]
    fill = {'tenant': args.tenant or 'common'}
    auth = check_url((args.auth_url or preset['auth_url']).format(**fill))
    token = check_url((args.token_url or preset['token_url']).format(**fill))
    return preset, auth, token


def post_token(url, fields):
    body = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        code = 'http_error'
        try:
            candidate = json.load(exc).get('error', '')
            if isinstance(candidate, str) and SAFE_ERROR.match(candidate):
                code = candidate
        except Exception:
            pass
        raise OAuthError(f'token endpoint refused the request: {code}') from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise OAuthError('token endpoint unreachable') from None


def pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return verifier, challenge


class _Callback(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (stdlib naming)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        self.server.result = {k: v[0] for k, v in query.items()}
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'IMAPLANE: authorization received. You can close this tab.\n')

    def log_message(self, *args):  # never log request lines (they carry the code)
        pass


def authorize(args, announce=print, wait=300):
    """Run the interactive consent flow and store the refresh token (and optionally an access token)."""
    preset, auth_url, token_url = endpoints(args)
    client_id, client_secret = load_client(args)
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(24)
    server = http.server.HTTPServer(('127.0.0.1', args.port), _Callback)
    server.result = None
    server.timeout = 1
    redirect = f'http://{preset["redirect_host"]}:{server.server_address[1]}'
    scope = args.scope or preset['scope']
    query = {'client_id': client_id, 'redirect_uri': redirect, 'response_type': 'code', 'scope': scope,
             'state': state, 'code_challenge': challenge, 'code_challenge_method': 'S256', **preset['extra_auth']}
    if args.login_hint:
        query['login_hint'] = args.login_hint
    announce('Open this URL in a browser signed in to the DISPOSABLE test account:\n\n  '
             + auth_url + '?' + urllib.parse.urlencode(query) + '\n')
    deadline = time.monotonic() + wait
    try:
        while server.result is None and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    result = server.result
    if result is None:
        raise OAuthError('timed out waiting for the browser redirect')
    if not secrets.compare_digest(result.get('state', ''), state):
        raise OAuthError('state mismatch; authorization discarded')
    if 'error' in result:
        code = result['error'] if SAFE_ERROR.match(result['error']) else 'error'
        raise OAuthError(f'authorization refused: {code}')
    fields = {'grant_type': 'authorization_code', 'code': result.get('code', ''), 'client_id': client_id,
              'redirect_uri': redirect, 'code_verifier': verifier}
    if client_secret:
        fields['client_secret'] = client_secret
    tokens = post_token(token_url, fields)
    if not tokens.get('refresh_token'):
        raise OAuthError('no refresh token returned (revoke the app\'s access for this account and retry)')
    granted = tokens.get('scope', '')
    if granted and not all(part in granted.split() for part in scope.split() if part != 'offline_access'):
        raise OAuthError('the granted scope does not include everything requested; nothing was saved')
    write_private(args.refresh_token_file, tokens['refresh_token'])
    if args.access_token_file and tokens.get('access_token'):
        write_private(args.access_token_file, tokens['access_token'])
    announce(f'Authorized. Refresh token saved (mode 0600); access token valid about {int(tokens.get("expires_in", 0))} s.')
    return 0


def refresh_once(args):
    preset, _, token_url = endpoints(args)
    client_id, client_secret = load_client(args)
    fields = {'grant_type': 'refresh_token', 'refresh_token': read_private(args.refresh_token_file, 'refresh token'),
              'client_id': client_id}
    if client_secret:
        fields['client_secret'] = client_secret
    tokens = post_token(token_url, fields)
    if not tokens.get('access_token'):
        raise OAuthError('token endpoint returned no access token')
    write_private(args.access_token_file, tokens['access_token'])
    return int(tokens.get('expires_in', 3600))


def refresh(args, announce=print, sleep=time.sleep, iterations=None):
    done = 0
    while True:
        try:
            lifetime = refresh_once(args)
            announce(f'Access token refreshed (valid about {lifetime} s).')
            delay = max(60, lifetime - 300)
        except OAuthError as exc:
            if not args.loop or 'invalid_grant' in str(exc):
                raise  # a revoked/expired refresh token cannot be retried
            announce(f'refresh failed: {exc}; keeping the previous token and retrying in 60 s')
            delay = 60
        done += 1
        if not args.loop or (iterations is not None and done >= iterations):
            return 0
        sleep(delay)


def parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name in ('authorize', 'refresh'):
        p = sub.add_parser(name)
        p.add_argument('--provider', choices=sorted(PROVIDERS), required=True)
        p.add_argument('--client-json', help='Google Desktop-app client JSON (mode 0600)')
        p.add_argument('--client-id', help='public client id (Microsoft)')
        p.add_argument('--client-secret-file')
        p.add_argument('--tenant', help='Microsoft tenant id or "common"/"organizations"')
        p.add_argument('--refresh-token-file', required=True)
        p.add_argument('--auth-url', help=argparse.SUPPRESS)
        p.add_argument('--token-url', help=argparse.SUPPRESS)
        if name == 'authorize':
            p.add_argument('--login-hint')
            p.add_argument('--scope')
            p.add_argument('--port', type=int, default=0)
            p.add_argument('--access-token-file')
        else:
            p.add_argument('--access-token-file', required=True)
            p.add_argument('--loop', action='store_true', help='keep refreshing before expiry until stopped')
    return ap


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return authorize(args) if args.cmd == 'authorize' else refresh(args)
    except OAuthError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:  # unreadable/invalid local files; no secret in the type name
        print(f'error: {type(exc).__name__} while reading a local file or response', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
