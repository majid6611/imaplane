#!/usr/bin/env python3
"""Black-box security test of the OAuth token helper as an installed command.

  oauth_cli_security.py PATH_TO_HELPER   (e.g. /usr/bin/imaplane-oauth-token or scripts/oauth_token.py)

It talks only to a loopback fake token endpoint on 127.0.0.1 (never a real provider) and checks, through
the real command line of the helper, that:
  * token files are mode 0600 and replaced atomically (no leftover temporary files, even after errors);
  * no secret (client secret, refresh token, access token, authorization code) appears on stdout, stderr
    or in the helper's argv (read back from /proc while it runs);
  * group/world-readable credential files are refused, and nothing is written for a refused request;
  * an invalid_grant answer is reported with the allowlisted code only and leaves the old token intact.
Python standard library only.
"""
import http.server
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HELPER = sys.argv[1]
SECRETS = ['CLIENT-SECRET-XYZ', 'REFRESH-TOKEN-ABC', 'ACCESS-TOKEN-NEW', 'ACCESS-TOKEN-OLD']


class Provider(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers['Content-Length'])).decode()
        good = 'refresh_token=REFRESH-TOKEN-ABC' in body and 'client_secret=CLIENT-SECRET-XYZ' in body
        answer = {'access_token': 'ACCESS-TOKEN-NEW', 'expires_in': 3599} if good else {'error': 'invalid_grant', 'error_description': 'SECRET-DETAIL'}
        data = json.dumps(answer).encode()
        self.send_response(200 if good else 400)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def private(path, text, mode=0o600):
    path.write_text(text)
    path.chmod(mode)
    return str(path)


def run(args, sample_argv=True):
    """Run the helper; while it runs, read its argv back from /proc and keep it for the leak check."""
    p = subprocess.Popen([sys.executable, HELPER, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    seen = []
    while p.poll() is None:
        try:
            seen.append(Path(f'/proc/{p.pid}/cmdline').read_bytes().decode(errors='replace'))
        except OSError:
            pass
        time.sleep(0.005)
    out, err = p.communicate()
    return p.returncode, out, err, seen


def main():
    server = http.server.HTTPServer(('127.0.0.1', 0), Provider)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_address[1]}/token'
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        os.chmod(d, 0o700)
        client = private(d / 'client.json', json.dumps({'installed': {'client_id': 'cid', 'client_secret': 'CLIENT-SECRET-XYZ'}}))
        refresh = private(d / 'refresh', 'REFRESH-TOKEN-ABC\n')
        access = d / 'access'
        access.write_text('ACCESS-TOKEN-OLD'); access.chmod(0o640)   # an old, too-open file: replaced, result must be 0600
        base = ['refresh', '--provider', 'google', '--client-json', client, '--refresh-token-file', refresh,
                '--access-token-file', str(access), '--token-url', url]

        def no_leaks(label, out, err, argv):
            blob = out + err + ''.join(argv)
            for s in SECRETS + ['SECRET-DETAIL']:
                assert s not in blob, f'{label}: secret/detail leaked: {s}'

        # 1. a good refresh
        code, out, err, argv = run(base)
        assert code == 0, (code, out, err)
        assert access.read_text() == 'ACCESS-TOKEN-NEW'
        assert stat.S_IMODE(access.stat().st_mode) == 0o600, oct(access.stat().st_mode)
        assert not [p for p in d.iterdir() if p.name.startswith('.token-')], 'temporary token file left behind'
        no_leaks('refresh', out.replace('ACCESS-TOKEN-NEW', ''), err, argv)
        assert 'ACCESS-TOKEN-NEW' not in out + err
        print('PASS refresh: token file 0600, atomic, nothing secret on stdout/stderr/argv')

        # 2. the endpoint refuses (invalid_grant): only the allowlisted code is shown; the old token stays
        bad_refresh = private(d / 'refresh-bad', 'WRONG-REFRESH\n')
        before = access.read_text()
        code, out, err, argv = run(['refresh', '--provider', 'google', '--client-json', client, '--refresh-token-file', bad_refresh,
                                    '--access-token-file', str(access), '--token-url', url])
        assert code == 1 and 'invalid_grant' in err, (code, out, err)
        assert access.read_text() == before
        no_leaks('invalid_grant', out, err, argv)
        assert 'WRONG-REFRESH' not in out + err
        assert not [p for p in d.iterdir() if p.name.startswith('.token-')]
        print('PASS refusal: allowlisted error code only, previous token untouched, no leftovers')

        # 3. group/world-readable inputs are refused before any network use
        for label, make in (('refresh token', lambda: private(d / 'open-refresh', 'REFRESH-TOKEN-ABC', 0o644)),
                            ('client json', lambda: private(d / 'open-client.json', json.dumps({'installed': {'client_id': 'c', 'client_secret': 'CLIENT-SECRET-XYZ'}}), 0o640))):
            path = make()
            a = list(base)
            a[a.index('--refresh-token-file') + 1 if 'refresh' in label else a.index('--client-json') + 1] = path
            before = access.read_text()
            code, out, err, argv = run(a)
            assert code == 1 and 'mode 0600' in err, (label, code, out, err)
            assert access.read_text() == before
            no_leaks(label, out, err, argv)
        print('PASS permissions: open credential files refused, nothing written')

        # 4. a symlinked credential and a non-https endpoint are refused
        link = d / 'link'
        link.symlink_to(refresh)
        a = list(base); a[a.index('--refresh-token-file') + 1] = str(link)
        code, out, err, argv = run(a)
        assert code == 1, (code, out, err)
        code, out, err, argv = run(base[:-1] + ['http://example.com/token'])
        assert code == 1 and 'https' in err, (code, out, err)
        no_leaks('endpoint', out, err, argv)
        print('PASS hardening: symlinked token and plain-http endpoint refused')
    server.shutdown()
    print('OAUTH CLI SECURITY: all checks passed')


main()
