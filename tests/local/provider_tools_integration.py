#!/usr/bin/env python3
"""Rehearsal of the provider-test toolchain against two LOCAL Dovecot containers.

Seeds the synthetic corpus, snapshots the source, runs IMAPLANE with diagnostics on,
snapshots again, and proves the comparison tools both pass a correct copy and catch
deliberate tampering. Needs Docker. Never contacts a real provider.
Usage: python3 tests/local/provider_tools_integration.py [path/to/imaplane]
"""
import imaplib
import json
import os
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'target/release/imaplane').resolve()
SCRIPTS = ROOT / 'scripts'
UNICODE_FOLDER = 'Archive/Éléments 📬'
UNICODE_WIRE = 'Archive/&AMk-l&AOk-ments &2D3c7A-'   # as printed by `imap_snapshot.py list`
FAILED = []
EXTRA = f"stream_threshold_bytes = {os.environ['IMAPLANE_TEST_STREAM_THRESHOLD']}\n" if os.environ.get('IMAPLANE_TEST_STREAM_THRESHOLD') else ''


def check(name, fn):
    try:
        fn(); print('PASS', name, flush=True)
    except BaseException as exc:
        FAILED.append(name); print('FAIL', name, '->', repr(exc)[:900], flush=True)


def py(script, *args, expected=0):
    p = subprocess.run([sys.executable, '-I', str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True, timeout=300)
    assert p.returncode == expected, (script, args[:3], p.returncode, p.stdout, p.stderr)
    return p


with tempfile.TemporaryDirectory(prefix='imaplane-tools-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    labdir = root / 'lab'
    started = False
    try:
        py('provider_lab.py', 'up', '--dir', labdir, '--roles', 'source,destination'); started = True
        labinfo = json.loads((labdir / 'lab.json').read_text())
        py('provider_lab.py', 'seed', '--dir', labdir)
        manifest = json.loads((labdir / 'corpus-manifest.json').read_text())

        def conn(role):
            return ['--host', 'localhost', '--port', labinfo['ports'][role], '--user', 'lab',
                    '--password-file', labdir / 'password', '--ca-file', labdir / 'tls.crt']

        folders = ['INBOX', UNICODE_WIRE]
        cfg = root / 'migrate.toml'
        cfg.write_text(f'state_dir = "{root/"state"}"\ntimeout_seconds = 30\nread_attempts = 4\n{EXTRA}' + ''.join(
            f'[{r}]\nhost = "localhost"\nport = {labinfo["ports"][r]}\nusername = "lab"\npassword_file = "{labdir/"password"}"\nca_file = "{labdir/"tls.crt"}"\n'
            for r in ('source', 'destination')) + ''.join(f'[[folders]]\nsource = "{f}"\ndestination = "{f}"\n' for f in ('INBOX', UNICODE_FOLDER)))
        cfg.chmod(0o600)
        diag = root / 'diag.jsonl'

        def capture(role, name):
            py('imap_snapshot.py', 'capture', *conn(role), '--folder', 'INBOX', '--folder', UNICODE_WIRE, '--out', root / name)

        def migrate(action, expected=0):
            p = subprocess.run([str(BIN), '--diagnostics-file', str(diag), action, '--config', str(cfg), '--json'],
                               capture_output=True, text=True, timeout=300)
            assert p.returncode == expected, (p.returncode, p.stdout[-1500:], p.stderr[-800:])
            return json.loads(p.stdout)

        check('list shows the wire (modified UTF-7) folder names', lambda: (
            (lambda out: (UNICODE_WIRE in out) or (_ for _ in ()).throw(AssertionError(out)))(py('imap_snapshot.py', 'list', *conn('source')).stdout)))

        capture('source', 'src-before.json')
        check('source snapshot holds every seeded message', lambda: (
            lambda s: (sum(len(f['messages']) for f in s['folders'].values()) == len(manifest)) or (_ for _ in ()).throw(AssertionError(len(manifest))))(
                json.loads((root / 'src-before.json').read_text())))
        check('IMAPLANE migrates the corpus (diagnostics on)', lambda: migrate('migrate')['complete'] or (_ for _ in ()).throw(AssertionError('incomplete')))
        capture('source', 'src-after.json'); capture('destination', 'dst.json')
        check('source provably unchanged', lambda: py('imap_snapshot.py', 'same', root / 'src-before.json', root / 'src-after.json'))
        check('destination equals source (content, dates, flags, duplicate multiplicity)', lambda: py(
            'imap_snapshot.py', 'copy', root / 'src-before.json', root / 'dst.json', '--map', 'INBOX=INBOX', '--map', f'{UNICODE_WIRE}={UNICODE_WIRE}'))
        check('rerun is idempotent: no new messages', lambda: (
            migrate('migrate')['complete'], capture('destination', 'dst2.json'),
            py('imap_snapshot.py', 'copy', root / 'src-before.json', root / 'dst2.json', '--map', 'INBOX=INBOX', '--map', f'{UNICODE_WIRE}={UNICODE_WIRE}'),
            [(_ for _ in ()).throw(AssertionError('destination changed')) for a, b in [(json.loads((root / 'dst.json').read_text()), json.loads((root / 'dst2.json').read_text()))]
             if {f: [m['sha256'] for m in v['messages']] for f, v in a['folders'].items()} != {f: [m['sha256'] for m in v['messages']] for f, v in b['folders'].items()}]))
        check('verify command agrees', lambda: migrate('verify')['complete'] or (_ for _ in ()).throw(AssertionError('verify incomplete')))

        def ctx(role):
            c = imaplib.IMAP4_SSL('localhost', labinfo['ports'][role], ssl_context=ssl.create_default_context(cafile=str(labdir / 'tls.crt')))
            c.login('lab', (labdir / 'password').read_text().strip()); return c

        def tamper_destination():
            c = ctx('destination'); c.select('INBOX')
            typ, data = c.uid('SEARCH', None, 'ALL'); first = data[0].split()[0]
            c.uid('STORE', first, '+FLAGS', '(\\Deleted)'); c.expunge(); c.logout()
            capture('destination', 'dst-tampered.json')
            p = py('imap_snapshot.py', 'copy', root / 'src-before.json', root / 'dst-tampered.json', '--map', 'INBOX=INBOX', '--map', f'{UNICODE_WIRE}={UNICODE_WIRE}', expected=1)
            assert 'MISMATCH' in p.stdout and 'missing' in p.stdout, p.stdout
        check('comparison catches a deleted destination message', tamper_destination)

        def tamper_source():
            c = ctx('source'); c.append('INBOX', None, None, b'Subject: intruder\r\n\r\nnew\r\n'); c.logout()
            capture('source', 'src-tampered.json')
            p = py('imap_snapshot.py', 'same', root / 'src-before.json', root / 'src-tampered.json', expected=1)
            assert 'appeared' in p.stdout, p.stdout
        check('comparison catches a changed source', tamper_source)

        def diagnostics_clean():
            raw = diag.read_text()
            password = (labdir / 'password').read_text().strip()
            for forbidden in (password, 'Éléments', 'Archive', 'Subject', 'lab-', 'Bearer'):
                assert forbidden not in raw, forbidden
            events = [json.loads(line) for line in raw.splitlines()]
            assert any(e.get('op') == 'append' and e['outcome'] == 'OK' for e in events)
            assert {e['role'] for e in events if e['event'] == 'connect'} == {'source', 'destination'}
        check('real-Dovecot diagnostics contain no secrets, names or content', diagnostics_clean)

        def generated_config_loads():
            (root / 'tok').write_text('placeholder'); (root / 'tok').chmod(0o600)
            out = root / 'g.toml'
            py('provider_lab.py', 'config', '--dir', labdir, '--direction', 'gmail-to-dovecot', '--provider-user', 'disposable@example.test',
               '--token-file', root / 'tok', '--state-dir', root / 'gstate', '--out', out)
            # Point the provider side at a closed loopback port: the config must load, then the connection must fail.
            text = out.read_text().replace('imap.gmail.com', '127.0.0.1').replace('port = 993', 'port = 9')
            out.unlink(); out.write_text(text); out.chmod(0o600)
            p = subprocess.run([str(BIN), 'migrate', '--config', str(out), '--dry-run'], capture_output=True, text=True, timeout=120)
            assert p.returncode != 0 and 'configuration' not in p.stderr.lower() and 'unknown field' not in p.stderr.lower(), (p.returncode, p.stderr)
            assert not (root / 'gstate' / 'journal.sqlite3').exists()
        check('generated Gmail-to-Dovecot config is accepted by IMAPLANE (provider side pointed at a closed loopback port)', generated_config_loads)
    finally:
        if started:
            py('provider_lab.py', 'down', '--dir', labdir)
    mine = set(labinfo['containers'].values())
    present = set(subprocess.run(['docker', 'ps', '-a', '--format', '{{.Names}}'], capture_output=True, text=True).stdout.split())
    check('this run\'s lab containers are gone after down', lambda: (not (mine & present)) or (_ for _ in ()).throw(AssertionError(mine & present)))

print('FAILED: ' + str(FAILED) if FAILED else 'all provider-tool integration checks passed')
sys.exit(1 if FAILED else 0)
