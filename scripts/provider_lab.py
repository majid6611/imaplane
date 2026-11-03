#!/usr/bin/env python3
"""Local, loopback-only Dovecot lab for provider compatibility tests (stdlib + Docker).

A provider test pairs ONE real provider with ONE local Dovecot:
  gmail-to-dovecot   dovecot-to-gmail   m365-to-dovecot   dovecot-to-m365

  provider_lab.py up     --dir D [--roles destination|source|source,destination]
  provider_lab.py seed   --dir D [--include-large] [--oversize-bytes N]   (source Dovecot only)
  provider_lab.py config --dir D --direction X --provider-user U --token-file T
                         --state-dir S --out FILE [--map SRC=DST ...]
  provider_lab.py status --dir D
  provider_lab.py down   --dir D

Safety: containers publish only on 127.0.0.1; the lab password is random and stays in
D (mode 0700); `seed` writes ONLY to containers recorded in D/lab.json, over loopback,
and the corpus is synthetic. Nothing here ever contacts a real provider; the generated
config only *names* the provider for IMAPLANE to use later. Containers are disposable
(mail lives in tmpfs) and are removed by `down`.
"""
import argparse
import base64
import datetime as dt
import hashlib
import imaplib
import json
import os
import random
import re
import secrets
import ssl
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Same pinned image as the test suites.
IMAGE = 'dovecot/dovecot:2.3.21@sha256:1c18c756f20d03867077a1b509a6e2e3008ab1eafa56377b6f2eca12dc1ba581'
LABEL = 'imaplane.provider-lab=1'
PREFIX = 'imaplane-provider-lab-'
DIRECTIONS = {
    'gmail-to-dovecot': ('imap.gmail.com', 'source'),
    'dovecot-to-gmail': ('imap.gmail.com', 'destination'),
    'm365-to-dovecot': ('outlook.office365.com', 'source'),
    'dovecot-to-m365': ('outlook.office365.com', 'destination'),
}
LAB_USER = 'lab'


def sh(*args, **kw):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw).stdout.strip()


def utf7(text):
    """IMAP modified UTF-7 for folder names."""
    out, run = '', ''

    def flush():
        nonlocal out, run
        if run:
            out += '&' + base64.b64encode(run.encode('utf-16-be')).decode().rstrip('=').replace('/', ',') + '-'
            run = ''
    for ch in text:
        if 0x20 <= ord(ch) <= 0x7e:
            flush()
            out += '&-' if ch == '&' else ch
        else:
            run += ch
    flush()
    return out


# ---------------------------------------------------------------- corpus ------------------
def _msg(subject, body, extra_headers=(), message_id=True, tag='x'):
    headers = [f'From: Lab Sender <sender@lab.test>', 'To: Lab Receiver <receiver@lab.test>', f'Subject: {subject}',
               'Date: Thu, 02 Jan 2020 03:04:05 +0000', 'MIME-Version: 1.0']
    if message_id:
        headers.append(f'Message-ID: <{tag}@lab.test>')
    headers.extend(extra_headers)
    return ('\r\n'.join(headers) + '\r\n\r\n').encode() + (body if isinstance(body, bytes) else body.encode())


def _attachment(tag, size, seed):
    data = random.Random(seed).randbytes(size)
    b64 = base64.encodebytes(data).decode().replace('\n', '\r\n')
    boundary = f'=_lab_{tag}'
    return _msg(f'attachment {size} bytes', f'--{boundary}\r\nContent-Type: text/plain\r\n\r\nsee attachment\r\n--{boundary}\r\n'
                'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n'
                f'Content-Disposition: attachment; filename="{tag}.bin"\r\n\r\n{b64}--{boundary}--\r\n',
                [f'Content-Type: multipart/mixed; boundary="{boundary}"'], tag=tag)


def corpus(include_large=False, oversize_bytes=0):
    """Deterministic synthetic messages: (folder, description, bytes, flags, datetime)."""
    old = dt.datetime(1999, 12, 31, 23, 59, 58, tzinfo=dt.timezone.utc)
    tz = dt.timezone(dt.timedelta(hours=-9, minutes=-30))
    mid = dt.datetime(2020, 1, 2, 3, 4, 5, tzinfo=tz)
    new = dt.datetime(2024, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
    dup = _msg('legitimate duplicate', 'identical twin\r\n', tag='twin')
    inner = _msg('inner message', 'forwarded body\r\n', tag='inner')
    pixel = base64.b64encode(random.Random(7).randbytes(300)).decode()
    items = [
        ('INBOX', 'tiny text', _msg('tiny', 'hello\r\n', tag='tiny'), [], new),
        ('INBOX', 'no Message-ID', _msg('no message id', 'body\r\n', message_id=False), [], new),
        ('INBOX', 'UTF-8 headers and body', _msg('=?UTF-8?B?' + base64.b64encode('日本語 café'.encode()).decode() + '?=',
         'Grüße — ünïcødé ✉\r\n', ['Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit'], tag='utf8'), [], new),
        ('INBOX', 'bare LF and very long line', _msg('bare lf', b'line one\nline two\n' + b'L' * 5000 + b'\n', tag='barelf'), [], new),
        ('INBOX', '8-bit content', _msg('8bit', bytes(range(160, 256)) + b'\r\n', ['Content-Type: application/octet-stream'], tag='8bit'), [], new),
        ('INBOX', 'nested message/rfc822', _msg('forward', inner, ['Content-Type: message/rfc822'], tag='nested'), [], new),
        ('INBOX', 'inline image', _msg('inline', f'--b\r\nContent-Type: text/html\r\n\r\n<img src="cid:p">\r\n--b\r\nContent-Type: image/png\r\n'
         f'Content-ID: <p>\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: inline\r\n\r\n{pixel}\r\n--b--\r\n',
         ['Content-Type: multipart/related; boundary="b"'], tag='inline'), [], new),
        ('INBOX', '1 MiB attachment', _attachment('onemib', 1 << 20, 1), ['\\Seen'], mid),
        ('INBOX', 'duplicate A', dup, ['\\Seen'], new),
        ('INBOX', 'duplicate B (identical bytes)', dup, ['\\Seen'], new),
        ('INBOX', 'old INTERNALDATE (1999)', _msg('old', 'old\r\n', tag='old'), [], old),
        ('INBOX', 'flag combination', _msg('flags', 'flags\r\n', tag='flags'), ['\\Seen', '\\Flagged', '\\Answered', '\\Draft'], new),
        ('INBOX', 'custom keyword', _msg('keyword', 'kw\r\n', tag='kw'), ['$LabKeyword'], new),
        ('Archive/Éléments 📬', 'Unicode-named nested folder', _msg('unicode folder', 'in unicode folder\r\n', tag='ufolder'), [], new),
    ]
    if include_large:
        items.append(('INBOX', '10 MiB attachment', _attachment('tenmib', 10 << 20, 2), [], new))
    if oversize_bytes:
        items.append(('INBOX', f'oversize probe {oversize_bytes} bytes', _attachment('oversize', oversize_bytes, 3), [], new))
    return items


# ---------------------------------------------------------------- lab lifecycle -----------
def lab_file(d):
    return Path(d) / 'lab.json'


def load_lab(d):
    path = lab_file(d)
    if not path.exists():
        raise SystemExit(f'{d}: no lab here; run `up` first')
    return json.loads(path.read_text())


def cmd_up(args):
    d = Path(args.dir)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    if lab_file(d).exists():
        raise SystemExit(f'{d}: a lab already exists here; run `down` first')
    roles = [r for r in args.roles.split(',') if r]
    if not roles or any(r not in ('source', 'destination') for r in roles):
        raise SystemExit('--roles must be source, destination or both')
    cert, key, pw, conf = d / 'tls.crt', d / 'tls.key', d / 'password', d / 'dovecot.conf'
    sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '30',
       '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1')
    password = secrets.token_hex(16)
    pw.write_text(password); os.chmod(pw, 0o600); os.chmod(key, 0o600)
    template = (ROOT / 'tests/local/dovecot.conf').read_text()
    assert 'password=imaplane-test-only' in template
    conf.write_text(template.replace('password=imaplane-test-only', f'password={password}')); os.chmod(conf, 0o600)
    # The Dovecot container user must be able to read the (private, throwaway) key.
    os.chmod(key, 0o644); os.chmod(conf, 0o644)
    lab = {'version': 1, 'containers': {}, 'ports': {}, 'user': LAB_USER}
    try:
        for role in roles:
            name = f'{PREFIX}{role}-{secrets.token_hex(4)}'
            sh('docker', 'run', '-d', '--name', name, '--label', LABEL, '-p', '127.0.0.1::993',
               '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL',
               *sum((['--cap-add', c] for c in ('CHOWN', 'DAC_OVERRIDE', 'SETUID', 'SETGID', 'SYS_CHROOT', 'NET_BIND_SERVICE', 'KILL')), []),
               '--read-only', '--tmpfs', '/run', '--tmpfs', '/tmp', '--tmpfs', '/var/lib/dovecot',
               '--tmpfs', '/srv/mail:uid=1000,gid=1000,mode=0700',
               '-v', f'{conf}:/etc/dovecot/dovecot.conf:ro', '-v', f'{cert}:/etc/dovecot/tls.crt:ro',
               '-v', f'{key}:/etc/dovecot/tls.key:ro', IMAGE)
            lab['containers'][role] = name
            mapping = sh('docker', 'port', name, '993/tcp')
            host, port = mapping.rsplit(':', 1)
            assert host == '127.0.0.1', f'unexpected bind {mapping}'
            lab['ports'][role] = int(port)
            lab_file(d).write_text(json.dumps(lab, indent=1)); os.chmod(lab_file(d), 0o600)
        for role in roles:
            wait_ready(d, lab, role)
    except BaseException:
        teardown(lab)
        lab_file(d).unlink(missing_ok=True)
        raise
    print(json.dumps({'dir': str(d), 'ports': lab['ports'], 'user': LAB_USER,
                      'password_file': str(pw), 'ca_file': str(cert)}, indent=1))
    return 0


def lab_connect(d, lab, role):
    pw = (Path(d) / 'password').read_text().strip()
    ctx = ssl.create_default_context(cafile=str(Path(d) / 'tls.crt'))
    conn = imaplib.IMAP4_SSL('localhost', lab['ports'][role], ssl_context=ctx, timeout=30)
    conn.login(lab['user'], pw)
    return conn


def wait_ready(d, lab, role):
    for _ in range(150):
        try:
            lab_connect(d, lab, role).logout()
            return
        except (OSError, imaplib.IMAP4.error, ssl.SSLError):
            time.sleep(0.2)
    raise SystemExit(f'{role} Dovecot did not become ready')


def teardown(lab):
    for name in lab.get('containers', {}).values():
        if not name.startswith(PREFIX):
            continue  # never remove anything this tool did not create
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def cmd_down(args):
    lab = load_lab(args.dir)
    teardown(lab)
    lab_file(args.dir).unlink()
    print('removed:', ', '.join(lab['containers'].values()))
    return 0


def cmd_status(args):
    lab = load_lab(args.dir)
    state = {r: sh('docker', 'inspect', '-f', '{{.State.Status}}', n) for r, n in lab['containers'].items()}
    print(json.dumps({'containers': state, 'ports': lab['ports']}, indent=1))
    return 0


def cmd_seed(args):
    lab = load_lab(args.dir)
    if 'source' not in lab['containers']:
        raise SystemExit('this lab has no source Dovecot; seeding is only for a Dovecot used as the SOURCE')
    conn = lab_connect(args.dir, lab, 'source')
    manifest, made = [], set()
    for folder, description, data, flags, when in corpus(args.include_large, args.oversize_bytes):
        name = utf7(folder)
        if folder != 'INBOX' and folder not in made:
            typ, _ = conn.create('"' + name + '"')
            assert typ == 'OK', f'create {folder!r}'
            made.add(folder)
        flag_text = '(' + ' '.join(flags) + ')' if flags else None
        typ, _ = conn.append('"' + name + '"' if folder != 'INBOX' else 'INBOX', flag_text, when, data)
        assert typ == 'OK', f'append {description!r}'
        manifest.append({'folder': folder, 'description': description, 'size': len(data),
                         'sha256': hashlib.sha256(data).hexdigest(), 'flags': flags, 'internaldate': when.isoformat()})
    conn.logout()
    out = Path(args.dir) / 'corpus-manifest.json'
    out.write_text(json.dumps(manifest, indent=1)); os.chmod(out, 0o600)
    print(f'seeded {len(manifest)} synthetic message(s); manifest: {out}')
    return 0


def cmd_config(args):
    host, provider_role = DIRECTIONS[args.direction]
    lab = load_lab(args.dir)
    dove_role = 'destination' if provider_role == 'source' else 'source'
    if dove_role not in lab['ports']:
        raise SystemExit(f'{args.direction} needs a {dove_role} Dovecot: run `up --roles {dove_role}`')
    out = Path(args.out)
    if out.exists():
        raise SystemExit(f'{out}: refusing to overwrite')
    maps = [m.split('=', 1) for m in (args.map or ['INBOX=INBOX'])]
    if any(len(m) != 2 for m in maps):
        raise SystemExit('--map expects SRC=DST')
    quote = json.dumps
    provider = (f'host = {quote(host)}\nport = 993\nusername = {quote(args.provider_user)}\n'
                f'auth = "xoauth2"\naccess_token_file = {quote(str(Path(args.token_file).resolve()))}\n')
    dovecot = (f'host = "localhost"\nport = {lab["ports"][dove_role]}\nusername = {quote(lab["user"])}\n'
               f'password_file = {quote(str((Path(args.dir) / "password").resolve()))}\n'
               f'ca_file = {quote(str((Path(args.dir) / "tls.crt").resolve()))}\n')
    source, destination = (provider, dovecot) if provider_role == 'source' else (dovecot, provider)
    text = (f'# {args.direction}: generated by provider_lab.py. Contains paths only, no secrets.\n'
            f'state_dir = {quote(str(Path(args.state_dir).resolve()))}\ntimeout_seconds = 60\n'
            f'max_message_bytes = {args.max_message_bytes}\nread_attempts = 6\nappend_rejection_limit = 3\n\n'
            f'[source]\n{source}\n[destination]\n{destination}\n'
            + ''.join(f'[[folders]]\nsource = {quote(s)}\ndestination = {quote(d)}\n\n' for s, d in maps))
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    print(f'wrote {out} (mode 0600)')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('up'); p.add_argument('--dir', required=True); p.add_argument('--roles', default='destination')
    p = sub.add_parser('down'); p.add_argument('--dir', required=True)
    p = sub.add_parser('status'); p.add_argument('--dir', required=True)
    p = sub.add_parser('seed'); p.add_argument('--dir', required=True)
    p.add_argument('--include-large', action='store_true'); p.add_argument('--oversize-bytes', type=int, default=0)
    p = sub.add_parser('config'); p.add_argument('--dir', required=True)
    p.add_argument('--direction', choices=sorted(DIRECTIONS), required=True)
    p.add_argument('--provider-user', required=True); p.add_argument('--token-file', required=True)
    p.add_argument('--state-dir', required=True); p.add_argument('--out', required=True)
    p.add_argument('--map', action='append', metavar='SRC=DST'); p.add_argument('--max-message-bytes', type=int, default=52428800)
    args = ap.parse_args(argv)
    return {'up': cmd_up, 'down': cmd_down, 'status': cmd_status, 'seed': cmd_seed, 'config': cmd_config}[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())
