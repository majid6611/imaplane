"""Shared helpers: Docker/Dovecot lifecycle, seeding, the independent verifier, and the Dovecot log parser.

Nothing here knows how either tool works. The verifier talks to the two Dovecot servers directly over
IMAP (BODY.PEEK[] so it never changes flags) and compares multisets, so a duplicated message cannot
be mistaken for a copied one and a dropped one cannot hide behind a duplicate.
"""
import collections
import datetime as dt
import hashlib
import imaplib
import json
import os
import re
import shutil
import ssl
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOVECOT_IMAGE = 'dovecot/dovecot:2.3.21'
RUNNER_IMAGE = 'imaplane-bench-runner:1'
NETWORK = 'bench-net'
PASSWORD = 'imaplane-test-only'
SRC_USER, DST_USER = 'bsrc', 'bdst'
UID = os.getuid()


def sh(*args, check=True, capture=True, timeout=None, input=None):
    p = subprocess.run(args, capture_output=capture, text=True, timeout=timeout, input=input)
    if check and p.returncode:
        raise RuntimeError(f'{args[:3]}... failed ({p.returncode}): {(p.stderr or "")[-400:]}')
    return p


def create_network(name):
    sh('docker', 'network', 'rm', name, check=False)
    sh('docker', 'network', 'create', name)


def remove_network(name):
    sh('docker', 'network', 'rm', name, check=False)


def tree_hash(root):
    """SHA-256 over every file under `root` (relative path, size, content), in sorted order. Used to prove a
    dataset directory is byte-identical before and after a run."""
    h = hashlib.sha256()
    root = Path(root)
    for p in sorted(root.rglob('*')):
        rel = str(p.relative_to(root)).encode()
        if p.is_symlink():
            h.update(b'L' + rel + os.readlink(p).encode())
        elif p.is_file():
            h.update(b'F' + rel + str(p.stat().st_size).encode())
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
        else:
            h.update(b'D' + rel)
    return h.hexdigest()


def ensure_cert(work):
    cert, key = Path(work) / 'tls.crt', Path(work) / 'tls.key'
    if not cert.exists():
        sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '30', '-subj', '/CN=bench',
           '-addext', 'subjectAltName=DNS:bench-src,DNS:bench-dst,DNS:localhost')
        os.chmod(key, 0o600)
    (Path(work) / 'password').write_text(PASSWORD); os.chmod(Path(work) / 'password', 0o600)
    return cert, key


class Dovecot:
    """One disposable Dovecot container with a bind-mounted mail directory."""

    def __init__(self, name, mail_dir, cert, key, user, network, alias, cpus='2', memory='2g'):
        self.name, self.mail_dir, self.user, self.network, self.alias = name, Path(mail_dir), user, network, alias
        self.cert, self.key, self.cpus, self.memory = cert, key, cpus, memory
        self.port = None

    def start(self):
        self.mail_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.mail_dir, 0o777)
        sh('docker', 'rm', '-f', self.name, check=False)
        sh('docker', 'run', '-d', '--name', self.name, '--hostname', self.alias, '--network', self.network, '--network-alias', self.alias, '--cpus', self.cpus, '--memory', self.memory,
           '-p', '127.0.0.1::993', '-v', f'{HERE}/dovecot-bench.conf:/etc/dovecot/dovecot.conf:ro', '-v', f'{self.cert}:/etc/dovecot/tls.crt:ro',
           '-v', f'{self.key}:/etc/dovecot/tls.key:ro', '-v', f'{self.mail_dir}:/srv/mail', DOVECOT_IMAGE)
        self.port = int(sh('docker', 'port', self.name, '993/tcp').stdout.strip().rsplit(':', 1)[1])
        for _ in range(200):
            try:
                c = self.connect(); c.logout(); return self
            except (OSError, imaplib.IMAP4.error):
                time.sleep(0.1)
        raise RuntimeError(f'{self.name} did not become ready')

    def connect(self, user=None):
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        c = imaplib.IMAP4_SSL('127.0.0.1', self.port, ssl_context=ctx)
        c.login(user or self.user, PASSWORD)
        return c

    def stop(self):
        sh('docker', 'rm', '-f', self.name, check=False)

    def events(self, since, until):
        """Per-command and per-session accounting from Dovecot's own log between two epoch times."""
        iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        text = sh('docker', 'logs', '--since', iso(since), '--until', iso(until), self.name, check=False).stdout
        text += ''
        return parse_dovecot_log(text)


def quoted(name):
    return '"' + name.replace('\\', '\\\\').replace('"', '\\"') + '"'


def utf7(name):
    """Modified UTF-7 (RFC 3501) for mailbox names as an IMAP4rev1 server lists them."""
    import base64
    out, buf = '', ''
    def flush():
        nonlocal out, buf
        if buf:
            enc = base64.b64encode(buf.encode('utf-16-be')).decode().rstrip('=').replace('/', ',')
            out += '&' + enc + '-'; buf = ''
    for ch in name:
        if 0x20 <= ord(ch) <= 0x7e:
            flush(); out += '&-' if ch == '&' else ch
        else:
            buf += ch
    flush()
    return out


def imap_date(d):
    return d.strftime('%d-%b-%Y %H:%M:%S %z')


def seed(dovecot, records, folders, batch_log=None):
    """APPEND every record to the (empty) source mailbox, creating folders first."""
    c = dovecot.connect()
    for f in folders:
        if f != 'INBOX':
            assert c.create(quoted(utf7(f)))[0] == 'OK', f
    for i, r in enumerate(records):
        flags = '(' + ' '.join(r['flags']) + ')' if r['flags'] else None
        typ, data = c.append(quoted(utf7(r['folder'])), flags, '"' + imap_date(r['date']) + '"', r['body'])
        if typ != 'OK':
            raise RuntimeError(f'append {i} failed: {data}')
        if batch_log and i % 1000 == 999:
            batch_log(f'  seeded {i + 1}/{len(records)}')
    c.logout()


def append_records(dovecot, records):
    c = dovecot.connect()
    for r in records:
        flags = '(' + ' '.join(r['flags']) + ')' if r['flags'] else None
        typ, data = c.append(quoted(utf7(r['folder'])), flags, '"' + imap_date(r['date']) + '"', r['body'])
        assert typ == 'OK', data
    c.logout()


def list_folders(c):
    typ, data = c.list()
    names = []
    for line in data:
        m = re.match(rb'\((.*?)\) "(.*?)" (.*)$', line)
        if m:
            raw = m.group(3).strip()
            names.append(raw[1:-1].decode() if raw.startswith(b'"') else raw.decode())
    return names


def snapshot(dovecot, folders_utf7):
    """folder (utf7 name) -> list of (sha256, size, flags-tuple, internaldate-epoch). Read-only."""
    c = dovecot.connect(); out = {}
    existing = set(list_folders(c))
    for f in folders_utf7:
        if f not in existing and f != 'INBOX':
            out[f] = None; continue
        typ, data = c.select(quoted(f), readonly=True)
        rows = []
        n = int(data[0])
        if n:
            typ, parts = c.uid('FETCH', '1:*', '(FLAGS INTERNALDATE BODY.PEEK[])')
            for item in parts:
                if isinstance(item, tuple):
                    head, body = item
                    flags = tuple(sorted(x.decode() for x in imaplib.ParseFlags(head) if x != b'\\Recent'))
                    date = imaplib.Internaldate2tuple(head)
                    # Internaldate2tuple returns LOCAL time; mktime turns it back into the instant
                    rows.append((hashlib.sha256(body).hexdigest(), len(body), flags, int(time.mktime(date))))
        out[f] = rows
        c.close()
    c.logout()
    return out


def verify(src_snap, dst_snap, strict_deleted=False):
    """Compare per-folder multisets. Classes of difference are reported separately:

    exact          copies whose (content, flags, date) match
    missing        in the source, absent in the destination
    duplicates     extra identical copies in the destination (more copies than the source has)
    flag_diff      same content+date, different flags (split: only \\Deleted differs / anything else)
    date_diff      same content+flags, different date
    foreign        destination messages whose content is not in the source folder at all
    """
    total = collections.Counter()
    detail = {}
    for folder, srows in src_snap.items():
        drows = dst_snap.get(folder)
        r = dict(src=len(srows), dst=None if drows is None else len(drows), exact=0, missing=0, duplicates=0, flag_diff_only_deleted=0,
                 flag_diff_other=0, date_diff=0, foreign=0, folder_missing=drows is None)
        if drows is None:
            r['missing'] = len(srows); detail[folder] = r; total.update({k: v for k, v in r.items() if isinstance(v, int) and not isinstance(v, bool)}); continue
        s = collections.Counter((a, c, d) for a, b, c, d in srows)
        d = collections.Counter((a, c, d_) for a, b, c, d_ in drows)
        common = s & d
        r['exact'] = sum(common.values())
        s_left, d_left = s - common, d - common
        # pair leftovers by content hash
        by_hash_s = collections.defaultdict(list); by_hash_d = collections.defaultdict(list)
        for (h, fl, dt_), n in s_left.items():
            by_hash_s[h] += [(fl, dt_)] * n
        for (h, fl, dt_), n in d_left.items():
            by_hash_d[h] += [(fl, dt_)] * n
        for h in set(by_hash_s) | set(by_hash_d):
            a, b = list(by_hash_s.get(h, [])), list(by_hash_d.get(h, []))
            # first pair identical-date different-flags, then identical-flags different-date, then leftover
            for same in ('date', 'flags'):
                for x in list(a):
                    match = next((y for y in b if (y[1] == x[1] if same == 'date' else y[0] == x[0])), None)
                    if match is not None:
                        a.remove(x); b.remove(match)
                        if same == 'date':
                            only_deleted = set(x[0]) ^ set(match[0]) <= {'\\Deleted'}
                            r['flag_diff_only_deleted' if only_deleted else 'flag_diff_other'] += 1
                        else:
                            r['date_diff'] += 1
            r['missing'] += len(a)
            if h in {k[0] for k in s}:
                r['duplicates'] += len(b)
            else:
                r['foreign'] += len(b)
        detail[folder] = r
        total.update({k: v for k, v in r.items() if isinstance(v, int) and not isinstance(v, bool)})
    ok = (total['missing'] == 0 and total['duplicates'] == 0 and total['foreign'] == 0 and total['date_diff'] == 0 and total['flag_diff_other'] == 0)
    return {'ok': ok, 'total': dict(total), 'folders': detail}


def parse_dovecot_log(text):
    """Count finished IMAP commands (from the exported JSON events) and session bytes (Disconnected lines)."""
    commands, verbs, failed = 0, collections.Counter(), 0
    us_by_verb = collections.Counter()
    server_us = bytes_in_cmds = bytes_out_cmds = 0
    sessions, in_total, out_total = 0, 0, 0
    for line in text.splitlines():
        i = line.find('{"event":"imap_command_finished"')
        if i >= 0:
            try:
                f = json.loads(line[i:])['fields']
            except ValueError:
                continue
            commands += 1; verbs[f.get('cmd_name', '?')] += 1; us_by_verb[f.get('cmd_name', '?')] += f.get('running_usecs', 0)
            if f.get('tagged_reply_state') not in ('OK', None):
                failed += 1
            server_us += f.get('running_usecs', 0); bytes_in_cmds += f.get('bytes_in', 0); bytes_out_cmds += f.get('bytes_out', 0)
            continue
        m = re.search(r'Disconnected: .*? in=(\d+) out=(\d+)', line)
        if m and ' imap(' in line:
            sessions += 1; in_total += int(m.group(1)); out_total += int(m.group(2))
    return {'commands': commands, 'by_verb': dict(verbs), 'server_s_by_verb': {k: round(v / 1e6, 4) for k, v in us_by_verb.items()}, 'failed_commands': failed, 'server_command_s': server_us / 1e6, 'sessions': sessions,
            'app_bytes_client_to_server': in_total, 'app_bytes_server_to_client': out_total}
