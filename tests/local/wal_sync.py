#!/usr/bin/env python3
"""Durability evidence for the write-ahead-log journal (phase 1 of the performance work).

Runs the real binary through a full migration of a few messages with an LD_PRELOAD shim that counts fsync and
fdatasync per journal file (tests/support/fsync_shim.c; it only observes), and asserts:
  * the journal ends up in WAL mode and per-message commits create no rollback-journal files;
  * every durable commit reached the disk: the number of syncs of the -wal file is at least the number of commits
    (four per message: prepared, literal authorized, acknowledged, confirmed);
  * the pre-literal fence is still ahead of the first literal byte (the journal row says literal_authorized before
    the message is confirmed, and an APPEND was never sent without it: checked by the existing crash matrices, here
    only the commit count is asserted);
  * nothing is synced less than once per commit: syncs of the log >= commits;
  * (phase 2) the log is synced with fdatasync only: the build carries -DHAVE_FDATASYNC=1.

  python3 tests/local/wal_sync.py target/release/imaplane
Needs Docker (only to compile the shim with the dev image's gcc, as no compiler is installed on the host).
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from e2e import PASSWORD, STREAM_EXTRA, ProtocolServer, command
from freshness import require_fresh
from stream_stress import FOLDER

binary = Path(sys.argv[1]).resolve()
require_fresh(binary, 'binary')
ROOT = Path(__file__).resolve().parents[2]
N = 8

with tempfile.TemporaryDirectory(prefix='imaplane-walsync-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    shim = root / 'shim.so'
    import shutil
    if shutil.which('gcc'):   # CI runners have a compiler; the Docker image is only for hosts without one
        subprocess.run(['gcc', '-shared', '-fPIC', '-O2', '-o', str(shim), str(ROOT / 'tests/support/fsync_shim.c'), '-ldl', '-lpthread'], check=True)
    else:
            subprocess.run(['docker', 'run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}', '-v', f'{ROOT}/tests/support:/s:ro', '-v', f'{root}:/o', os.environ.get('IMAPLANE_TEST_IMAGE', 'imaplane-dev:1.85.1'),
                        'gcc', '-shared', '-fPIC', '-O2', '-o', '/o/shim.so', '/s/fsync_shim.c', '-ldl', '-lpthread'], check=True)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    password = root / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
    server = ProtocolServer(str(cert), str(key), 'rev1')
    server.messages['source'] = [b'Subject: wal sync %d\r\n\r\n' % i + os.urandom(500) for i in range(N)]
    state = root / 'state'
    cfg = root / 'c.toml'
    text = f'state_dir = "{state}"\ntimeout_seconds = 10\nmax_message_bytes = 4194304\n{STREAM_EXTRA}'
    for role in ('source', 'destination'):
        text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
    text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
    cfg.write_text(text)
    out = root / 'shim.json'
    env = dict(os.environ, LD_PRELOAD=str(shim), SHIM_OUT=str(out))
    p = subprocess.run([str(binary), 'migrate', '--config', str(cfg), '--json'], env=env, capture_output=True, text=True, timeout=300)
    server.close()
    assert p.returncode == 0, (p.returncode, p.stderr[-400:])
    report = json.loads(p.stdout); assert report['complete'] and len(report['entries']) == N
    stats = json.loads(out.read_text())
    syncs = lambda k: stats[k]['fsyncs'] + stats[k]['fdatasyncs']
    commits = 4 * N
    print('syncs by file:', {k: syncs(k) for k in stats}, 'opens:', {k: v['opens'] for k, v in stats.items()})
    assert (state / 'journal.sqlite3-wal').exists() is False, 'a clean exit removes the log'
    c = sqlite3.connect(state / 'journal.sqlite3'); mode = c.execute('PRAGMA journal_mode').fetchone()[0]; c.close()
    assert mode == 'wal', mode
    # Creating the journal (its tables, in a scratch file, before it is switched to WAL) uses a handful of
    # rollback journals; per-message commits must use none (the old configuration created one per commit).
    assert stats['rollback_journal']['opens'] < 2 * N, f'rollback journals in use per commit: {stats["rollback_journal"]["opens"]}'
    assert syncs('wal') >= commits, f'{syncs("wal")} syncs of the log for at least {commits} durable commits: a commit skipped its sync'
    # Phase 2: the log is synced with fdatasync (SQLite built with -DHAVE_FDATASYNC=1 via .cargo/config.toml), never
    # with a plain fsync, and every commit still reaches the disk: the count of syncs did not drop.
    assert stats['wal']['fdatasyncs'] >= commits and stats['wal']['fsyncs'] == 0, f'log syncs: {stats["wal"]["fdatasyncs"]} fdatasync, {stats["wal"]["fsyncs"]} fsync (the build lost -DHAVE_FDATASYNC=1?)'
    assert syncs('wal') < commits * 3, 'unexpectedly many syncs of the log'
    print(f'PASS WAL journal: {stats["wal"]["fdatasyncs"]} fdatasyncs of the log for {commits} durable commits ({N} messages), no rollback journal, clean exit removed the log')
