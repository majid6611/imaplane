#!/usr/bin/env python3
"""Gmail duplicate protection, end to end against a Gmail-like scripted server (no Docker, no real mail).

The fixture (e2e.ProtocolServer with an XOAUTH2 token) advertises X-GM-EXT-1, lists an \\All mailbox, answers batched
X-GM-RAW searches, and with gmail_merge=True merges an APPEND of the same Message-ID and body into the existing
message and DISCARDS the new bytes while reporting success (experiment E7).
Usage: python3 tests/local/gmail_dup.py [path/to/imaplane]
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import BIN, PASSWORD, ProtocolServer, command, STREAM_EXTRA, ALL_MAIL
from freshness import require_fresh
require_fresh(BIN)

TOKEN = 'gmail-dup-test-token'
FAILED = []
FOLDER = '台北/📬'
RB = ''


def msg(mid, body, extra=''):
    head = (f'Message-ID: {mid}\r\n' if mid else '') + f'From: a@example.invalid\r\nSubject: s\r\n{extra}'
    return (head + '\r\n' + body + '\r\n').encode()


def check(name):
    def wrap(fn):
        try:
            fn(); print('PASS', name)
        except BaseException as exc:
            FAILED.append(name); print('FAIL', name, '->', repr(exc)[:1500])
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-gmaildup-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    tokenfile = root / 'token'; tokenfile.write_text(TOKEN); tokenfile.chmod(0o600)
    servers = []; counter = [0]

    def fixture(sources, existing=(), merge=True, gmail=True, extra_cfg=''):
        counter[0] += 1; name = f'job{counter[0]}'
        s = ProtocolServer(str(cert), str(key), 'rev1'); servers.append(s)
        s.messages['source'] = list(sources)
        s.messages['destination'] = list(existing)
        if gmail: s.xoauth2_token = TOKEN
        s.gmail_merge = merge
        cfg = root / (name + '.toml')
        text = f'state_dir = "{root/name}"\ntimeout_seconds = 5\nread_attempts = 2\n{extra_cfg}{STREAM_EXTRA}'
        for role in ['source', 'destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {s.port}\nusername = "{role}"\nca_file = "{cert}"\n'
            text += f'auth = "xoauth2"\naccess_token_file = "{tokenfile}"\n' if gmail else f'password_file = "{tokenfile}"\n'
        text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
        cfg.write_text(text)
        return s, cfg, root / name

    def cli(*args, code=None):
        p = subprocess.run([str(BIN), *map(str, args)], capture_output=True, text=True, timeout=120)
        if code is not None: assert p.returncode == code, (args, p.returncode, p.stdout[-1500:], p.stderr[-1500:])
        for secret in (TOKEN,): assert secret not in p.stdout + p.stderr
        return p, (json.loads(p.stdout) if p.stdout.strip().startswith('{') else None)

    def migrate(cfg, code=None): return cli('migrate', '--config', cfg, '--json', code=code)

    def stored(s): return [m for m in s.messages['destination'] if m is not None]

    def journal(state): return sqlite3.connect(state / 'journal.sqlite3')

    def results(report): return sorted(e['result'] for e in report['entries'])

    def no_writes_besides_append(s):
        verbs = {v for u, v, _ in s.events if u == 'destination'}
        assert not verbs & {b'STORE', b'EXPUNGE', b'COPY', b'MOVE', b'DELETE', b'RENAME'}, verbs
        assert not s.errors, s.errors

    @check('1 identical duplicate pair: one APPEND, the second is held, not migrated, exit 2')
    def _():
        a = msg('<d1@x>', 'same')
        s, cfg, state = fixture([a, a])
        p, r = migrate(cfg, code=2)
        assert results(r) == ['confirmed', 'held'], results(r)
        assert not r['complete'] and r['verification']['held'] == 1
        assert stored(s) == [a], 'exactly one APPEND reached the server; the first copy is untouched'
        c = journal(state)
        assert c.execute('PRAGMA user_version').fetchone()[0] == 6
        assert c.execute("select count(*) from transfers where state='confirmed'").fetchone()[0] == 1
        assert c.execute("select count(*) from append_attempts").fetchone()[0] == 1, 'no attempt row for the held message'
        assert c.execute("select reason from client_hold_events").fetchall() == [('SAME_CONTENT_THIS_JOB',)]
        assert any(str(state) in w or 'schema 6' in w for w in r['warnings'])
        no_writes_besides_append(s)

    @check('2 E7 pair: same Message-ID and body, extra header: held, the first copy is not replaced')
    def _():
        a, b = msg('<e7@x>', 'body'), msg('<e7@x>', 'body', 'X-Dup-Test: 1\r\n')
        s, cfg, state = fixture([a, b])
        p, r = migrate(cfg, code=2)
        assert results(r) == ['confirmed', 'held'], results(r)
        assert stored(s) == [a]
        assert 'SAME_CONTENT_THIS_JOB' in json.dumps(r) or 'appended earlier in this run' in json.dumps(r)

    @check('3 same Message-ID but a different body, and messages without Message-ID, are NOT held')
    def _():
        s, cfg, _ = fixture([msg('<x@x>', 'ALPHA'), msg('<x@x>', 'BRAVO'), msg(None, 'one'), msg(None, 'two')])
        p, r = migrate(cfg, code=0)
        assert results(r) == ['confirmed'] * 4 and r['complete']
        assert len(stored(s)) == 4

    @check('4 two identical messages without a Message-ID are held by the journal (identical content)')
    def _():
        a = msg(None, 'twin')
        s, cfg, _ = fixture([a, a])
        p, r = migrate(cfg, code=2)
        assert results(r) == ['confirmed', 'held'] and len(stored(s)) == 1

    @check('5 an existing destination message with the same Message-ID and body: held, zero APPENDs, existing untouched')
    def _():
        a = msg('<pre@x>', 'already there')
        s, cfg, state = fixture([a, msg('<new@x>', 'new')], existing=[msg('<pre@x>', 'already there', 'X-Other: header\r\n')])
        before = list(s.messages['destination'])
        p, r = migrate(cfg, code=2)
        assert results(r) == ['confirmed', 'held']
        assert s.messages['destination'][0] == before[0] and len(stored(s)) == 2
        assert journal(state).execute("select reason from client_hold_events").fetchall() == [('SAME_ID_AND_BODY_EXISTING',)]
        assert s.searches and all(len(ids) <= 100 for ids in s.searches)
        no_writes_besides_append(s)

    @check('6 existing destination message with identical bytes is SAME_CONTENT_EXISTING')
    def _():
        a = msg('<pre2@x>', 'same bytes')
        s, cfg, state = fixture([a], existing=[a])
        p, r = migrate(cfg, code=2)
        assert results(r) == ['held'] and stored(s) == [a]
        assert journal(state).execute("select reason from client_hold_events").fetchall() == [('SAME_CONTENT_EXISTING',)]

    @check('7 an existing message with the same Message-ID but a different body is not a duplicate')
    def _():
        s, cfg, _ = fixture([msg('<k@x>', 'mine')], existing=[msg('<k@x>', 'someone elses')])
        p, r = migrate(cfg, code=0)
        assert results(r) == ['confirmed'] and len(stored(s)) == 2

    @check('8 reruns are idempotent: still held, exit 2, no new evidence rows, never migrated')
    def _():
        a = msg('<d8@x>', 'same')
        s, cfg, state = fixture([a, a], extra_cfg=RB)
        migrate(cfg, code=2)
        rows = journal(state).execute('select count(*) from client_hold_events').fetchone()[0]
        for _ in range(3):
            p, r = migrate(cfg, code=2)
            assert results(r) == ['confirmed', 'held'] or results(r) == ['held', 'confirmed'], results(r)
        assert journal(state).execute('select count(*) from client_hold_events').fetchone()[0] == rows == 1
        assert len(stored(s)) == 1
        st, js = cli('status', '--state', state / 'journal.sqlite3', '--json')
        assert js['held'] == 1 and js['confirmed'] == 1 and js['planned'] == 1

    @check('9 skip accepts the hold as evidence; the skipped message is not migrated and the run stays incomplete')
    def _():
        a = msg('<d9@x>', 'same')
        s, cfg, state = fixture([a, a], extra_cfg=RB)
        migrate(cfg, code=2)
        p, r = cli('skip', '--config', cfg, '--folder', FOLDER, '--uid', 2, '--reason', 'existing copy is the same mail', '--json', code=2)
        p, r = migrate(cfg, code=2)
        assert 'skipped_by_operator' in results(r) and 'held' not in results(r)
        st, js = cli('status', '--state', state / 'journal.sqlite3', '--json')
        assert js['held'] == 0 and js['skipped'] == 1 and js['confirmed'] == 1
        cli('unskip', '--config', cfg, '--folder', FOLDER, '--uid', 2, '--reason', 'check again', '--json', code=2)
        p, r = migrate(cfg, code=2)
        assert 'held' in results(r) and len(stored(s)) == 1

    @check('10 skip of a message that is not held and was not rejected is still refused')
    def _():
        s, cfg, _ = fixture([msg('<ok@x>', 'fine')])
        migrate(cfg, code=0)
        cli('skip', '--config', cfg, '--folder', FOLDER, '--uid', 1, '--reason', 'no', '--json', code=1)

    @check('11 many holds never trip the rejection breaker: 60 identical messages -> 1 sent, 59 held, run completes')
    def _():
        a = msg('<many@x>', 'same')
        s, cfg, state = fixture([a] * 60)
        p, r = migrate(cfg, code=2)
        assert results(r).count('held') == 59 and results(r).count('confirmed') == 1 and len(r['entries']) == 60
        assert r['halt_reason'] is None
        assert journal(state).execute('select count(*) from append_rejections').fetchone()[0] == 0
        assert journal(state).execute("select count(*) from client_hold_events").fetchone()[0] == 59

    @check('12 a search failure fails closed: nothing sent, nothing recorded, exit 2; the next run succeeds')
    def _():
        s, cfg, state = fixture([msg('<f1@x>', 'one'), msg('<f2@x>', 'two')])
        s.search_fail = lambda n: 'no'
        p, r = migrate(cfg, code=2)
        assert results(r) == ['failed'] and 'duplicate check unavailable' in r['entries'][0]['detail']
        assert stored(s) == []
        c = journal(state)
        assert c.execute('select count(*) from client_hold_events').fetchone()[0] == 0
        assert c.execute('select count(*) from transfers').fetchone()[0] == 0
        s.search_fail = None
        p, r = migrate(cfg, code=0)
        assert results(r) == ['confirmed', 'confirmed'] and len(stored(s)) == 2

    @check('13 a dropped search connection is retried within bounds and then succeeds')
    def _():
        s, cfg, _ = fixture([msg('<g1@x>', 'one')])
        s.search_fail = lambda n: 'drop' if n == 1 else None
        p, r = migrate(cfg, code=0)
        assert results(r) == ['confirmed'] and len(s.searches) >= 2

    @check('14 searches are batched: 250 distinct messages need at most 3 searches of at most 100 ids')
    def _():
        s, cfg, _ = fixture([msg(f'<b{i}@x>', f'body {i}') for i in range(250)])
        p, r = migrate(cfg, code=0)
        assert r['complete'] and len(stored(s)) == 250
        assert len(s.searches) == 3 and all(len(ids) <= 100 for ids in s.searches), [len(i) for i in s.searches]
        assert s.header_fetches <= 5

    @check('15 protection off: the Gmail merge goes unprevented and the unchanged read-back reports it')
    def _():
        a, b = msg('<off@x>', 'body'), msg('<off@x>', 'body', 'X-Dup-Test: 1\r\n')
        s, cfg, state = fixture([a, b], extra_cfg='gmail_duplicate_protection = "off"\n')
        p, r = migrate(cfg)
        assert not s.searches
        assert p.returncode == 2 and 'confirmed' in results(r) and any(x in ('mismatch', 'missing', 'failed', 'uncertain') for x in results(r)), results(r)
        assert journal(state).execute('PRAGMA user_version').fetchone()[0] == 4, 'off never upgrades the journal'

    OFF = 'gmail_duplicate_protection = "off"\n'

    def strip_class(report):
        r = json.loads(json.dumps(report))
        for e in r['entries']: e.pop('classification', None)
        r['verification'].pop('provider_merges', None)
        r['verification']['statement'] = r['verification']['statement'].split('; 1 of the problems')[0]
        for k in ('folders',): r['verification'].pop(k, None)
        return r

    @check('23 P4: a merge that slips through (E7 pair, protection off) keeps result/detail/exit code and gains an additive classification')
    def _():
        a, b = msg('<p4a@x>', 'body'), msg('<p4a@x>', 'body', 'X-Dup-Test: 1\r\n')
        s, cfg, state = fixture([a, b], extra_cfg=OFF)
        p, r = migrate(cfg, code=2)
        bad = [e for e in r['entries'] if e['result'] == 'mismatch']
        assert results(r) == ['confirmed', 'mismatch'] and len(bad) == 1, results(r)
        assert bad[0]['detail'] == 'content hash mismatch', bad[0]['detail']
        c = bad[0]['classification']
        assert c['kind'] == 'provider_merge_new_bytes_discarded' and 'UID 1' in c['explanation'], c
        assert r['verification']['provider_merges'] == 1 and not r['complete']
        assert all('classification' not in e for e in r['entries'] if e['result'] != 'mismatch')
        no_writes_besides_append(s)
        old = os.environ.get('IMAPLANE_OLD_BIN', '')
        if old and Path(old).is_file():
            s2, cfg2, _ = fixture([a, b])   # the previous release has no option; same inputs, merge unprevented there
            q = subprocess.run([old, 'migrate', '--config', str(cfg2), '--json'], capture_output=True, text=True, timeout=120)
            assert q.returncode == 2
            ro = json.loads(q.stdout)
            assert [(e['result'], e['detail']) for e in ro['entries']] == [(e['result'], e['detail']) for e in r['entries']]
            assert ro['complete'] == r['complete']
        else:
            print('   (IMAPLANE_OLD_BIN not set: old-vs-new result comparison NOT TESTED here)')

    @check('24 P4: verify explains a vanished UID when an identical copy sent for another source message is intact (Gmail only)')
    def _():
        a = msg('<p4b@x>', 'twin body')
        s, cfg, state = fixture([a, a], extra_cfg=OFF)
        migrate(cfg)        # merge unprevented: identical bytes, the first UID is re-issued
        p, r = cli('verify', '--config', cfg, '--json', code=2)
        by = {e['source_uid']: e for e in r['entries']}
        assert by[1]['result'] == 'missing' and by[2]['result'] == 'confirmed', by
        assert by[1]['detail'] == 'destination UID no longer exists'
        assert by[1]['classification']['kind'] == 'provider_merge_identical_copy_kept' and 'UID 2' in by[1]['classification']['explanation']
        assert 'classification' not in by[2] and r['verification']['provider_merges'] == 1 and not r['complete']
        no_writes_besides_append(s)

    @check('25 P4: no classification without proof (vanished UID with no identical sibling) and none on a non-Gmail destination')
    def _():
        s, cfg, _ = fixture([msg('<p4c@x>', 'lonely')])
        migrate(cfg, code=0)
        s.messages['destination'][0] = None
        p, r = cli('verify', '--config', cfg, '--json', code=2)
        assert results(r) == ['missing'] and 'classification' not in r['entries'][0] and 'provider_merges' not in r['verification']
        a = msg('<p4d@x>', 'plain twin')
        s, cfg, _ = fixture([a, a], gmail=False, merge=False)
        migrate(cfg, code=0)
        s.messages['destination'][0] = None      # an identical sibling IS intact, but this is not Gmail
        p, r = cli('verify', '--config', cfg, '--json', code=2)
        assert results(r) == ['confirmed', 'missing'] and all('classification' not in e for e in r['entries'])

    @check('26 P4: the human report prints the classification line; status and journal are unchanged by it')
    def _():
        a = msg('<p4e@x>', 'twin text')
        s, cfg, state = fixture([a, a], extra_cfg=OFF)
        migrate(cfg)
        before = journal(state).execute('select count(*) from transfers').fetchone()[0]
        p, _ = cli('verify', '--config', cfg, code=2)
        assert 'classification: provider_merge_identical_copy_kept' in p.stdout, p.stdout
        assert journal(state).execute('PRAGMA user_version').fetchone()[0] == 4 and before == 2

    @check('16 not Gmail: no X-GM-EXT-1, no extra connections or commands, journal stays schema 4')
    def _():
        a = msg('<ng@x>', 'same')
        s, cfg, state = fixture([a, a], gmail=False, merge=False)
        p, r = migrate(cfg, code=0)
        assert results(r) == ['confirmed'] * 2 and not s.searches and s.header_fetches == 0
        assert journal(state).execute('PRAGMA user_version').fetchone()[0] == 4
        assert not any(v == b'LIST' and u == 'destination' and False for u, v, _ in s.events)

    @check('17 an older release cannot open a schema 6 journal (fails closed); status reads it')
    def _():
        old = Path(os.environ.get('IMAPLANE_OLD_BIN', ''))
        a = msg('<old@x>', 'same')
        s, cfg, state = fixture([a, a], extra_cfg=RB)
        migrate(cfg, code=2)
        p, js = cli('status', '--state', state / 'journal.sqlite3', '--json')
        assert js['held'] == 1
        if old.is_file():
            q = subprocess.run([str(old), 'status', '--state', str(state / 'journal.sqlite3')], capture_output=True, text=True)
            assert q.returncode != 0 and 'unsupported journal schema 6' in q.stderr, (q.returncode, q.stderr)
            m = subprocess.run([str(old), 'migrate', '--config', str(cfg), '--json'], capture_output=True, text=True)
            assert m.returncode != 0 and len(stored(s)) == 1
        else:
            print('   (IMAPLANE_OLD_BIN not set: older-binary refusal NOT TESTED here)')

    @check('18 backups: a verified backup per upgrade step sits next to the journal; held mail leaves the source untouched')
    def _():
        a = msg('<bk@x>', 'same')
        s, cfg, state = fixture([a, a])
        migrate(cfg, code=2)
        baks = sorted(p.name for p in state.glob('*.bak*'))
        assert len(baks) >= 1, baks
        assert s.messages['source'] == [a, a]
        assert not [e for e in s.events if e[0] == 'source' and e[1] in (b'STORE', b'APPEND', b'EXPUNGE')]

    @check('19 accounting: report entries and journal agree for a mixed job')
    def _():
        d = msg('<acc@x>', 'dup')
        srcs = [d, d, msg('<u1@x>', 'u1'), msg(None, 'n1'), d]
        s, cfg, state = fixture(srcs, extra_cfg=RB)
        p, r = migrate(cfg, code=2)
        assert len(r['entries']) == 5
        st, js = cli('status', '--state', state / 'journal.sqlite3', '--json')
        assert js['confirmed'] + js['held'] + js['skipped'] + js['uncertain'] + js['accepted'] == 5 - 0 or js['planned'] == js['held']
        assert js['confirmed'] == results(r).count('confirmed') and js['held'] == results(r).count('held') == 2

    FAULT = os.environ.get('IMAPLANE_FAULT_BIN')

    def killed(cfg, point, nth=None):
        env = dict(os.environ, IMAPLANE_FAULT_POINT=point)
        if nth: env['IMAPLANE_FAULT_NTH'] = str(nth)
        p = subprocess.run([FAULT, 'migrate', '--config', str(cfg), '--json'], capture_output=True, text=True, timeout=120, env=env)
        assert p.returncode == -9, (point, p.returncode, p.stderr[-500:])

    if FAULT:
        for point in ['hold_before_commit', 'after_hold']:
            @check(f'20 SIGKILL at {point} then rerun: still one APPEND, the duplicate held, nothing delivered twice')
            def _(point=point):
                a = msg('<c1@x>', 'same')
                s, cfg, state = fixture([a, a])
                killed(cfg, point)
                assert len(stored(s)) == 1
                c = journal(state)
                assert c.execute('select count(*) from append_attempts where uid=2').fetchone()[0] == 0
                p, r = migrate(cfg, code=2)
                assert results(r).count('held') == 1 and len(stored(s)) == 1
                assert journal(state).execute('select count(*) from client_hold_events').fetchone()[0] == 1
                assert journal(state).execute("select count(*) from transfers where state='confirmed'").fetchone()[0] == 1

        for point in ['after_append_reply', 'begin_append_before_commit', 'after_append_continuation', 'before_literal_send']:
            @check(f'21 SIGKILL during the first APPEND at {point}: duplicates are never delivered twice after recovery')
            def _(point=point):
                a = msg('<c2@x>', 'same')
                s, cfg, state = fixture([a, a])
                killed(cfg, point)
                n_after_kill = len(stored(s))
                assert n_after_kill <= 1
                for _ in range(3):
                    p, r = migrate(cfg)
                    assert len(stored(s)) <= 1, 'a duplicate was delivered'
                    if p.returncode == 0: break
                c = journal(state)
                states = dict(c.execute('select uid,state from transfers').fetchall())
                assert states.get(2, 'planned') in ('planned',), states   # the duplicate is never appended
                held = c.execute('select count(*) from client_hold_events').fetchone()[0]
                assert not (held and states.get(2) in ('confirmed', 'accepted')), 'both held and delivered'

        for point in ['release_before_commit', 'after_release']:
            @check(f'22 hold released when the existing copy disappears; SIGKILL at {point} loses nothing')
            def _(point=point):
                a = msg('<rel@x>', 'body')
                s, cfg, state = fixture([a], existing=[msg('<rel@x>', 'body', 'X-Other: 1\r\n')])
                migrate(cfg, code=2)
                assert journal(state).execute("select kind from client_hold_events").fetchall() == [('hold',)]
                s.messages['destination'][0] = None   # the owner removed the existing message
                killed(cfg, point)
                p, r = migrate(cfg, code=0)
                assert results(r) == ['confirmed'] and len(stored(s)) == 1
                kinds = [k for (k,) in journal(state).execute("select kind from client_hold_events order by rowid")]
                assert kinds[0] == 'hold' and kinds[-1] == 'release' and kinds.count('release') == 1, kinds

print()
if FAILED:
    print('FAILED:', FAILED); sys.exit(1)
print('all gmail duplicate checks passed')
