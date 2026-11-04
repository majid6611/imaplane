"""The stress harness's invariant checks must be able to FAIL (offline, no server or binary).

A clean stress run only means something if each invariant demonstrably fires on a violating state,
so every one of I1..I8 is exercised here with a synthetic corrupted fixture.
"""
import sqlite3
import tempfile
import types
import unittest
from pathlib import Path

import stream_stress as st

BODIES = [b'one', b'two', b'three']


def fixture(dest=(), events=(), source=None, rows=(), journal=True, files=()):
    tmp = tempfile.TemporaryDirectory()
    state = Path(tmp.name)
    db = state / 'journal.sqlite3'
    if journal:
        c = sqlite3.connect(db)
        c.execute('create table transfers (uid integer, state text, destination_uid integer)')
        c.executemany('insert into transfers values (?,?,?)', rows)
        c.commit(); c.close()
    for name in files:
        (state / name).write_text('x')
    server = types.SimpleNamespace(messages={'source': list(BODIES) if source is None else source, 'destination': list(dest)},
                                   events=[('destination', b'APPEND', [])] * len([1 for _ in dest]) + list(events))
    return tmp, server, db, state


def verdict(**kw):
    recovers = kw.pop('recovers', 0)
    tmp, server, db, state = fixture(**kw)
    try:
        st.check_invariants(server, BODIES, db, state, recovers)
        return None
    except st.Violation as v:
        return str(v)
    finally:
        tmp.cleanup()


class Invariants(unittest.TestCase):
    def test_a_healthy_state_passes(self):
        self.assertIsNone(verdict(dest=[b'one', b'two'], rows=[(1, 'confirmed', 1), (2, 'confirmed', 2), (3, 'planned', None)]))
        self.assertIsNone(verdict())

    def test_each_invariant_fires_on_its_violation(self):
        cases = {
            'I1': dict(journal=True, rows=[], dest=[]),            # replaced below by a corrupted file
            'I2': dict(dest=[b'one', b'one']),
            'I3': dict(dest=[b'alien']),
            'I4 source content': dict(source=[b'one', b'CHANGED', b'three']),
            'I4 verbs': dict(events=[('source', b'STORE', [])]),
            'I5': dict(dest=[b'two'], rows=[(1, 'confirmed', 1)]),
            'I5 missing': dict(dest=[], rows=[(1, 'confirmed', 1)]),
            'I6 accepted without uid': dict(rows=[(1, 'accepted', None)]),
            'I6 uid without state': dict(rows=[(1, 'planned', 5)]),
            'I7': dict(dest=[b'one'], events=[('destination', b'APPEND', [])] * 3),
            'I8': dict(files=['spool-abc', 'journal.sqlite3-journal']),
        }
        for name, kw in cases.items():
            if name == 'I1':
                continue
            self.assertIn(name.split()[0], verdict(**kw) or 'NO VIOLATION', name)

    def test_a_corrupted_journal_is_a_violation(self):
        tmp, server, db, state = fixture()
        try:
            db.write_bytes(b'this is not a database' * 100)
            with self.assertRaises(st.Violation) as raised:
                st.check_invariants(server, BODIES, db, state, 0)
            self.assertIn('I1', str(raised.exception))
        finally:
            tmp.cleanup()

    def test_audited_recovers_and_journal_sidecars_are_allowed(self):
        extra = [('destination', b'APPEND', [])] * 3                 # plus the one APPEND the fixture adds for its single copy
        self.assertIsNone(verdict(dest=[b'one'], events=extra, recovers=1, rows=[(1, 'planned', None)]))   # 4 APPENDs = 3 messages + 1 audited reset
        self.assertIn('I7', verdict(dest=[b'one'], events=extra, recovers=0))
        self.assertIsNone(verdict(files=['journal.sqlite3-journal', 'journal.sqlite3-wal', 'job.lock']))

    def test_a_dead_counter_cannot_make_the_append_check_pass_vacuously(self):
        tmp, server, db, state = fixture()
        server.messages['destination'] = [b'one']
        server.events = []                                           # a copy exists but no APPEND was counted
        try:
            with self.assertRaises(st.Violation) as raised:
                st.check_invariants(server, BODIES, db, state, 0)
            self.assertIn('counter', str(raised.exception))
        finally:
            tmp.cleanup()


if __name__ == '__main__':
    unittest.main()
