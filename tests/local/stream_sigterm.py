#!/usr/bin/env python3
"""Graceful shutdown of a large-message transfer (phase 5A): SIGTERM in every phase.

A throttled lean fixture makes each phase of a 200 MiB spooled transfer last several seconds. A
SIGTERM is sent a moment into one phase and the test records how long the process takes to exit,
what the report and journal say, and that a rerun finishes the work with exactly one APPEND:

  download   while the source message is streamed into the spool (nothing durable exists yet)
  upload     while the literal is streamed to the destination (authorized, so it must complete)
  verify     while the destination copy is read back

The two contracts under test: a stop request NEVER abandons an authorized APPEND midway (that would
manufacture an uncertain transfer), and a stop request in the safe pre-journal phase should not make
the operator wait for the whole download. Usage: python3 tests/local/stream_sigterm.py BINARY
Loopback only; the fixture holds no message in memory.
"""
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.argv, _argv = sys.argv[:1], sys.argv[1:]
from e2e import command, PASSWORD  # noqa: E402
sys.argv = [sys.argv[0]] + _argv
from freshness import require_fresh  # noqa: E402
from lean_server import LeanServer, FOLDER  # noqa: E402

BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release/imaplane').resolve()
require_fresh(BINARY)
MIB = 200
RATE = 40                       # MiB/s, so each pass over 200 MiB takes about 5 seconds
FAILED = []


def check(name):
    def wrap(fn):
        try:
            fn(); print('PASS', name, flush=True)
        except BaseException as exc:
            FAILED.append(name); print('FAIL', name, '->', repr(exc)[:700], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-sigterm-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    password = root / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
    counter = [0]

    def fixture(sig=signal.SIGTERM):
        counter[0] += 1
        server = LeanServer(str(cert), str(key), [MIB << 20], throttle_mib_s=RATE)
        server.append_throttle = RATE
        state = root / f's{counter[0]}'
        cfg = root / f'c{counter[0]}.toml'
        text = f'state_dir = "{state}"\ntimeout_seconds = 60\nmax_message_bytes = 1073741824\nread_attempts = 2\nstream_threshold_bytes = 0\n'
        for role in ('source', 'destination'):
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
        text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
        cfg.write_text(text)
        return server, cfg, state

    def start(cfg):
        return subprocess.Popen([str(BINARY), 'migrate', '--config', str(cfg), '--json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def stop_in(phase_event, server, p, after=1.0, sig=signal.SIGTERM):
        assert phase_event.wait(60), 'the phase never started'
        time.sleep(after)
        sent = time.monotonic()
        p.send_signal(sig)
        out, err = p.communicate(timeout=120)
        return time.monotonic() - sent, p.returncode, json.loads(out), err

    def rows(state): return sqlite3.connect(state / 'journal.sqlite3').execute('select state from transfers').fetchall()
    def intact(state): assert sqlite3.connect(state / 'journal.sqlite3').execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    def appends(server): return sum(v == 'APPEND' for _, v in server.events)
    def residue(state): assert [x.name for x in state.iterdir() if not x.name.startswith(('journal.sqlite3', 'job.lock'))] == []
    def rerun(server, cfg):
        server.throttle = server.append_throttle = None
        p = start(cfg); out, _ = p.communicate(timeout=300)
        return p.returncode, json.loads(out)

    results = {}

    @check('SIGTERM while downloading into the spool: stops within moments, before any journal write; no APPEND; rerun completes once')
    def _():
        server, cfg, state = fixture(); p = start(cfg)
        took, code, report, err = stop_in(server.fetch_started, server, p)
        results['download'] = round(took, 1)
        print(f'       time from SIGTERM to exit: {took:.1f} s (a full pass takes about {MIB / RATE:.0f} s)')
        assert code == 2 and report['interrupted'] and not report['complete'], (code, report)
        assert took < 2.0, f'a stop request during the (safe) download must not wait for it: {took:.1f} s'
        assert report['entries'] == [], 'nothing was attempted, so nothing is reported as failed'
        intact(state); assert rows(state) == [] and appends(server) == 0 and not server.dest
        residue(state)
        code, report = rerun(server, cfg)
        assert code == 0 and report['complete'] and appends(server) == 1 and server.destination_matches_source()
        server.close()

    @check('SIGTERM during the upload: the authorized APPEND completes, is verified, and then the run stops')
    def _():
        server, cfg, state = fixture(); p = start(cfg)
        took, code, report, err = stop_in(server.append_started, server, p)
        results['upload'] = round(took, 1)
        print(f'       time from SIGTERM to exit: {took:.1f} s')
        assert code == 2 and report['interrupted'], (code, report)
        assert [e['result'] for e in report['entries']] == ['confirmed'], report['entries']
        intact(state); assert rows(state) == [('confirmed',)] and appends(server) == 1 and server.destination_matches_source()
        residue(state)
        code, report = rerun(server, cfg)
        assert code == 0 and report['complete'] and appends(server) == 1, 'no second APPEND'
        server.close()

    @check('SIGTERM during read-back verification: verification completes, nothing is left half-confirmed')
    def _():
        server, cfg, state = fixture(); p = start(cfg)
        took, code, report, err = stop_in(server.verify_started, server, p)
        results['verify'] = round(took, 1)
        print(f'       time from SIGTERM to exit: {took:.1f} s')
        assert code == 2 and report['interrupted'] and [e['result'] for e in report['entries']] == ['confirmed'], (code, report)
        intact(state); assert rows(state) == [('confirmed',)] and appends(server) == 1
        residue(state)
        server.close()

    @check('SIGINT and SIGHUP are honored the same way as SIGTERM')
    def _():
        for sig in (signal.SIGINT, signal.SIGHUP):
            server, cfg, state = fixture(); p = start(cfg)
            took, code, report, err = stop_in(server.append_started, server, p, sig=sig)
            assert code == 2 and report['interrupted'] and [e['result'] for e in report['entries']] == ['confirmed'], (sig, code, report)
            intact(state); assert appends(server) == 1 and rows(state) == [('confirmed',)]
            server.close()

    print('worst-case time from a stop request to exit (seconds):', results)
sys.exit(1 if FAILED else 0)
