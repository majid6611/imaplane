#!/usr/bin/env python3
"""Cost of the Gmail duplicate check: protection on vs off, same Gmail-like fixture, with and without injected latency.
Usage: python3 gmail_dup_bench.py BIN [N=300] [LATENCY_MS=20] [REPEATS=3]. Local loopback only; synthetic mail."""
import json, os, statistics, subprocess, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import PASSWORD, ProtocolServer, Proxy, command
BIN = Path(sys.argv[1]).resolve(); N = int(sys.argv[2]) if len(sys.argv) > 2 else 300
LAT = int(sys.argv[3]) if len(sys.argv) > 3 else 20; REP = int(sys.argv[4]) if len(sys.argv) > 4 else 3
TOKEN = 'bench-token'
def msg(i): return (f'Message-ID: <bench{i}@x>\r\nFrom: a@example.invalid\r\nSubject: s{i}\r\n\r\n' + ('body %d ' % i) * 200 + '\r\n').encode()
with tempfile.TemporaryDirectory(prefix='imaplane-bench-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'c.crt', root / 'c.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    tok = root / 'token'; tok.write_text(TOKEN); tok.chmod(0o600)
    def run(protect, latency):
        s = ProtocolServer(str(cert), str(key), 'rev1'); s.xoauth2_token = TOKEN
        s.messages['source'] = [msg(i) for i in range(N)]
        px = Proxy(s.port, str(cert), str(key), latency_ms=latency) if latency else None
        port = px.port if px else s.port
        state = root / f's{time.monotonic_ns()}'
        cfg = root / f'{state.name}.toml'
        text = f'state_dir = "{state}"\ntimeout_seconds = 30\n' + ('' if protect else 'gmail_duplicate_protection = "off"\n')
        for role in ['source', 'destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {port}\nusername = "{role}"\nca_file = "{cert}"\nauth = "xoauth2"\naccess_token_file = "{tok}"\n'
        text += '[[folders]]\nsource = "台北/📬"\ndestination = "台北/📬"\n'
        cfg.write_text(text)
        t = time.monotonic()
        p = subprocess.run([str(BIN), 'migrate', '--config', str(cfg), '--json'], capture_output=True, text=True, timeout=3000)
        dt = time.monotonic() - t
        assert p.returncode == 0, p.stderr[-500:]
        assert len([m for m in s.messages['destination'] if m]) == N
        extra = (len(s.searches), s.header_fetches)
        s.close()
        if px: px.close()
        return dt, extra
    for latency in (0, LAT):
        res = {True: [], False: []}
        for r in range(REP):
            for protect in (False, True):      # interleaved, same conditions
                res[protect].append(run(protect, latency))
        off = statistics.median(x[0] for x in res[False]); on = statistics.median(x[0] for x in res[True])
        print(f'N={N} latency={latency}ms: off median {off:.2f}s  on median {on:.2f}s  overhead {100*(on-off)/off:+.1f}%  (searches, header fetches per run: {res[True][0][1]})  runs off={[round(x[0],2) for x in res[False]]} on={[round(x[0],2) for x in res[True]]}', flush=True)
