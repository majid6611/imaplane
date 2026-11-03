#!/usr/bin/env python3
"""Instrumented Linux baseline using isolated real Dovecot, strict TLS and synthetic MIME.
Protocol latency is injected per command/continuation exchange, not kernel netem.
JSON contains aggregates only; temporary secrets/mail/strace files are removed.
"""
import argparse
import base64
import collections
import datetime
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from harness import DovecotLab
from e2e import IMAGE, ROOT


def fsync_counts(text):
    counts={'fsync':0,'fdatasync':0}
    for line in text.splitlines():
        parts=line.split()
        if parts and parts[-1] in counts:
            # strace -c: %time, seconds, usecs/call, calls, [errors], syscall
            counts[parts[-1]]=int(parts[3])
    return counts


def dataset(count, attachment_bytes):
    bodies=[]
    for i in range(count):
        # Adjacent identical pairs intentionally preserve legitimate multiplicity.
        index=i//2
        attachment=hashlib.sha256(str(index).encode()).digest()
        attachment=(attachment*((attachment_bytes+31)//32))[:attachment_bytes]
        wire=(f'From: source@example.test\r\nTo: destination@example.test\r\nMessage-ID: <baseline-{index}@example.test>\r\nSubject: baseline {index}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="fixture"\r\n\r\n--fixture\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBonjour, pièce jointe de référence.\r\n--fixture\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="fixture.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\n').encode()
        wire+=base64.encodebytes(attachment).replace(b'\n',b'\r\n')+b'--fixture--\r\n'
        bodies.append(wire)
    return bodies


def build_source_fingerprint():
    inputs=[ROOT/'Cargo.toml',ROOT/'Cargo.lock',*sorted((ROOT/'src').rglob('*.rs')),*sorted((ROOT/'vendor').rglob('*.rs')),*sorted((ROOT/'vendor').rglob('Cargo.toml'))]
    digest=hashlib.sha256()
    for path in inputs:
        digest.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/'target/release/imaplane')
    parser.add_argument('--messages',type=int,default=100)
    parser.add_argument('--attachment-bytes',type=int,default=4096)
    parser.add_argument('--latency-ms',type=int,nargs='+',default=[0,25,50])
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not 2<=args.messages<=10000 or not 0<=args.attachment_bytes<=16*1024*1024 or not 1<=args.repeats<=20 or any(not 0<=x<=1000 for x in args.latency_ms):
        parser.error('messages 2..10000; attachment bytes 0..16MiB; repeats 1..20; latency 0..1000ms')
    if len(set(args.latency_ms)) != len(args.latency_ms): parser.error('latency values must be unique')
    if args.messages*args.attachment_bytes>128*1024*1024: parser.error('dataset attachment memory budget is 128 MiB')
    if args.output.exists(): parser.error('output already exists; choose a new baseline file')
    binary=args.binary.resolve()
    if not binary.is_file(): parser.error('build the regular release binary first')
    for tool in ['strace','docker','openssl']:
        if not shutil.which(tool): parser.error(f'{tool} is required')
    if not Path('/usr/bin/time').is_file(): parser.error('GNU /usr/bin/time is required')
    bodies=dataset(args.messages,args.attachment_bytes)
    result={'format_version':1,'build_source_sha256':build_source_fingerprint(),'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
            'cargo_lock_sha256':hashlib.sha256((ROOT/'Cargo.lock').read_bytes()).hexdigest(),
            'binary_version':subprocess.check_output([str(binary),'--version'],text=True).strip(),
            'git_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'tracked_diff_sha256':hashlib.sha256(subprocess.check_output(['git','diff','HEAD'],cwd=ROOT)).hexdigest(),
            'platform':platform.platform(),'architecture':platform.machine(),'python':platform.python_version(),
            'dovecot_image':IMAGE,'docker_version':subprocess.check_output(['docker','--version'],text=True).strip(),
            'strace_version':subprocess.check_output(['strace','-V'],text=True).splitlines()[0],
            'method':'strace-instrumented; fresh and no-op resume; protocol-exchange latency, excludes TLS handshake latency; client-only fsync/RSS; server storage not traced; warm host caches uncontrolled',
            'messages':args.messages,'attachment_bytes':args.attachment_bytes,'message_bytes':sum(map(len,bodies)),
            'dataset_sha256':hashlib.sha256(b''.join(hashlib.sha256(body).digest() for body in bodies)).hexdigest(),'runs':[]}
    with tempfile.TemporaryDirectory(prefix='imaplane-benchmark-') as temporary:
        root=Path(temporary)
        with DovecotLab(root) as lab:
            lab.seed(bodies)
            for latency in args.latency_ms:
                for repeat in range(args.repeats):
                    name=f'l{latency}r{repeat}'
                    cfg,destination,proxies=lab.config(name,latency)
                    for phase in ['fresh','resume']:
                        previous=[p.round_trips for p in proxies]; command_counts=[len(p.commands) for p in proxies]
                        trace=root/'fsync.stats'; memory=root/'memory.json'
                        env=os.environ.copy(); env['LC_ALL']='C'; env.pop('IMAPLANE_FAULT_POINT',None)
                        started=time.perf_counter()
                        p=subprocess.run(['strace','-f','-qq','-c','-e','trace=fsync,fdatasync','-o',str(trace),'/usr/bin/time','-f','{"max_rss_kib":%M,"user_seconds":%U,"system_seconds":%S}','-o',str(memory),str(binary),'migrate','--config',str(cfg),'--json'],env=env,capture_output=True,text=True,timeout=1800)
                        elapsed=time.perf_counter()-started
                        if p.returncode!=0: raise RuntimeError(f'benchmark migration failed: {p.returncode}: {p.stderr}')
                        report=json.loads(p.stdout); assert report['complete'] and len(report['entries'])==args.messages
                        counts=fsync_counts(trace.read_text()); metrics=json.loads(memory.read_text())
                        by_role={role:proxies[i].round_trips-previous[i] for i,role in enumerate(['source','destination'])}
                        verbs={role:dict(collections.Counter(v for v,_ in proxies[i].commands[command_counts[i]:])) for i,role in enumerate(['source','destination'])}
                        row={'phase':phase,'repeat':repeat,'latency_ms':latency,'wall_seconds':elapsed,
                             'messages_per_second':args.messages/elapsed,'source_message_bytes_per_second':sum(map(len,bodies))/elapsed if phase=='fresh' else 0,
                             'protocol_round_trips':by_role,'round_trips_per_message':sum(by_role.values())/args.messages,
                             **counts,'syncs_per_message':sum(counts.values())/args.messages,**metrics,'command_counts':verbs}
                        # Correctness checks are excluded from the timed region and proxies.
                        lab.check(destination)
                        assert all(not p.errors for p in proxies)
                        result['runs'].append(row)
                        print(f'{phase} latency={latency}ms repeat={repeat}: {row["messages_per_second"]:.2f} msg/s, {row["round_trips_per_message"]:.2f} exchanges/msg, {row["syncs_per_message"]:.2f} syncs/msg, {metrics["max_rss_kib"]} KiB RSS',flush=True)
            result['all_content_metadata_multiplicity_checks_passed']=True
            result['source_unchanged']=True
    result['medians']=[]
    for latency in args.latency_ms:
        for phase in ['fresh','resume']:
            group=[r for r in result['runs'] if r['latency_ms']==latency and r['phase']==phase]
            result['medians'].append({'latency_ms':latency,'phase':phase,**{key:statistics.median(r[key] for r in group) for key in ['wall_seconds','messages_per_second','round_trips_per_message','syncs_per_message','max_rss_kib']}})
    args.output.parent.mkdir(parents=True,exist_ok=True)
    # Do not overwrite previous baseline evidence silently.
    with args.output.open('x') as output: json.dump(result,output,indent=2); output.write('\n')
    print('Saved',args.output,flush=True)

if __name__=='__main__': main()
