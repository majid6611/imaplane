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


def fsync_probe(root, samples=32):
    values=[]
    with (root/'sync-probe').open('wb',buffering=0) as output:
        for index in range(samples):
            output.write(bytes([index%256])*4096)
            start=time.perf_counter_ns(); os.fsync(output.fileno()); values.append((time.perf_counter_ns()-start)/1e6)
    ordered=sorted(values)
    return {'samples_ms':values,'median_ms':statistics.median(values),'p95_ms':ordered[min(len(ordered)-1,int(.95*len(ordered)))],'max_ms':max(values)}

def provenance(binary):
    metadata=binary.with_name(binary.name+'.json')
    if not metadata.is_file(): raise RuntimeError('Build a commit-bound snapshot with scripts/build-benchmark-binary.py first')
    record=json.loads(metadata.read_text())
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=record['binary_sha256']: raise RuntimeError('binary differs from its recorded commit snapshot')
    return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/'target/release/imaplane')
    parser.add_argument('--binary-b',type=Path)
    parser.add_argument('--mixed',action='store_true',help='cycle 1KiB, 8KiB, 128KiB and 1MiB attachments in duplicate pairs')
    parser.add_argument('--smoke',action='store_true',help='permit fewer than five repeats for harness checks only')
    parser.add_argument('--messages',type=int,default=100)
    parser.add_argument('--attachment-bytes',type=int,default=4096)
    parser.add_argument('--latency-ms',type=int,nargs='+',default=[0,25,50])
    parser.add_argument('--repeats',type=int,default=5)
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
    if args.repeats<5 and not args.smoke: parser.error('at least five repetitions are required; use --smoke only for harness tests')
    binaries={'A':binary,'B':(args.binary_b or binary).resolve()}
    records={label:provenance(path) for label,path in binaries.items()}
    if args.mixed:
        bodies=[dataset(2,[1024,8192,131072,1048576][(i//2)%4])[0] for i in range(args.messages)]
    else: bodies=dataset(args.messages,args.attachment_bytes)

    result={'format_version':2,'binaries':records,'mixed':args.mixed,'build_source_sha256':build_source_fingerprint(),'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
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
            if args.mixed:
                lab.seed(bodies[:len(bodies)//2]); lab.seed(bodies[len(bodies)//2:],'Travail')
            else: lab.seed(bodies)
            result['fsync_probe_start']=fsync_probe(root)
            for latency in args.latency_ms:
                for repeat in range(args.repeats):
                    # Alternate AB / BA so labels are not confounded with run order.
                    for label in (['A','B'] if repeat%2==0 else ['B','A']):
                        binary=binaries[label]
                        name=f'l{latency}r{repeat}{label.lower()}'
                        cfg,destination,proxies=lab.config(name,latency)
                        for phase in ['fresh','resume']:
                            previous=[p.round_trips for p in proxies]; command_counts=[len(p.commands) for p in proxies]
                            trace=root/'fsync.stats'; memory=root/'memory.json'
                            env=os.environ.copy(); env['LC_ALL']='C'; env.pop('IMAPLANE_FAULT_POINT',None)
                            probe_before=fsync_probe(root,8)
                            started=time.perf_counter()
                            p=subprocess.run(['strace','-f','-qq','-c','-e','trace=fsync,fdatasync','-o',str(trace),'/usr/bin/time','-f','{"max_rss_kib":%M,"user_seconds":%U,"system_seconds":%S}','-o',str(memory),str(binary),'migrate','--config',str(cfg),'--json'],env=env,capture_output=True,text=True,timeout=1800)
                            elapsed=time.perf_counter()-started
                            if p.returncode!=0: raise RuntimeError(f'benchmark migration failed: {p.returncode}: {p.stderr}')
                            report=json.loads(p.stdout); assert report['complete'] and len(report['entries'])==args.messages
                            counts=fsync_counts(trace.read_text()); metrics=json.loads(memory.read_text())
                            by_role={role:proxies[i].round_trips-previous[i] for i,role in enumerate(['source','destination'])}
                            verbs={role:dict(collections.Counter(v for v,_ in proxies[i].commands[command_counts[i]:])) for i,role in enumerate(['source','destination'])}
                            row={'fsync_probe_before':probe_before,'fsync_probe_after':fsync_probe(root,8),'binary':label,'phase':phase,'repeat':repeat,'latency_ms':latency,'wall_seconds':elapsed,
                                 'messages_per_second':args.messages/elapsed,'source_message_bytes_per_second':sum(map(len,bodies))/elapsed if phase=='fresh' else 0,
                                 'protocol_round_trips':by_role,'round_trips_per_message':sum(by_role.values())/args.messages,
                                 **counts,'syncs_per_message':sum(counts.values())/args.messages,**metrics,'command_counts':verbs}
                            # Correctness checks are excluded from the timed region and proxies.
                            lab.check(destination)
                            assert all(not p.errors for p in proxies)
                            result['runs'].append(row)
                            print(f'{label} {phase} latency={latency}ms repeat={repeat}: {row["messages_per_second"]:.2f} msg/s, {row["round_trips_per_message"]:.2f} exchanges/msg, {row["syncs_per_message"]:.2f} syncs/msg, {metrics["max_rss_kib"]} KiB RSS',flush=True)
            result['all_content_metadata_multiplicity_checks_passed']=True
            result['source_unchanged']=True
            result['fsync_probe_end']=fsync_probe(root)
    result['medians']=[]
    for label in binaries:
        for latency in args.latency_ms:
            for phase in ['fresh','resume']:
                group=[r for r in result['runs'] if r['binary']==label and r['latency_ms']==latency and r['phase']==phase]
                result['medians'].append({'binary':label,'latency_ms':latency,'phase':phase,**{key:statistics.median(r[key] for r in group) for key in ['wall_seconds','messages_per_second','round_trips_per_message','syncs_per_message','max_rss_kib']}})
    args.output.parent.mkdir(parents=True,exist_ok=True)
    # Do not overwrite previous baseline evidence silently.
    with args.output.open('x') as output: json.dump(result,output,indent=2); output.write('\n')
    print('Saved',args.output,flush=True)

if __name__=='__main__': main()
