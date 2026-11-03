#!/usr/bin/env python3
"""Host-side lab lifecycle. Destruction is restricted to this Compose project."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = HERE / '.runtime'
CLIENT = RUNTIME / 'client'
PROJECT = 'imaplane-lab'

def execute(args, **kwargs):
    return subprocess.run(list(map(str,args)),check=True,**kwargs)

def compose(*args, **kwargs):
    # Explicit project/file/env inputs; do not inherit a different COMPOSE_FILE.
    env = {k:v for k,v in os.environ.items() if not k.startswith('COMPOSE_')}
    return execute(['docker','compose','--project-name',PROJECT,'--project-directory',HERE,
                    '--file',HERE/'compose.yaml','--env-file',RUNTIME/'compose.env',*args],env=env,**kwargs)

def isolation_check():
    effective=json.loads(compose('--profile','tools','config','--format','json',stdout=subprocess.PIPE,text=True).stdout)
    assert set(effective['services']) == {'source','destination','client'}, 'Expected exactly the three lab services'
    assert effective['networks']['lab']['internal'] is True
    for service in effective['services'].values():
        assert set(service['networks']) == {'lab'}, 'External network rejected'
        assert not service.get('ports') and not service.get('privileged'), 'Published ports/privileged services rejected'
    for volume in effective['volumes'].values():
        assert not volume.get('external') and not volume.get('driver_opts'), 'External or host-backed mail volume rejected'

def private_write(path,text):
    path.write_text(text); path.chmod(0o600)

def prepare():
    if RUNTIME.is_symlink() or (RUNTIME.exists() and not RUNTIME.is_dir()):
        sys.exit('Refusing a symlinked or non-directory lab runtime')
    if RUNTIME.exists() and any(p.is_symlink() for p in RUNTIME.rglob('*')):
        sys.exit('Refusing symlinks inside the lab runtime; do not link production files here')
    for d in [RUNTIME,CLIENT,RUNTIME/'users',RUNTIME/'tls',CLIENT/'reports',CLIENT/'state']:
        d.mkdir(parents=True,exist_ok=True); d.chmod(0o700)
    private_write(RUNTIME/'compose.env',f'LAB_UID={os.getuid()}\nLAB_GID={os.getgid()}\n')
    for role in ['source','destination']:
        private_write(RUNTIME/'users'/role,f'{role}@imaplane.test:{{PLAIN}}test-only-{role}-password\n')
        (RUNTIME/'users'/role).chmod(0o644) # Dovecot auth worker; public synthetic credentials only
        private_write(CLIENT/f'{role}.password',f'test-only-{role}-password\n')
    tls = RUNTIME/'tls'
    def openssl(*args): execute(['openssl',*args],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    if not (tls/'ca.pem').exists():
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','30',
                '-keyout',tls/'ca.key','-out',tls/'ca.pem','-subj','/CN=IMAPLANE LOCAL TEST CA',
                '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        for role,hostname in [('source','source'),('destination','destination'),('proxy','localhost')]:
            openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',tls/f'{role}.key',
                    '-out',tls/f'{role}.csr','-subj',f'/CN={hostname}')
            extension = tls/f'{role}.ext'
            extension.write_text(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{hostname}\n')
            openssl('x509','-req','-in',tls/f'{role}.csr','-CA',tls/'ca.pem','-CAkey',tls/'ca.key',
                    '-CAcreateserial','-days','30','-sha256','-extfile',extension,'-out',tls/f'{role}.crt')
        for p in tls.iterdir(): p.chmod(0o600)
    for role in ['source','destination','proxy']:
        if not (tls/f'{role}.crt').exists() or not (tls/f'{role}.key').exists():
            sys.exit('Incomplete lab certificates; run scripts/lab.sh reset')
        result = subprocess.run(['openssl','x509','-in',str(tls/f'{role}.crt'),'-checkend','3600','-noout'],stdout=subprocess.DEVNULL)
        if result.returncode: sys.exit('Lab certificates expire soon; run scripts/lab.sh reset')
    shutil.copyfile(tls/'ca.pem',CLIENT/'ca.pem')
    for suffix in ['crt','key']:
        shutil.copyfile(tls/f'proxy.{suffix}',CLIENT/f'proxy.{suffix}')
        (CLIENT/f'proxy.{suffix}').chmod(0o600)
    if not (CLIENT/'migration.toml').exists():
        # Seeding writes the exact same mapping alongside the manifest.
        from fixture import FOLDERS, render_config
        private_write(CLIENT/'migration.toml',render_config([(f,f) for f in FOLDERS]))

def tools(script,*args):
    compose('run','--rm','--no-deps','--entrypoint','python3','client',f'/tests/{script}',*args)

def up():
    prepare()
    isolation_check()
    compose('build','client')
    compose('up','-d','--wait','--wait-timeout','90','source','destination')
    tools('fixture.py','seed')
    print('Lab ready: scripts/lab.sh cli migrate --dry-run',flush=True)

def reset():
    # Fixed paths and a private project only. No global docker prune/volume delete.
    prepare()
    isolation_check()
    compose('down','--volumes','--remove-orphans','--timeout','10')
    if RUNTIME.is_symlink(): sys.exit('Refusing to reset a symlinked runtime directory')
    # Only this lab's generated directory is removed. Lifecycle lock lives outside it.
    shutil.rmtree(RUNTIME)
    up()

def main():
    if not __debug__: sys.exit('Python optimization must be disabled for lab safety checks')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['up','reset','down','logs','status','test','recovery','check','cli'])
    parser.add_argument('args',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    endpoint=os.environ.get('DOCKER_HOST')
    if endpoint is None:
        selected=execute(['docker','context','inspect'],stdout=subprocess.PIPE,text=True)
        endpoint=json.loads(selected.stdout)[0]['Endpoints']['docker']['Host']
    if not endpoint.startswith('unix://'):
        sys.exit('This lab requires a local Unix-socket Docker daemon; remote Docker contexts are refused')
    # Prevent resets/seeding racing another lifecycle operation; CLI database lock
    # still protects concurrent migrations exactly as in normal IMAPLANE use.
    lock=open(HERE/'.lifecycle.lock','a')
    if args.command not in ['logs','status']:
        try: fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: sys.exit('Another lab operation is running; wait before resetting or starting a new migration')
    if args.command == 'reset': reset(); return
    if args.command == 'up': up(); return
    if not (RUNTIME/'compose.env').exists(): sys.exit('Run scripts/lab.sh up first')
    isolation_check()
    if args.command == 'down': compose('down','--timeout','10')
    elif args.command == 'status': compose('ps')
    elif args.command == 'logs': compose('logs','--tail','80','source','destination')
    elif args.command == 'test': tools('fixture.py','test')
    elif args.command == 'recovery': tools('recovery.py')
    elif args.command == 'check': tools('fixture.py','check')
    elif args.command == 'cli':
        if not args.args or args.args[0] not in ['inspect','migrate','verify','status']:
            sys.exit('Use cli inspect|migrate|verify|status [--dry-run] [--json]')
        action,*flags=args.args
        allowed={'inspect':set(),'migrate':{'--dry-run','--json'},'verify':{'--json'},'status':{'--json'}}
        if any(f not in allowed[action] for f in flags): sys.exit('Only lab-safe flags are accepted; endpoint/config overrides are not allowed')
        result=subprocess.run(['docker','compose','--project-name',PROJECT,'--project-directory',str(HERE),
            '--file',str(HERE/'compose.yaml'),'--env-file',str(RUNTIME/'compose.env'),
            'run','--rm','--no-deps','--entrypoint','python3','client','/tests/fixture.py','cli',action,*flags],env={k:v for k,v in os.environ.items() if not k.startswith('COMPOSE_')})
        sys.exit(result.returncode)
if __name__=='__main__':
    try: main()
    except subprocess.CalledProcessError as e: sys.exit(e.returncode)
    except AssertionError as e: sys.exit(f'Lab isolation check failed: {e}')
