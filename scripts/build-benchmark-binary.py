#!/usr/bin/env python3
"""Build a normal release snapshot from a clean tracked Git commit with provenance."""
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests/local'))
from benchmark import build_source_fingerprint

def main():
    subprocess.run(['git','diff','--exit-code','HEAD','--'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
    untracked=subprocess.check_output(['git','ls-files','--others','--exclude-standard','src','vendor','Cargo.toml','Cargo.lock','scripts','tests','docs'],cwd=ROOT,text=True)
    if untracked.strip(): sys.exit('Commit build/harness/documentation inputs before capturing provenance')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    subprocess.run(['cargo','build','--release','--locked'],cwd=ROOT,check=True)
    payload=(ROOT/'target/release/imaplane').read_bytes(); digest=hashlib.sha256(payload).hexdigest()
    directory=ROOT/'target/baselines'/commit; directory.mkdir(parents=True,exist_ok=True)
    binary=directory/'imaplane'; metadata=directory/'imaplane.json'
    record={'git_commit':commit,'binary_sha256':digest,'build_source_sha256':build_source_fingerprint(),
            'cargo_lock_sha256':hashlib.sha256((ROOT/'Cargo.lock').read_bytes()).hexdigest(),
            'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'profile':'release-default-features'}
    if binary.exists() or metadata.exists():
        if not (binary.exists() and metadata.exists() and binary.read_bytes()==payload and json.loads(metadata.read_text())==record):
            sys.exit('Existing snapshot differs; do not overwrite benchmark evidence')
    else:
        with binary.open('xb') as out: out.write(payload)
        binary.chmod(0o755)
        with metadata.open('x') as out: json.dump(record,out,indent=2); out.write('\n')
    (ROOT/'target/release/imaplane.json').write_text(json.dumps(record,indent=2)+'\n')
    print(binary)
if __name__=='__main__': main()
