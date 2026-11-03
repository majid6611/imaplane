#!/usr/bin/env python3
"""Collect dependency and Rust toolchain notices; fail on missing crate notices."""
import json
from pathlib import Path
import sys
metadata = json.loads(Path(sys.argv[1]).read_text())
output = Path(sys.argv[2])
parts = ['IMAPLANE third-party notices\n\nGenerated from the locked Cargo metadata graph. Includes build/test dependencies.\nSPDX expressions are declarations, not an independent license compatibility review.\n']
missing = []
nodes = {n['id']:n for n in metadata['resolve']['nodes']}
pending = [metadata['resolve']['root']]; reachable = set()
while pending:
    current = pending.pop()
    if current in reachable: continue
    reachable.add(current)
    pending.extend(d['pkg'] for d in nodes[current]['deps'])
for package in sorted(metadata['packages'],key=lambda p:(p['name'],p['version'])):
    if package['id'] not in reachable: continue
    directory = Path(package['manifest_path']).parent
    files = sorted(p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE','LICENCE','COPYING','NOTICE','COPYRIGHT','UNLICENSE')))
    if package.get('license_file'):
        p = directory/package['license_file']
        if p.is_file() and p not in files: files.append(p)
    if not files: missing.append(package['name']+' '+package['version'])
    parts.append('\n\n===== '+package['name']+' '+package['version']+' =====\nLicense: '+str(package.get('license'))+'\nRepository: '+str(package.get('repository'))+'\n')
    for file in files:
        parts.append('\n--- '+file.name+' ---\n'+file.read_text(errors='replace'))
if missing: sys.exit('Missing crate license/notice files: '+', '.join(missing))
if len(sys.argv) > 3:
    toolchain = Path(sys.argv[3])/'share/doc/rust'
    for file in sorted(toolchain.rglob('*')):
        if file.is_file() and (file.parent.name == 'licenses' or file.name == 'COPYRIGHT-library.html' or (file.name == 'COPYRIGHT.html' and not (toolchain/'COPYRIGHT-library.html').exists())):
            parts.append('\n\n===== Rust toolchain '+file.name+' =====\n'+file.read_text(errors='replace'))
output.write_text('\n'.join(parts))
print('Collected notices for',len(reachable),'locked packages')
