#!/usr/bin/env python3
"""Pinned, checksum-verified build tool download. No tar path extraction."""
import hashlib
import io
import os
from pathlib import Path
import platform
import sys
import tarfile
import tempfile
import urllib.request
VERSION = '2.48.0'
ASSETS = {
    'x86_64': ('x86_64','6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750'),
    'aarch64': ('arm64','a9a75213763783b7669719e505474c748c5ad7dc66591a195619deb50f85c2f4'),
}
arch, checksum = ASSETS[platform.machine()]
root = Path(sys.argv[1]); root.mkdir(parents=True,exist_ok=True)
archive = root/f'nfpm_{VERSION}_Linux_{arch}.tar.gz'
if not archive.exists():
    with urllib.request.urlopen(f'https://github.com/goreleaser/nfpm/releases/download/v{VERSION}/{archive.name}',timeout=60) as response:
        data = response.read(32*1024*1024)
else: data = archive.read_bytes()
if hashlib.sha256(data).hexdigest() != checksum:
    sys.exit('nFPM checksum mismatch; refusing to execute build tool')
archive.write_bytes(data)
with tarfile.open(fileobj=io.BytesIO(data)) as tar:
    member = tar.getmember('nfpm')
    if not member.isfile() or member.size > 64*1024*1024: sys.exit('unexpected nFPM archive')
    binary = tar.extractfile(member).read()
with tempfile.NamedTemporaryFile(dir=root,delete=False) as f:
    f.write(binary); temporary = Path(f.name)
temporary.chmod(0o755); os.replace(temporary,root/'nfpm')
