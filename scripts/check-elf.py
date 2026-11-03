#!/usr/bin/env python3
"""Reject packaging a binary under a different architecture label."""
import struct
import sys
from pathlib import Path
head = Path(sys.argv[1]).read_bytes()[:20]
expected = {'amd64':62,'arm64':183}[sys.argv[2]]
if head[:6] != b'\x7fELF\x02\x01' or struct.unpack('<H',head[18:20])[0] != expected:
    sys.exit('ELF class, endianness or machine does not match package architecture')
