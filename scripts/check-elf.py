#!/usr/bin/env python3
"""Reject packaging a binary under a different architecture label, or one built without the durability flags.

  check-elf.py BINARY amd64|arm64

The second check reads the dynamic symbol table: the bundled SQLite is built with -DHAVE_FDATASYNC=1 (see
.cargo/config.toml) and then imports fdatasync from libc; without the flag it imports only fsync. A binary that
lost the flag would still be correct, only slower, so this is a packaging gate and not a safety net.
"""
import struct
import sys
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()
head = data[:20]
expected = {'amd64': 62, 'arm64': 183}[sys.argv[2]]
if head[:6] != b'\x7fELF\x02\x01' or struct.unpack('<H', head[18:20])[0] != expected:
    sys.exit('ELF class, endianness or machine does not match package architecture')


def undefined_dynamic_symbols(blob):
    shoff, = struct.unpack_from('<Q', blob, 0x28)
    shentsize, shnum = struct.unpack_from('<HH', blob, 0x3A)
    sections = [struct.unpack_from('<IIQQQQIIQQ', blob, shoff + i * shentsize) for i in range(shnum)]
    names = set()
    for name, kind, flags, addr, offset, size, link, info, align, entsize in sections:
        if kind != 11:          # SHT_DYNSYM
            continue
        strtab = sections[link]
        for off in range(offset, offset + size, 24):
            st_name, st_info, st_other, st_shndx = struct.unpack_from('<IBBH', blob, off)
            if st_shndx == 0 and st_name:
                start = strtab[4] + st_name
                names.add(blob[start:blob.index(b'\0', start)].decode())
    return names


imports = undefined_dynamic_symbols(data)
if 'fdatasync' not in imports:
    sys.exit('the binary does not import fdatasync: SQLite was built without -DHAVE_FDATASYNC=1 (.cargo/config.toml missing from the build?)')
