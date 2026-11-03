"""Refuse to test a binary that is older than the sources it claims to represent.

A stale binary silently passes or fails for the wrong reasons (a stale `target/release`
once made a whole matrix reject a newer config key). Every suite calls require_fresh()
on each binary it executes. A binary is stale when any Rust source or Cargo manifest of
the project or its vendored crates is newer than it. Set IMAPLANE_ALLOW_STALE_BINARY=1 to
bypass deliberately (for example to compare against an old release).
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def source_files(root=ROOT):
    """Files whose change means a rebuild is required."""
    for top in ('src', 'vendor'):
        base = root / top
        if not base.is_dir():
            continue
        for path in base.rglob('*'):
            if path.suffix in ('.rs',) or path.name in ('Cargo.toml',):
                if 'tests' in path.relative_to(root).parts and top == 'vendor':
                    continue  # vendored crates' own integration tests are not part of the build
                yield path
    for name in ('Cargo.toml', 'Cargo.lock'):
        if (root / name).exists():
            yield root / name


def stale_reason(binary, root=ROOT):
    """None if `binary` is fresh, else a one-line explanation."""
    binary = Path(binary)
    if not binary.is_file():
        return f'{binary} does not exist; build it first'
    built = binary.stat().st_mtime
    newest, newest_path = 0.0, None
    for path in source_files(root):
        mtime = path.stat().st_mtime
        if mtime > newest:
            newest, newest_path = mtime, path
    if newest_path is not None and newest > built:
        return (f'{binary} is older than {newest_path.relative_to(root)} '
                f'({newest - built:.0f}s newer); rebuild before testing')
    return None


def require_fresh(binary, label='binary', root=ROOT):
    if os.environ.get('IMAPLANE_ALLOW_STALE_BINARY') == '1':
        return
    reason = stale_reason(binary, root)
    if reason:
        sys.exit(f'STALE {label}: {reason} (set IMAPLANE_ALLOW_STALE_BINARY=1 to override)')
