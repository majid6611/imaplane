"""The stale-binary guard itself (offline)."""
import os
import tempfile
import time
import unittest
from pathlib import Path
import freshness


def touch(path, mtime):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('x')
    os.utime(path, (mtime, mtime))


class Freshness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.now = time.time()
        touch(self.root / 'src/a.rs', self.now - 100)
        touch(self.root / 'vendor/imap/src/lib.rs', self.now - 100)
        touch(self.root / 'Cargo.toml', self.now - 100)
        touch(self.root / 'Cargo.lock', self.now - 100)

    def tearDown(self):
        self.tmp.cleanup()

    def binary(self, age):
        path = self.root / 'bin'
        touch(path, self.now - age)
        return path

    def test_binary_newer_than_every_source_is_fresh(self):
        self.assertIsNone(freshness.stale_reason(self.binary(50), self.root))

    def test_any_newer_source_makes_it_stale_and_names_the_file(self):
        for rel in ('src/a.rs', 'vendor/imap/src/lib.rs', 'Cargo.toml', 'Cargo.lock', 'src/new/deep.rs'):
            binary = self.binary(50)
            touch(self.root / rel, self.now)
            reason = freshness.stale_reason(binary, self.root)
            self.assertIn(rel.split('/')[-1], reason, rel)
            touch(self.root / rel, self.now - 100)

    def test_missing_binary_and_non_source_changes(self):
        self.assertIn('does not exist', freshness.stale_reason(self.root / 'nope', self.root))
        binary = self.binary(50)
        touch(self.root / 'src/notes.md', self.now)               # documentation is not a build input
        touch(self.root / 'vendor/imap/tests/it.rs', self.now)    # vendored integration tests are not built in
        self.assertIsNone(freshness.stale_reason(binary, self.root))

    def test_require_fresh_exits_unless_explicitly_overridden(self):
        binary = self.binary(500)
        with self.assertRaises(SystemExit) as raised:
            freshness.require_fresh(binary, 'release binary', self.root)
        self.assertIn('STALE release binary', str(raised.exception))
        os.environ['IMAPLANE_ALLOW_STALE_BINARY'] = '1'
        try:
            freshness.require_fresh(binary, 'release binary', self.root)
        finally:
            del os.environ['IMAPLANE_ALLOW_STALE_BINARY']

    def test_the_real_repository_is_scanned(self):
        files = {p.relative_to(freshness.ROOT).as_posix() for p in freshness.source_files()}
        for expected in ('src/engine.rs', 'vendor/imap/src/client/streaming.rs', 'Cargo.lock'):
            self.assertIn(expected, files)


if __name__ == '__main__':
    unittest.main()
