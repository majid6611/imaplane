"""Offline tests for benchmark metric parsing and deterministic MIME input."""
import unittest
from benchmark import fsync_counts, dataset

class BaselineTests(unittest.TestCase):
    def test_sync_counts_include_both_syscalls_and_optional_errors_column(self):
        summary='''% time seconds usecs/call calls errors syscall
 75.0 0.1500 10 15000 fsync
 25.0 0.0500 20 2500 3 fdatasync
100.0 0.2000 11 17500 3 total
'''
        self.assertEqual(fsync_counts(summary),{'fsync':15000,'fdatasync':2500})
        self.assertEqual(fsync_counts(''),{'fsync':0,'fdatasync':0})
    def test_dataset_is_reproducible_with_intentional_duplicate_multiplicity(self):
        bodies=dataset(4,4096)
        self.assertEqual(bodies,dataset(4,4096))
        self.assertEqual(bodies[0],bodies[1]); self.assertNotEqual(bodies[1],bodies[2])
        self.assertIn(b'Content-Disposition: attachment',bodies[0])

if __name__=='__main__': unittest.main()
