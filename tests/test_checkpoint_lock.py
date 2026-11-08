"""Cross-process checkpoint locking tests, using only temporary synthetic paths."""
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

from tools.checkpoint_lock import checkpoint_lock


class CheckpointLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "checkpoint.json"

    def test_second_process_rejected_and_lock_released(self):
        script = (
            "import sys; from tools.checkpoint_lock import checkpoint_lock; "
            "lock=checkpoint_lock(sys.argv[1]); lock.__enter__(); "
            "print('LOCKED',flush=True); sys.stdin.readline(); lock.__exit__(None,None,None)"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(self.state)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            self.assertEqual(process.stdout.readline().strip(), "LOCKED")
            with self.assertRaisesRegex(RuntimeError, "in use"):
                with checkpoint_lock(self.state):
                    pass
        finally:
            process.communicate(input="\n", timeout=10)
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertEqual(process.returncode, 0)
        with checkpoint_lock(self.state):
            pass

    def test_lock_file_remains_after_release(self):
        with checkpoint_lock(self.state):
            self.assertTrue(Path(str(self.state) + ".lock").exists())
        self.assertTrue(Path(str(self.state) + ".lock").exists())

    def test_crash_releases_os_lock(self):
        script = (
            "import os,sys; from tools.checkpoint_lock import checkpoint_lock; "
            "lock=checkpoint_lock(sys.argv[1]); lock.__enter__(); os._exit(0)"
        )
        result = subprocess.run(
            [sys.executable, "-c", script, str(self.state)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with checkpoint_lock(self.state):
            pass


if __name__ == "__main__":
    unittest.main()
