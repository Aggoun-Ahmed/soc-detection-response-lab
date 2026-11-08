"""Explicit log segment handoff tests using synthetic records only."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from tools.phase5_checkpoint import SnapshotCheckpoint


def event(rule, when):
    return {"rule":{"id":str(rule)},"agent":{"id":"synthetic"},
            "data":{"win":{"eventdata":{"processGuid":"SYNTHETIC-ONLY","utcTime":when}}}}


class SegmentRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.active=self.root/"alerts.json"
        self.old=self.root/"alerts.1.json"
        self.state=self.root/"checkpoint.json"

    def write(self,path,*rows):
        path.write_bytes(b"".join(json.dumps(row).encode()+b"\n" for row in rows))

    def test_rotation_preserves_cross_segment_correlation(self):
        self.write(self.active,event(100133,"2026-11-08 22:00:00"))
        self.assertEqual(SnapshotCheckpoint(self.state).process(self.active),[])
        self.active.rename(self.old)
        self.write(self.active,event(100134,"2026-11-08 22:00:00.197"))
        engine=SnapshotCheckpoint(self.state)
        found=engine.process_segments([self.old,self.active])
        self.assertEqual(len(found),1)
        self.assertEqual(found[0]["delta_seconds"],0.197)
        self.assertEqual(SnapshotCheckpoint(self.state).process_segments([self.old,self.active]),[])
        self.assertEqual(len(SnapshotCheckpoint(self.state).pending_findings()),1)

    def test_compressed_history_and_uncompressed_current(self):
        self.write(self.active,event(100133,"2026-11-08 22:00:00"))
        SnapshotCheckpoint(self.state).process(self.active)
        with gzip.open(str(self.old)+".gz","wb") as out:
            out.write(self.active.read_bytes())
        self.write(self.active,event(100134,"2026-11-08 22:00:00.197"))
        found=SnapshotCheckpoint(self.state).process_segments([str(self.old)+".gz",self.active])
        self.assertEqual(len(found),1)

    def test_missing_history_fails_closed(self):
        self.write(self.active,event(100133,"2026-11-08 22:00:00"))
        SnapshotCheckpoint(self.state).process(self.active)
        self.write(self.active,event(100134,"2026-11-08 22:00:00.197"))
        with self.assertRaises(RuntimeError):
            SnapshotCheckpoint(self.state).process_segments([self.active])
        self.assertEqual(SnapshotCheckpoint(self.state).lines,1)

    def test_tampered_archive_fails_closed_without_new_finding(self):
        self.write(self.active,event(100133,"2026-11-08 22:00:00"))
        SnapshotCheckpoint(self.state).process(self.active)
        self.write(self.old,event(100133,"2026-11-08 22:00:01"))
        self.write(self.active,event(100134,"2026-11-08 22:00:00.197"))
        with self.assertRaises(RuntimeError):
            SnapshotCheckpoint(self.state).process_segments([self.old,self.active])
        self.assertEqual(SnapshotCheckpoint(self.state).pending_findings(),[])

    def test_duplicate_segment_path_rejected(self):
        self.write(self.active,event(100133,"2026-11-08 22:00:00"))
        with self.assertRaises(ValueError):
            SnapshotCheckpoint(self.state).process_segments([self.active,self.active])
        self.assertFalse(self.state.exists())

    def test_incomplete_new_segment_rejected_before_commit(self):
        self.write(self.active,event(100133,"2026-11-08 22:00:00"))
        SnapshotCheckpoint(self.state).process(self.active)
        self.active.rename(self.old)
        self.active.write_bytes(b'{"rule":')
        with self.assertRaises(ValueError):
            SnapshotCheckpoint(self.state).process_segments([self.old,self.active])
        self.assertEqual(SnapshotCheckpoint(self.state).lines,1)


if __name__=="__main__":
    unittest.main()
