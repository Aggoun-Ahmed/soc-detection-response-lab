"""Phase 5 checkpointed snapshot recovery tests (no Wazuh access needed)."""
import json
from pathlib import Path
import tempfile
import unittest

from tools.phase5_checkpoint import SnapshotCheckpoint


def alert(rule, guid="GUID-SENSITIVE", agent="001", at="2026-11-08 22:00:00"):
    return {
        "rule": {"id": str(rule)},
        "agent": {"id": agent, "name": "PRIVATE-COMPUTER"},
        "data": {"win": {"eventdata": {"processGuid": guid, "utcTime": at}}},
    }


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / "alerts.json"
        self.state = Path(self.tmp.name) / "checkpoint.json"
        self.source.write_bytes(b"")

    def append(self, *alerts):
        with self.source.open("ab") as handle:
            for record in alerts:
                handle.write(json.dumps(record).encode() + b"\n")

    def test_recovery_across_restarts(self):
        self.append(alert(100133))
        self.assertEqual(SnapshotCheckpoint(self.state).process(self.source), [])
        self.append(alert(100134, at="2026-11-08 22:00:00.197"))
        findings = SnapshotCheckpoint(self.state).process(self.source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["delta_seconds"], 0.197)
        self.assertEqual(SnapshotCheckpoint(self.state).process(self.source), [])

    def test_prefix_tampering_fails_closed(self):
        self.append(alert(100133))
        SnapshotCheckpoint(self.state).process(self.source)
        self.source.write_bytes(json.dumps(alert(100133, guid="CHANGED")).encode() + b"\n")
        with self.assertRaises(RuntimeError):
            SnapshotCheckpoint(self.state).process(self.source)

    def test_truncated_source_fails_closed(self):
        self.append(alert(100133), alert(100134, at="2026-11-08 22:00:10"))
        SnapshotCheckpoint(self.state).process(self.source)
        self.source.write_bytes(json.dumps(alert(100133)).encode() + b"\n")
        with self.assertRaises(RuntimeError):
            SnapshotCheckpoint(self.state).process(self.source)

    def test_unterminated_line_fails(self):
        with self.source.open("ab") as handle:
            handle.write(b'{"rule":')
        with self.assertRaises(ValueError):
            SnapshotCheckpoint(self.state).process(self.source)
        self.assertFalse(self.state.exists())

    def test_sensitive_identifiers_not_in_checkpoint(self):
        self.append(alert(100133))
        SnapshotCheckpoint(self.state).process(self.source)
        content = self.state.read_text(encoding="utf-8")
        self.assertNotIn("GUID-SENSITIVE", content)
        self.assertNotIn("PRIVATE-COMPUTER", content)
        self.assertNotIn('"001"', content)

    def test_invalid_checkpoint_version(self):
        self.state.write_text('{"version":999}', encoding="utf-8")
        with self.assertRaises(ValueError):
            SnapshotCheckpoint(self.state)

    def test_append_only_ignored_on_replay(self):
        self.append(alert(100133), alert(100134, at="2026-11-08 22:00:20"))
        self.assertEqual(len(SnapshotCheckpoint(self.state).process(self.source)), 1)
        self.assertEqual(SnapshotCheckpoint(self.state).process(self.source), [])
        self.append(alert(100134, at="2026-11-08 22:00:21"))
        self.assertEqual(SnapshotCheckpoint(self.state).process(self.source), [])


    def test_finding_saved_in_outbox_after_restart(self):
        self.append(alert(100133), alert(100134, at="2026-11-08 22:00:00.197"))
        worker = SnapshotCheckpoint(self.state)
        self.assertEqual(len(worker.process(self.source)), 1)
        restored = SnapshotCheckpoint(self.state)
        self.assertEqual(len(restored.pending_findings()), 1)
        self.assertEqual(restored.pending_findings()[0]["id"], 1)

    def test_replay_does_not_duplicate_outbox(self):
        self.append(alert(100133), alert(100134, at="2026-11-08 22:00:00.197"))
        SnapshotCheckpoint(self.state).process(self.source)
        worker = SnapshotCheckpoint(self.state)
        self.assertEqual(worker.process(self.source), [])
        self.assertEqual(len(worker.pending_findings()), 1)

    def test_acknowledged_finding_stays_acknowledged(self):
        self.append(alert(100133), alert(100134, at="2026-11-08 22:00:00.197"))
        SnapshotCheckpoint(self.state).process(self.source)
        worker = SnapshotCheckpoint(self.state)
        worker.acknowledge(1)
        self.assertEqual(SnapshotCheckpoint(self.state).pending_findings(), [])
        self.assertEqual(SnapshotCheckpoint(self.state).process(self.source), [])
        self.assertEqual(SnapshotCheckpoint(self.state).pending_findings(), [])

    def test_invalid_ack_does_not_remove_pending(self):
        self.append(alert(100133), alert(100134, at="2026-11-08 22:00:00.197"))
        SnapshotCheckpoint(self.state).process(self.source)
        worker = SnapshotCheckpoint(self.state)
        for value in (0, 999, "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                worker.acknowledge(value)
        self.assertEqual(len(SnapshotCheckpoint(self.state).pending_findings()), 1)

    def test_sensitive_details_absent_from_outbox(self):
        self.append(alert(100133), alert(100134, at="2026-11-08 22:00:00.197"))
        SnapshotCheckpoint(self.state).process(self.source)
        content = self.state.read_text(encoding="utf-8")
        for value in ("GUID-SENSITIVE", "PRIVATE-COMPUTER", '"001"'):
            self.assertNotIn(value, content)

    def test_legacy_checkpoint_without_outbox_loads(self):
        self.append(alert(100133))
        SnapshotCheckpoint(self.state).process(self.source)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        saved.pop("pending")
        saved.pop("next_finding_id")
        self.state.write_text(json.dumps(saved), encoding="utf-8")
        restored = SnapshotCheckpoint(self.state)
        self.assertEqual(restored.pending_findings(), [])
        self.append(alert(100134, at="2026-11-08 22:00:00.197"))
        self.assertEqual(len(restored.process(self.source)), 1)
        self.assertEqual(len(SnapshotCheckpoint(self.state).pending_findings()), 1)


if __name__ == "__main__":
    unittest.main()
