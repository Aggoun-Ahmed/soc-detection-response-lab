"""Offline unit tests for Phase 4 correlation logic."""
import unittest
from tools.sysmon_correlator import correlate


def alert(rule, guid="lab-guid", agent="001", when="2026-11-08 22:00:00"):
    return {
        "rule": {"id": str(rule)},
        "agent": {"id": agent},
        "data": {"win": {"eventdata": {"processGuid": guid, "utcTime": when}}},
    }


class CorrelationTests(unittest.TestCase):
    def test_matching_process_within_window(self):
        events = [alert(100133), alert(100134, when="2026-11-08 22:00:20")]
        self.assertEqual(len(correlate(events)), 1)

    def test_mismatched_guid(self):
        self.assertEqual(correlate([alert(100133), alert(100134, guid="other")]), [])

    def test_mismatched_agent(self):
        self.assertEqual(correlate([alert(100133), alert(100134, agent="002")]), [])

    def test_outside_window(self):
        self.assertEqual(correlate([alert(100133), alert(100134, when="2026-11-08 22:01:01")]), [])

    def test_reverse_order(self):
        self.assertEqual(correlate([alert(100134), alert(100133, when="2026-11-08 22:00:20")]), [])

    def test_missing_guid(self):
        self.assertEqual(correlate([alert(100133, guid=""), alert(100134)]), [])

    def test_duplicates_only_one_finding(self):
        events = [alert(100133), alert(100134, when="2026-11-08 22:00:20"), alert(100134, when="2026-11-08 22:00:21")]
        self.assertEqual(len(correlate(events)), 1)

    def test_mixed_order_of_input(self):
        events = [alert(100134, when="2026-11-08 22:00:20"), alert(100133)]
        self.assertEqual(len(correlate(events)), 1)


if __name__ == "__main__":
    unittest.main()
