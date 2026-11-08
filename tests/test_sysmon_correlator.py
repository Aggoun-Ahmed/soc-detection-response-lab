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


    def test_duplicate_start_and_end_alerts(self):
        events = [alert(100133), alert(100133), alert(100134, when="2026-11-08 22:00:20"), alert(100134, when="2026-11-08 22:00:20")]
        self.assertEqual(len(correlate(events)), 1)

    def test_malformed_alerts_are_ignored(self):
        events = [None, "x", {}, {"rule": None}, {"rule": {"id": "100133"}, "data": []}, alert(100133), alert(100134, when="2026-11-08 22:00:02")]
        self.assertEqual(len(correlate(events)), 1)

    def test_invalid_timestamp_is_skipped(self):
        self.assertEqual(correlate([alert(100133, when="not-a-date"), alert(100134)]), [])

    def test_missing_timestamp_is_skipped(self):
        self.assertEqual(correlate([alert(100133, when=""), alert(100134)]), [])

    def test_timezone_offset_normalization(self):
        events = [alert(100133, when="2026-11-08T22:00:00Z"), alert(100134, when="2026-11-08T23:00:01+01:00")]
        self.assertEqual(correlate(events)[0]["delta_seconds"], 1.0)

    def test_exact_window_boundary(self):
        self.assertEqual(len(correlate([alert(100133), alert(100134, when="2026-11-08 22:01:00")])), 1)

    def test_same_timestamp(self):
        self.assertEqual(len(correlate([alert(100134), alert(100133)])), 1)

    def test_alert_after_window_does_not_match_even_with_repeated_start(self):
        events = [alert(100133), alert(100133, when="2026-11-08 22:00:50"), alert(100134, when="2026-11-08 22:01:10")]
        self.assertEqual(correlate(events), [])

    def test_invalid_window(self):
        for value in (0, -1, float("nan"), float("inf"), "60"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                correlate([], value)

    def test_non_list_input(self):
        with self.assertRaises(TypeError):
            correlate({"rule": {"id": "100133"}})

    def test_no_sensitive_ids_in_output(self):
        result = str(correlate([alert(100133, guid="private-guid"), alert(100134, guid="private-guid", when="2026-11-08 22:00:02")]))
        self.assertNotIn("private-guid", result)
        self.assertNotIn("agent_id", result)
        self.assertNotIn("processGuid", result)


if __name__ == "__main__":
    unittest.main()
