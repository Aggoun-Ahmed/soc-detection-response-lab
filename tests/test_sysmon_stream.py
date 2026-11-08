"""Phase 5 incremental correlation unit tests."""
import unittest
from tools.sysmon_stream import IncrementalCorrelator

def event(rule,guid="test-guid",agent="001",at="2026-11-08T22:00:00Z"):
    return {"rule":{"id":str(rule)},"agent":{"id":agent},"data":{"win":{"eventdata":{"processGuid":guid,"utcTime":at}}}}

class StreamTests(unittest.TestCase):
    def test_cross_batch_positive(self):
        c=IncrementalCorrelator()
        self.assertEqual(c.feed([event(100133)]),[])
        self.assertEqual(len(c.feed([event(100134,at="2026-11-08T22:00:00.197Z")])),1)
    def test_different_guid(self):
        self.assertEqual(IncrementalCorrelator().feed([event(100133),event(100134,guid="other")]),[])
    def test_different_agent(self):
        self.assertEqual(IncrementalCorrelator().feed([event(100133),event(100134,agent="002")]),[])
    def test_outside_window(self):
        self.assertEqual(IncrementalCorrelator().feed([event(100133),event(100134,at="2026-11-08T22:01:01Z")]),[])
    def test_reverse_arrival(self):
        c=IncrementalCorrelator()
        self.assertEqual(c.feed([event(100134,at="2026-11-08T22:00:10Z")]),[])
        self.assertEqual(len(c.feed([event(100133)])),1)
    def test_reverse_event_chronology(self):
        self.assertEqual(IncrementalCorrelator().feed([event(100134),event(100133,at="2026-11-08T22:00:10Z")]),[])
    def test_duplicates(self):
        c=IncrementalCorrelator()
        pair=[event(100133),event(100134,at="2026-11-08T22:00:10Z")]
        self.assertEqual(len(c.feed(pair)),1)
        self.assertEqual(c.feed(pair),[])
    def test_malformed_inputs(self):
        self.assertEqual(IncrementalCorrelator().feed([None,{},{"rule":None},event(100131),event(100133,at="bad")]),[])
    def test_privacy(self):
        c=IncrementalCorrelator()
        result=c.feed([event(100133,guid="private-guid"),event(100134,guid="private-guid",at="2026-11-08T22:00:10Z")])
        self.assertEqual(len(result),1)
        self.assertNotIn("private-guid",str(result))
        self.assertNotIn("processGuid",result[0])
        self.assertNotIn("agent_id",result[0])
    def test_same_timestamp(self):
        self.assertEqual(len(IncrementalCorrelator().feed([event(100134),event(100133)])),1)
    def test_fail_closed_capacity(self):
        c=IncrementalCorrelator(max_keys=1)
        c.ingest(event(100133))
        with self.assertRaises(RuntimeError): c.ingest(event(100133,guid="other"))
    def test_expired_events(self):
        c=IncrementalCorrelator()
        c.ingest(event(100133))
        c.ingest(event(100133,guid="new",at="2026-11-08T22:05:00Z"))
        self.assertEqual(c.feed([event(100134,at="2026-11-08T22:00:10Z")]),[])

if __name__=="__main__": unittest.main()
