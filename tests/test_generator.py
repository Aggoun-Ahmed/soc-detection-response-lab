import importlib.util
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

generator = module('generate_events', ROOT / 'scripts/generate_events.py')
analyzer = module('analyze_events', ROOT / 'scripts/analyze_events.py')

class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = generator.generate('all', datetime(2026, 11, 7, tzinfo=timezone.utc))

    def test_six_synthetic_events(self):
        self.assertEqual(len(self.events), 6)
        self.assertTrue(all(e['lab'] == 'soc-portfolio' for e in self.events))
        self.assertTrue(all(json.loads(json.dumps(e)) == e for e in self.events))

    def test_reference_alerts(self):
        ids = [a['rule_id'] for a in analyzer.analyze(self.events)]
        self.assertEqual(ids, [100101, 100110])

    def test_below_threshold(self):
        self.assertFalse(any(a['rule_id'] == 100101 for a in analyzer.analyze(self.events[:4])))

    def test_unrelated_logs_are_ignored(self):
        altered = [dict(e, lab='other') for e in self.events]
        self.assertEqual(analyzer.analyze(altered), [])

if __name__ == '__main__':
    unittest.main()
