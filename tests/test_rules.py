import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

RULES = Path(__file__).resolve().parents[1] / 'rules/soc_lab_rules.xml'

class RuleStructureTests(unittest.TestCase):
    def test_xml_parses(self):
        root = ET.parse(RULES).getroot()
        self.assertEqual(root.tag, 'group')

    def test_custom_id_range_unique(self):
        root = ET.parse(RULES).getroot()
        ids = [int(e.attrib['id']) for e in root.findall('rule')]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(100000 <= i <= 120000 for i in ids))
        self.assertEqual(ids, [100100, 100101, 100110])

if __name__ == '__main__':
    unittest.main()
