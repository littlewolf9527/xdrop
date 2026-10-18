#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import unittest

from reference_closeout import State


class FamilyOrderTests(unittest.TestCase):
    def test_protocol9_precedence_matrix(self):
        cases = json.loads((Path(__file__).with_name('precedence_p9.json')).read_text())
        cases = [c for c in cases if c['position'] != 'unspecified']
        self.assertEqual(len(cases), 76)
        for cell in cases:
            with self.subTest(name=cell['name']):
                actual = list(State().request(copy.deepcopy(cell['request'])))
                self.assertEqual(actual, cell['go'])
                if cell['position'] == 'before':
                    self.assertEqual(actual, list(State().request(copy.deepcopy(cell['control']))))
                print('AF_MODEL_PRECEDENCE case='+cell['name']+' class='+cell['position']+' pass=1')

    def test_protocol9_unspecified_anomaly_target(self):
        cases = json.loads((Path(__file__).with_name('precedence_p9.json')).read_text())
        cases = [c for c in cases if c['position'] == 'unspecified']
        self.assertEqual(len(cases), 32)
        for cell in cases:
            with self.subTest(name=cell['name']):
                command = copy.deepcopy(cell['request'])
                actual = list(State().request(command))
                if 'model_baseline' in cell:  # Existing 5d1b164 boundary, not model == Go.
                    self.assertEqual(cell['go'][0], 200)
                    self.assertEqual(cell['go'][1]['code'], 'committed')
                    self.assertEqual(actual, cell['model_baseline'])
                    self.assertNotEqual(actual, cell['go'])
                else:
                    self.assertEqual(actual, cell['go'])
                self.assertEqual(command, cell['request'])
                print('AF_MODEL_UNSPECIFIED case='+cell['name']+' pass=1')


if __name__ == '__main__':
    unittest.main()
