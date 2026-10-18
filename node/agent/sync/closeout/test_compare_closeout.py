import copy
import unittest
from compare_closeout import compare, cpu_sum, differences, response, COUNTERS


class CompareTests(unittest.TestCase):
    def test_drop_pps_only(self):
        a = {'s': {'installed': {'count': 1, 'rules': [{'id': 'r', 'stats': {'match_count': 4, 'drop_count': 3, 'drop_pps': 1.5}}]}}}
        b = copy.deepcopy(a)
        b['s']['installed']['rules'][0]['stats']['drop_pps'] = 2.0
        self.assertEqual(compare(a, b), [])
        for field in ('match_count', 'drop_count'):
            c = copy.deepcopy(b)
            c['s']['installed']['rules'][0]['stats'][field] += 1
            self.assertEqual(len(compare(a, c)), 1)

    def test_only_collections_sorted(self):
        rows = [{'id': 'b'}, {'id': 'a'}]
        self.assertEqual(response('/api/v1/rules', {'rules': rows})['rules'], rows)
        self.assertEqual(response('/api/v1/whitelist', {'entries': rows})['entries'], rows[::-1])
        for path in ('/api/v1/rules?page=1', '/api/v1/rules/batch', '/api/v1/sync/atomic'):
            self.assertEqual(response(path, {'rules': rows, 'results': rows, 'rejected': rows}), {'rules': rows, 'results': rows, 'rejected': rows})

    def test_duplicate_retained(self):
        a = response('/api/v1/rules', {'count': 2, 'rules': [{'id': 'a'}, {'id': 'a'}]})
        b = response('/api/v1/rules', {'count': 1, 'rules': [{'id': 'a'}]})
        self.assertEqual(len(list(differences(a, b))), 2)

    def test_unknown_fields_and_order(self):
        for key in ('timestamp', 'last_updated', 'created_at', 'updated_at', 'stats'):
            self.assertEqual(response('/api/v1/rules/commit', {key: 7}), {key: 7})
        self.assertTrue(list(differences([{'id': 'b'}, {'id': 'a'}], [{'id': 'a'}, {'id': 'b'}])))

    def test_types_and_missing(self):
        self.assertTrue(list(differences(True, 1)))
        self.assertTrue(list(differences({'x': None}, {})))
        self.assertTrue(list(differences([], None)))

    def test_cpu_quiescent_sum(self):
        stats = dict.fromkeys(COUNTERS, 3)
        cpu = {'per_cpu': [dict(cpu=0, **dict.fromkeys(COUNTERS, 1)), dict(cpu=1, **dict.fromkeys(COUNTERS, 2))]}
        cpu_sum(stats, cpu)
        cpu['per_cpu'][0]['dropped_packets'] = 4
        with self.assertRaises(AssertionError):
            cpu_sum(stats, cpu)

    def test_s7_requires_proof(self):
        a = {'s': {'family': 'S7', 'legal_serial_pass': True, 'ij': [1, 2], 'terminal': ['a']}}
        b = {'s': {'family': 'S7', 'legal_serial_pass': True, 'ij': [2, 1], 'terminal': ['b']}}
        self.assertEqual(compare(a, b), [])
        b['s']['legal_serial_pass'] = False
        with self.assertRaises(AssertionError):
            compare(a, b)

    def test_excluded_fields_recorded(self):
        removed = {}
        result = response('/api/v1/stats', {'passed_pps': 2.4, 'total_packets': 9, 'system': {'cpu_percent': 5.0, 'new_field': 7}}, removed)
        self.assertEqual(removed, {'passed_pps': 2.4, 'system.cpu_percent': 5.0})
        self.assertEqual(result, {'total_packets': 9, 'system': {'new_field': 7}})


if __name__ == '__main__':
    unittest.main()
