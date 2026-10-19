#!/usr/bin/env python3
"""Host-only source-boundary controls; these do not load a BPF program."""
import contextlib
import hashlib
import io
from pathlib import Path
import tempfile
import subprocess
import unittest

import b1_extract_probe as probe

ROOT = Path(__file__).resolve().parents[3]


class B1ExtractBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='b1-extract-boundary-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = (ROOT/'node/bpf/xdrop_main.c').read_bytes()
        self.path = self.root/'node/bpf/xdrop_main.c'
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(self.source)

    def generate(self, name):
        output = self.root/name
        with contextlib.redirect_stdout(io.StringIO()):
            probe.generate(self.root, output)
        return (output/'extract.c').read_bytes()

    def test_green_unchanged_probe(self):
        # Registered before this guard was added; the repair must not change
        # the C exercised by the saved extraction evidence.
        self.assertEqual(hashlib.sha256(self.generate('positive')).hexdigest(),
                         'b47929ff96d359df891e681385db82b30bdb62c679dd1e55a8e031f7ae39b744')

    def test_knife_one_frozen_probe(self):
        historical = subprocess.check_output(['git', 'show',
            '552139a:node/bpf/xdrop_main.c'], cwd=ROOT)
        try:
            self.path.write_bytes(historical)
            self.assertEqual(hashlib.sha256(self.generate('knife-one')).hexdigest(),
                             '5eea1a566b0154ad456f7fd32885494696d3c1e2b43faa10eadcc01492cd906e')
        finally:
            self.path.write_bytes(self.source)

    def test_red_writes_in_each_skipped_interval(self):
        positive = self.generate('positive')
        fields = ('pkt_len', 'tcp_flags', 'pkt_anomaly', 'ttl', 'dscp',
                  'icmp_type', 'icmp_code', 'frag_class', 'icmp_valid')
        for variable in ('attrs', 'cidr_attrs'):
            marker = ('struct pkt_attrs '+variable+' = {').encode()
            self.assertIn(marker, self.source)
            writes = [f'{field} = 0;\n' for field in fields]
            writes += ['__u8 *alias = &ttl; *alias = 0;\n']
            for i, write in enumerate(writes):
                with self.subTest(initializer=variable, write=write):
                    output = f'rejected-{variable}-{i}'
                    changed = self.source.replace(marker, write.encode()+marker, 1)
                    self.assertNotEqual(changed, self.source)
                    try:
                        self.path.write_bytes(changed)
                        with self.assertRaisesRegex(ValueError, 'B1 skipped source interval: '+variable):
                            self.generate(output)
                        self.assertFalse((self.root/output/'extract.c').exists())
                    finally:
                        self.path.write_bytes(self.source)
                    self.assertEqual(self.path.read_bytes(), self.source)
                    self.assertEqual(self.generate('restored'), positive)

    def test_red_write_after_extraction_marker(self):
        marker = b'  // Read rule map selector once per packet (dual rule map, Phase 4.2)'
        self.assertEqual(self.source.count(marker), 1)
        self.path.write_bytes(self.source.replace(marker, marker+b'\n  ttl = 0;', 1))
        with self.assertRaisesRegex(ValueError, 'B1 skipped source interval: attrs'):
            self.generate('marker-mutation')


if __name__ == '__main__':
    unittest.main(verbosity=2)
