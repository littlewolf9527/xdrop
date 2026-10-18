#!/usr/bin/env python3
"""Actual B1 AST generation controls, with isolated mutation/restoration."""
from pathlib import Path
import shutil
import tempfile
import unittest
import s2b_c_replay as c

ROOT=Path(__file__).resolve().parents[3]

class B1Contract(unittest.TestCase):
    def test_complete_generation_and_targeted_reds(self):
        with tempfile.TemporaryDirectory(prefix='b1-contract-') as tmp:
            root=Path(tmp)/'source'
            for n in ('xdrop_main.c','xdrop.h','combo_masks.h','headers/bpf_helpers.h'):
                p=root/'node/bpf'/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/'node/bpf'/n,p)
            path=root/'node/bpf/xdrop_main.c';original=path.read_bytes();text=original.decode()
            c.check_source(root,Path(tmp)/'positive');_,defs,_,_=c.extract(root,Path(tmp)/'signatures')
            self.assertEqual(c.interface_generation(defs),'b1cut54')
            trials=[
                ('half-group',text.replace('struct pkt_attrs *attrs,','const struct pkt_attrs *attrs,',1),'C interface mixed generations'),
                ('wrong-bit',text.replace('rule->pad2[0] & RULE_HAS_CONDITIONS','rule->pad2[1] & RULE_HAS_CONDITIONS',1),'C B1 condition lookup/output/fallback contract'),
                ('wrong-table',text.replace('COND_LOOKUP(rule_sel, matched_key)','COND_LOOKUP(1-rule_sel, matched_key)',1),'C B1 condition lookup/output/fallback contract'),
                ('no-stop',text.replace('if (cv && cond_match(cv, attrs) >= 0)\n        break;','if (cv && cond_match(cv, attrs) >= 0)\n        continue;',1),'C B1 condition lookup/output/fallback contract'),
            ]
            for name,mut,red in trials:
                with self.subTest(name=name):
                    self.assertNotEqual(mut,text)
                    try:
                        path.write_text(mut)
                        with self.assertRaisesRegex(c.ReplayError,red):c.check_source(root,Path(tmp)/name)
                    finally:path.write_bytes(original)
                    self.assertEqual(path.read_bytes(),original)
            print('B1_AST generation=b1cut54 signatures=2 rejected=4 restored=4')

if __name__=='__main__':unittest.main()
