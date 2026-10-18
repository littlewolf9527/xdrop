import json
import unittest
from pathlib import Path
from compare import ABSENT, AUTHORITIES, compare, differences, validate_records


class GateTests(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(compare({"a": [1, {}, None]}, {"a": [1, {}, None]}, []), ([], []))

    def test_exact_allow_and_positive_control(self):
        row = {"case": "s", "field": ["code"], "old": "old", "new": "new", "authority": "I3 ①"}
        self.assertEqual(len(compare({"s": {"code": "old"}}, {"s": {"code": "new"}}, [row])[0]), 1)
        self.assertTrue(compare({"s": {"code": "old"}}, {"s": {"code": "wrong"}}, [row])[1])
        self.assertTrue(compare({"s": {"code": "old"}}, {"s": {"code": "old"}}, [row])[1])

    def test_missing_is_not_zero_null_or_empty(self):
        for value in [0, None, "", [], {}]:
            self.assertEqual(list(differences({}, {"a": value})), [(("a",), ABSENT, value)])

    def test_verdict_first_and_never_scene_exemption(self):
        a = {"s": {"packets": [{"verdict": 1}], "maps": "old"}}
        b = {"s": {"packets": [{"verdict": 2}], "maps": "new"}}
        _, rejected = compare(a, b, [])
        self.assertEqual(rejected[0]["field"], ["s", "packets", 0, "verdict"])
        self.assertEqual(len(rejected), 2)

    def test_allow_table_is_finite_and_has_no_packet_exemption(self):
        table = json.loads(Path(__file__).with_name("allowed.json").read_text())
        keys = [(r["case"], *r["field"]) for r in table]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(all("packets" not in r["field"] for r in table))
        self.assertTrue(all(r["old"] != r["new"] for r in table))

    def test_missing_scenario_is_red(self):
        with self.assertRaises(ValueError):
            validate_records({}, [{"Name": "s", "Steps": [{"Name": "r"}]}])

    def test_cut53_authority_tokens_are_exact(self):
        for token in AUTHORITIES - {"I15", "I16"}:
            case = "J8_accept_exact/create" if token == "J8" else "s"
            row = {"case": case, "field": ["code"], "old": 1, "new": 2, "authority": token + " explicit field"}
            self.assertEqual(len(compare({case: {"code": 1}}, {case: {"code": 2}}, [row])[0]), 1)
        for token in ("J6", "J8*", "J8x", "J9anything", "I10*", "I11broad", "I12b*", "I17bad", "I100", "I199", "I1anything", "I19*", "I15*", "I16x", "*"):
            row = {"case": "s", "field": ["code"], "old": 1, "new": 2, "authority": token}
            with self.assertRaises(ValueError):
                compare({"s": {"code": 1}}, {"s": {"code": 2}}, [row])

    def test_cut56_j8_rejects_outside_scenario(self):
        a={"historical/create":{"status":200}};b={"historical/create":{"status":201}}
        row=dict(case="historical/create",field=["status"],old=200,new=201,authority="J8 synthetic")
        self.assertEqual(len(compare(a,b,[])[1]),1)
        with self.assertRaisesRegex(ValueError,"J8"):
            compare(a,b,[row])
        print("CUT56_COMPARE_BOUNDARY scenario_escape_red=1")

    def test_cut56_j8_rejected_shape_is_error_text_only(self):
        case="J8_rejected_exact_full/create"
        a={case:{"status":409,"body":{"error":"old"}}}
        b={case:{"status":400,"body":{"error":"old"}}}
        row=dict(case=case,field=["status"],old=409,new=400,authority="J8 synthetic")
        self.assertEqual(len(compare(a,b,[])[1]),1)
        with self.assertRaisesRegex(ValueError,"J8"):
            compare(a,b,[row])
        b={case:{"status":409,"body":{"error":"new"}}}
        row.update(field=["body","error"],old="old",new="new")
        self.assertEqual(compare(a,b,[row])[1],[])
        self.assertEqual(len(compare(a,b,[row])[0]),1)
        print("CUT56_COMPARE_BOUNDARY rejected_shape_red=1 error_text_positive=1")

    def test_cut55_authority_has_structural_bounds(self):
        from reference_p4 import State
        a={"s":{"maps_before_packets":State(5).maps,"packets":[{"verdict":1}],"body":{"sync_protocol":4}}}
        import copy
        b=copy.deepcopy(a);b["s"]["body"]["sync_protocol"]=5
        row={"case":"s","field":["body","sync_protocol"],"old":4,"new":5,"authority":"I15 protocol"}
        self.assertEqual(len(compare(a,b,[row])[0]),1)
        b=copy.deepcopy(a);b["s"]["maps_before_packets"]["blacklist_b"]["key"]="value"
        row={"case":"s","field":["maps_before_packets","blacklist_b","key"],"old":ABSENT,"new":"value","authority":"I16 mirror"}
        self.assertEqual(len(compare(a,b,[row])[0]),1)
        for field in (["packets",0,"verdict"],["body","code"],["installed","count"],["maps_before_packets","blacklist","key"]):
            bad=dict(row,field=field)
            with self.assertRaises(ValueError):compare(a,b,[bad])
        print("CUT55_I16_BOUNDARY shadow_positive=1 packets_red=1 body_red=1 installed_red=1 active_red=1")

    def test_cut55_ruling2_snapshot_boundaries(self):
        import copy
        from reference_p4 import State
        from compare import CUT55_MAP_SNAPSHOTS
        for snapshot in CUT55_MAP_SNAPSHOTS:
            a={"s":{snapshot:State(5).maps}}
            b=copy.deepcopy(a);b["s"][snapshot]["blacklist_b"]["key"]="value"
            row={"case":"s","field":[snapshot,"blacklist_b","key"],"old":ABSENT,"new":"value","authority":"I16 mirror"}
            self.assertEqual(len(compare(a,b,[row])[0]),1)
            for name in ("config_a","config_b","active_config","sv4_cidr_trie","dv4_cidr_trie","sv6_cidr_trie","dv6_cidr_trie","id_counts","id_rl_states","stats"):
                with self.assertRaises(ValueError):compare(a,b,[dict(row,field=[snapshot,name,"key"])])
        a={"s":{"rate_initial":State(5).maps,"packets":[{"verdict":1}]}}
        for field in (["rate_initial","id_rl_states","key"],["packets",0,"verdict"],["status"],["maps_unregistered","blacklist_b","key"]):
            with self.assertRaises(ValueError):compare(a,a,[dict(row,field=field)])
        print("CUT55_RULING2_BOUNDARY snapshots=4 runtime_map_negatives=40 rate_initial_id_rl_states_red=1 packets_red=1")


if __name__ == "__main__":
    unittest.main()
