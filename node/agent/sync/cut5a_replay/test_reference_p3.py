import copy
import json
import struct
import unittest
from pathlib import Path

from compare import compare, validate_records
from generate_p3_scenarios import build, rule
from reference_p3 import State, allow_table, condition_wire, key, rule_wire, response_projection
from check_i12a import check as check_i12a


class Cut53ReferenceTests(unittest.TestCase):
    def test_fix1_closed_code_and_response_order(self):
        scenes = {s["Name"]: s for s in build()}
        record = State(3, 1, 0).run(scenes["I14_publish_lookup_failure"])
        self.assertEqual(record["I14_publish_lookup_failure/add"]["body"]["code"], "internal_error")
        raw = [{"id": "tcp", "reason": "condition field ttl is not supported yet"},
               {"id": "icmp", "reason": "condition field icmp_type is not supported yet"}]
        self.assertEqual(response_projection(raw), [raw[1], raw[0]])
        self.assertEqual(raw[0]["id"], "tcp")  # normalization must not reorder requests
        record = State(2, 1, 0).run(scenes["J3_six_attributes"])
        self.assertEqual(record["J3_six_attributes/full"]["body"]["rejected"], [raw[1], raw[0]])

    def test_fix1_future_stamp_and_first_bucket_capacity(self):
        scene = next(s for s in build() if s["Authority"] == "I12a")
        for cpus, cpu in ((1, 0), (4, 2)):
            touched = [i == cpu for i in range(cpus)]
            for protocol in (2, 3):
                records = State(protocol, cpus, cpu).run(scene)
                seed, move = [records[scene["Name"]+"/"+step] for step in ("seed", "move")]
                table = "rl_states" if protocol == 2 else "id_rl_states"
                old_key = key(rule(dst_port=80)) if protocol == 2 else "11000000"
                self.assertEqual(seed["packets"][0]["last_update_changed"], {table+"/"+old_key: touched})
                self.assertEqual(seed["maps_after_packets"][table][old_key]["tokens"], [0]*cpus)
                if protocol == 2:
                    tokens = [0]*cpus
                    tokens[cpu] = 1  # ceil(2*rate/divisor)-1, rate=divisor=1
                    bucket = move["maps_after_packets"][table][key(rule())]
                    self.assertEqual(bucket, {"tokens": tokens, "last_update_present": touched})
                    self.assertEqual(move["maps_after_packets"][table][old_key], seed["maps_after_packets"][table][old_key])
                else:
                    self.assertEqual(check_i12a(records, cpus, cpu), 34)

    def test_i12a_checker_kills_continuity_mutations(self):
        # These controls exercise the independent record checker, not its oracle.
        scene = next(s for s in build() if s["Authority"] == "I12a")
        records = State(3, 4, 2).run(scene)
        path = "I12a_rate_survives_key_move/move"
        mutants = [
            ("full retains counts", lambda r: r[path]["maps_before_packets"]["id_counts"].clear()),
            ("full retains bucket", lambda r: r[path]["maps_before_packets"]["id_rl_states"].clear()),
            ("exhausted logical bucket drops", lambda r: r[path]["packets"][0].update(verdict=2)),
            ("logical counter delta", lambda r: r[path]["packets"][0].update(counter_delta={})),
            ("legacy tuple bucket absent", lambda r: r[path]["maps_after_packets"]["rl_states"].update(stale={})),
            ("exhausted tokens preserved", lambda r: r[path]["maps_after_packets"]["id_rl_states"]["11000000"]["tokens"].__setitem__(2, 1)),
        ]
        for message, mutate in mutants:
            with self.subTest(message=message):
                mutant = copy.deepcopy(records)
                mutate(mutant)
                with self.assertRaisesRegex(ValueError, message):
                    check_i12a(mutant, 4, 2)

    def test_rate_refill_rounds_timestamp_up(self):
        state = State(3, 1, 0)
        state.maps["config_a"]["0b000000"] = "0200000000000000"
        state.maps["id_rl_states"]["11000000"] = {"tokens": [0], "last_update_present": [True]}
        state.rate_times["id_rl_states", "11000000"] = [9_000_000_000]
        state.now_ns = 10_000_000_000
        self.assertTrue(state.rate_take("id_rl_states", "11000000", 3))
        self.assertEqual(state.rate_times["id_rl_states", "11000000"], [9_666_666_667])
        state.now_ns = 10_333_333_333
        self.assertFalse(state.rate_take("id_rl_states", "11000000", 3))
        self.assertEqual(state.maps["id_rl_states"]["11000000"]["tokens"], [0])

    def test_script_is_reproducible_and_complete(self):
        scenes = build()
        self.assertEqual(scenes, json.loads(Path(__file__).with_name("scenarios_p3.json").read_text()))
        self.assertEqual((len(scenes), sum(len(s["Steps"]) for s in scenes),
                          sum(len(x["Packets"]) for s in scenes for x in s["Steps"])), (24, 41, 70))
        self.assertEqual({s["Authority"] for s in scenes}, {
            "unchanged", "J1", "J2", "J3", "J4", "J5", "I6", "I7", "I8", "I9",
            "I11a", "I12a", "I13", "I14", "I17a", "I19"})

    def test_literal_wire_offsets(self):
        r = rule(tcp_flags="SYN,!ACK", pkt_len_min=36, pkt_len_max=100)
        self.assertEqual(key(r), "00000000000000000000ffffc0000201"
                         "00000000000000000000000000000000" "00000000" "06000000")
        legacy = bytes.fromhex(rule_wire(r))
        self.assertEqual(legacy[:8], bytes([1, 18, 2, 0, 0, 0, 0, 0]))
        self.assertEqual(legacy[24:], bytes([36, 0, 100, 0, 0, 0, 0, 0]))
        flagged = bytes.fromhex(rule_wire(r, True))
        self.assertEqual(flagged, bytes([1])+bytes(27)+bytes([1, 0, 0, 0]))
        row = bytes.fromhex(condition_wire([r]))
        self.assertEqual(len(row), 844)
        self.assertEqual(row[:128], bytes([0x11])*128)
        self.assertEqual(row[128:256], bytes([0x11])*32+bytes(96))
        self.assertEqual(row[256+1]&15, 1)  # SYN
        self.assertEqual(row[256+9]&15, 0)  # SYN|ACK
        self.assertEqual(row[768:772], bytes([0x11])*4)
        self.assertEqual(row[772:780], struct.pack("<HHHH", 36, 100, 1, 0))
        self.assertEqual(row[804:808], bytes([1, 0, 0, 0]))
        self.assertEqual(row[824:840], struct.pack("<IIII", 17, 0, 0, 0))
        self.assertEqual(row[840:], bytes([1, 0, 1, 0]))

    def test_literal_behavior_witnesses(self):
        cases = {s["Name"]: s for s in build()}
        expected = {
            "J1_more_specific_candidate": ([1, 2], [1, 2]),
            "J2_exact_anomaly_over_cidr": ([1, 1], [1, 1]),
            "J3_six_attributes": ([2, 2, 2], [1, 1, 2]),
            "J3_anomaly04": ([2, 2], [1, 2]),
            "J3_anomaly08": ([2, 2], [1, 2]),
            "J4_RT_dispatch_model": ([2, 2], [1, 2]),
            "J5_zero_member": ([1, 2], [2, 2]),
            "I8_same_key_members": ([2, 2], [1, 2]),
            "I14_publish_lookup_failure": ([1], [2]),
            "I19_normalizes_input": ([2, 2], [1, 2]),
        }
        for name, pair in expected.items():
            for proto, want in zip((2, 3), pair):
                record = next(iter(State(proto, 1, 0).run(cases[name]).values()))
                self.assertEqual([p["verdict"] for p in record["packets"]], want, (name, proto))
        for proto, want in ((2, 2), (3, 1)):
            record = State(proto, 4, 2).run(cases["I12a_rate_survives_key_move"])
            self.assertEqual(record["I12a_rate_survives_key_move/seed"]["packets"][0]["verdict"], 1)
            self.assertEqual(record["I12a_rate_survives_key_move/move"]["packets"][0]["verdict"], want)
            moved = record["I12a_rate_survives_key_move/move"]
            if proto == 2:
                old_key = key(rule(tcp_flags="SYN", dst_port=80))
                self.assertIn(old_key, moved["maps_before_packets"]["rl_states"])
                self.assertEqual(len(moved["maps_after_packets"]["rl_states"]), 2)
            else:
                self.assertEqual(moved["maps_after_packets"]["rl_states"], {})
        record = State(3, 1, 0).run(cases["J1_more_specific_candidate"])
        self.assertEqual(record["J1_more_specific_candidate/full"]["packets"][0]["counter_delta"],
                         {"id_counts/12000000/match": 1, "id_counts/12000000/drop": 1})

    def test_finite_table_and_comparator_controls(self):
        scenes = [s for s in build() if s["Authority"] != "unchanged"]
        for cpus, packet_cpu in ((1, 0), (4, 2)):
            old, new = {}, {}
            for s in scenes:
                old.update(State(2, cpus, packet_cpu).run(s))
                new.update(State(3, cpus, packet_cpu).run(s))
            validate_records(old, scenes)
            validate_records(new, scenes)
            table = allow_table(cpus, packet_cpu)
            accepted, rejected = compare(old, new, table)
            self.assertEqual(rejected, [])  # model/comparator plumbing only
            self.assertEqual(len(accepted), len(table))
            self.assertEqual(compare(new, copy.deepcopy(new), []), ([], []))
            mutant = copy.deepcopy(new)
            mutant["J1_more_specific_candidate/full"]["packets"][0]["verdict"] = 2
            rejected = compare(old, mutant, table)[1]
            self.assertEqual(rejected[0]["field"], ["J1_more_specific_candidate/full", "packets", 0, "verdict"])
            if cpus == 1:
                self.assertEqual(table, json.loads(Path(__file__).with_name("allowed_p3.json").read_text()))


if __name__ == "__main__":
    unittest.main()
