#!/usr/bin/env python3
"""Finite, reviewable 5-3 request matrix; never consumes replay observations."""
import copy
import json
from pathlib import Path

HERE = Path(__file__).parent


def rule(name="r", logical=17, **fields):
    return dict(id=name, logical_id=logical, src_ip="192.0.2.1", protocol="tcp", action="drop", **fields)


def full(name, rules, p2="success", p3="success", packets=("syn", "miss"), fault=""):
    return dict(Name=name, Method="POST", Path="/api/v1/sync/atomic", Body=dict(rules=rules), ExpectP2=p2, ExpectP3=p3, Packets=list(packets), Fault=fault)


def scene(name, authority, *steps):
    return dict(Name=name, Authority=authority, Steps=list(steps))


def build():
    historical = json.loads((HERE / "scenarios.json").read_text())
    out = [copy.deepcopy(s) for s in historical if s["Name"] in ("pure_exact", "pure_cidr")]
    for s in out:
        s["Authority"] = "unchanged"
    for cidr in (False, True):
        for kind, fields, packets in (
            ("flags", {"tcp_flags": "SYN"}, ["syn", "ack"]),
            ("length", {"pkt_len_min": 36, "pkt_len_max": 100}, ["syn", "length400"]),
            ("anomaly", {"match_anomaly": 2}, ["invalid_tcp", "syn"]),
        ):
            r = rule(**fields)
            if cidr:
                del r["src_ip"]
                r["src_cidr"] = "192.0.2.0/24"
            out.append(scene("I7_legacy_" + ("cidr_" if cidr else "exact_") + kind, "I7",
                full("full", [r], packets=packets),
                dict(Name="single", Method="POST", Path="/api/v1/rules", Body=r, ExpectP2="success", ExpectP3="condition_group_required", Packets=packets, Fault="")))
    out += [
        scene("J1_more_specific_candidate", "J1", full("full", [rule("loose",17,tcp_flags="SYN"),rule("strict",18,tcp_flags="SYN",ttl="64")], p2="partial_rejection")),
        scene("J2_exact_anomaly_over_cidr", "J2", full("full", [dict(id="cidr",logical_id=17,src_cidr="192.0.2.0/24",protocol="tcp",action="drop"),rule("anomaly",18,match_anomaly=2)], packets=["invalid_tcp","syn"])),
        scene("J3_six_attributes", "J3", full("full", [rule("tcp",17,ttl="64",dscp="0",fragment="nofrag",pkt_len="40"),dict(id="icmp",logical_id=18,src_ip="192.0.2.1",protocol="icmp",action="drop",icmp_type="0",icmp_code="0")], p2="partial_rejection", packets=["syn","icmp_zero","miss"])),
        scene("J3_anomaly04", "J3", full("full", [rule(match_anomaly=4)], p2="partial_rejection", packets=["length_mismatch","syn"])),
        scene("J3_anomaly08", "J3", full("full", [rule(match_anomaly=8)], p2="partial_rejection", packets=["offset_one","syn"])),
        scene("J4_RT_dispatch_model", "J4", full("full", [rule(match_anomaly=2)], packets=["invalid_tcp","syn"], fault="rt_no_tail")),
        # The script gives a nonzero identity. This explicit node-boundary fault
        # injects the invalid zero ID required by J5, after fixture construction.
        scene("J5_zero_member", "J5", full("full", [rule(tcp_flags="SYN")], p3="condition_group_invalid", fault="zero_logical_id")),
        scene("I6_five_candidates", "I6", full("full", [rule("member-"+str(i),i) for i in range(1,6)], p2="duplicate_key", p3="condition_group_invalid")),
        scene("I8_same_key_members", "I8", full("full", [rule("first",17),rule("second",18)], p2="duplicate_key")),
        scene("I9_protocol", "I9", dict(Name="welcome",Method="GET",Path="/",Body=None,ExpectP2="welcome",ExpectP3="welcome",Packets=[],Fault="")),
        scene("I11a_count_survives_key_move", "I11a", full("seed",[rule(tcp_flags="SYN",dst_port=80)],packets=["syn"]),full("move",[rule(tcp_flags="SYN")],packets=["syn"])),
        scene("I12a_rate_survives_key_move", "I12a", full("seed",[dict(rule(tcp_flags="SYN",dst_port=80),action="rate_limit",rate_limit=1)],packets=["rate"]),full("move",[dict(rule(tcp_flags="SYN"),action="rate_limit",rate_limit=1)],packets=["syn"])),
        scene("I13_startup_refuses_clear_failure", "I13", dict(Name="startup",Method="STARTUP_CLEAR_FAILURE",Packets=[])),
        scene("I14_publish_lookup_failure", "I14", dict(Name="add",Method="POST",Path="/api/v1/rules",Body=rule(),ExpectP2="success",ExpectP3="publish_failure",Packets=["syn"],Fault="active_config_lookup")),
        scene("I17a_logical_capacity", "I17a", full("seed",[rule("old",17)],packets=[]),full("full",[dict(rule("next",18,tcp_flags="SYN"),src_ip="192.0.2.2")],p3="table_full",fault="capacity_one")),
        scene("I19_normalizes_input", "I19", full("full",[rule(ttl="128, 64",tcp_flags="SYN,!ACK")],p2="partial_rejection",packets=["syn","ack"])),
    ]
    for s in out:
        for step in s["Steps"]:
            body = step.get("Body")
            rules = body.get("rules", [body]) if isinstance(body, dict) else []
            for r in rules:
                if "id" in r and (not r["id"] or not r.get("logical_id")):
                    raise ValueError("all scripted rule identities must be nonzero")
    return out


if __name__ == "__main__":
    scenes = build()
    (HERE / "scenarios_p3.json").write_text(json.dumps(scenes, indent=2) + "\n")
    print("CUT53_REPLAY_SCENARIOS scenes=%d steps=%d packets=%d" % (len(scenes), sum(len(s["Steps"]) for s in scenes), sum(len(v["Packets"]) for s in scenes for v in s["Steps"])))
