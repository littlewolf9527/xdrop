#!/usr/bin/env python3
"""Exact field gate. The allow table is input-independent, checked into source.

No scene/name exemption, wildcard, inferred allow entry or tolerance is used.
Missing values are distinct from null, zero, an empty container and empty text.
"""
import argparse
import json
from pathlib import Path

ABSENT = {"$absent": True}
AUTHORITIES = frozenset({
    "I1", "I2", "I3", "I5",  # historical knife-five-alpha replay tables
    "J1", "J2", "J3", "J4", "J5", "I6", "I7", "I8", "I9",
    "I11a", "I12a", "I13", "I14", "I17a", "I19",
    "J8", "J9", "I10", "I11b", "I12b", "I17b", "I15", "I16",
})


def differences(old, new, path=()):
    if type(old) is type(new) and isinstance(old, dict):
        for key in sorted(old.keys() | new.keys()):
            if key not in old or key not in new:
                yield path + (key,), old.get(key, ABSENT), new.get(key, ABSENT)
            else:
                yield from differences(old[key], new[key], path + (key,))
    elif type(old) is type(new) and isinstance(old, list):
        for i in range(max(len(old), len(new))):
            if i >= len(old) or i >= len(new):
                yield path + (i,), old[i] if i < len(old) else ABSENT, new[i] if i < len(new) else ABSENT
            else:
                yield from differences(old[i], new[i], path + (i,))
    elif type(old) is not type(new) or old != new:
        yield path, old, new


# = HEAD driver cut5ReplayMaps call sites; exact names, never a prefix match.
CUT55_MAP_SNAPSHOTS = frozenset({
    "maps_after_clear", "maps_before_packets", "rate_initial", "maps_after_packets",
})
CUT55_RULE_TABLES = frozenset({
    "blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b",
    "cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b",
})

def validate_cut55_authority(entry, old, new):
    token=entry["authority"].split(maxsplit=1)[0]
    field=entry["field"]
    if token=="I15" and field!=["body","sync_protocol"]:
        raise ValueError("I15 cross-tree allowance is only the protocol number")
    if token!="I16":return
    if len(field)<2 or field[0] not in CUT55_MAP_SNAPSHOTS or field[1] not in CUT55_RULE_TABLES:
        raise ValueError("I16 must be in an exact map snapshot and rule/condition table")
    for records in (old,new):
        maps=records[entry["case"]][field[0]]
        config=int.from_bytes(bytes.fromhex(maps["active_config"]["00000000"]),"little")
        slot=int.from_bytes(bytes.fromhex(maps[("config_a","config_b")[config]]["09000000"]),"little")
        shadows=(("blacklist_b","cidr_blist_b","cond_b","cidr_cond_b"),
                 ("blacklist","cidr_blacklist","cond_a","cidr_cond_a"))[slot]
        if field[1] not in shadows:raise ValueError("I16 cannot permit active maps or verdict state")



def validate_cut56_authority(entry, old, new):
    if entry["authority"].split(maxsplit=1)[0] != "J8":
        return
    case, field = entry["case"], entry["field"]
    if not case.startswith("J8_"):
        raise ValueError("J8 allowance must belong to a J8 scenario case")
    if case.startswith("J8_rejected_"):
        message = (field == ["body", "error"] or
                   (len(field) == 4 and field[0] == "body" and
                    type(field[2]) is int and field[2] >= 0 and
                    ((field[1] == "conflicts" and field[3] == "reason") or
                     (field[1] == "groups" and field[3] == "error"))))
        if not message or not isinstance(entry["old"], str) or not isinstance(entry["new"], str):
            raise ValueError("J8 still-rejected allowance must be a body error-text field")


def compare(old, new, table):
    allowed = {}
    for entry in table:
        key = (entry["case"], *entry["field"])
        if key in allowed or entry["authority"].split(maxsplit=1)[0] not in AUTHORITIES:
            raise ValueError("duplicate or unauthorized allow entry")
        validate_cut55_authority(entry, old, new)
        validate_cut56_authority(entry, old, new)
        allowed[key] = entry
    accepted, rejected, seen = [], [], set()
    for path, a, b in differences(old, new):
        row = {"field": list(path), "old": a, "new": b}
        permit = allowed.get(path)
        if permit and type(a) is type(permit["old"]) and type(b) is type(permit["new"]) and a == permit["old"] and b == permit["new"]:
            row["authority"] = permit["authority"]
            accepted.append(row)
            seen.add(path)
        else:
            rejected.append(row)
    # Every expected positive-control field must actually be exercised.
    for path in allowed.keys() - seen:
        rejected.append({"field": list(path), "error": "expected allowed difference was not observed"})
    rejected.sort(key=lambda row: (not ("packets" in row["field"] and row["field"][-1] == "verdict"), repr(row["field"])))
    return accepted, rejected


def validate_records(records, scenes):
    expected = {s["Name"] + "/" + step["Name"]: step for s in scenes for step in s["Steps"]}
    if records.keys() != expected.keys():
        raise ValueError("recorded request set differs from the scenario script")
    for key, step in expected.items():
        record = records[key]
        if step["Method"] == "STARTUP_FAILURE":
            if set(record) != {"startup_refused"} or type(record["startup_refused"]) is not bool:
                raise ValueError("invalid startup refusal record")
            continue
        if step["Method"] == "STARTUP_CLEAR_FAILURE":
            if set(record) != {"startup_refused", "maps_after_clear"} or type(record["startup_refused"]) is not bool or not isinstance(record["maps_after_clear"], dict):
                raise ValueError("invalid startup clear refusal/readback record")
            continue
        for field in ("installed", "maps_before_packets", "maps_after_packets", "packets"):
            if field not in record:
                raise ValueError(f"missing {key}/{field}")
        if step["Method"] == "RESTART":
            if record.get("startup_success") is not True:
                raise ValueError("real startup pull did not complete")
        elif type(record.get("status")) is not int or not isinstance(record.get("body"), dict):
            raise ValueError("invalid HTTP response record")
        if [p["packet"] for p in record["packets"]] != step["Packets"]:
            raise ValueError("recorded packet sequence differs from script")
        for p in record["packets"]:
            if type(p["verdict"]) is not int or not isinstance(p["counter_delta"], dict) or not isinstance(p["last_update_changed"], dict):
                raise ValueError("incomplete packet record")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("old")
    parser.add_argument("new")
    parser.add_argument("--mode", choices=["identical", "allowed"], required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--scenarios", default=str(Path(__file__).with_name("scenarios.json")))
    parser.add_argument("--allowed", default=str(Path(__file__).with_name("allowed.json")))
    args = parser.parse_args()
    old, new = [json.loads(Path(p).read_text()) for p in (args.old, args.new)]
    scenes = json.loads(Path(args.scenarios).read_text())
    validate_records(old, scenes)
    validate_records(new, scenes)
    table = json.loads(Path(args.allowed).read_text()) if args.mode == "allowed" else []
    accepted, rejected = compare(old, new, table)
    Path(args.report).write_text(json.dumps({"accepted": accepted, "rejected": rejected}, indent=2) + "\n")
    for row in rejected:
        tag = "VERDICT_DIFFERENCE" if "packets" in row["field"] and row["field"][-1] == "verdict" else "FIELD_DIFFERENCE"
        print(tag, json.dumps(row, sort_keys=True))
    print(f"B1_CUT5A_DIFF mode={args.mode} accepted={len(accepted)} rejected={len(rejected)} records={len(old)}")
    return int(bool(rejected))


if __name__ == "__main__":
    raise SystemExit(main())
