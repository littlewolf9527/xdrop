#!/usr/bin/env python3
"""Independent I12a witness on real replay records; no reference-model import."""
import argparse
import json
from pathlib import Path


def check(records, cpus, packet_cpu):
    if not 0 <= packet_cpu < cpus:
        raise ValueError("I12a packet CPU outside topology")
    seed = records["I12a_rate_survives_key_move/seed"]
    move = records["I12a_rate_survives_key_move/move"]
    logical = "11000000"  # scripted logical ID 17, little-endian uint32
    zero = [0]*cpus
    touched = [i == packet_cpu for i in range(cpus)]
    bucket = {"tokens": zero, "last_update_present": [True]*cpus}
    checks = 0

    def equal(got, want, label):
        nonlocal checks
        if got != want:
            raise ValueError("I12a "+label+": got="+repr(got)+" want="+repr(want))
        checks += 1

    for stage, row in (("seed", seed), ("move", move)):
        equal(row["status"], 200, stage+" full accepted")
        equal(row["body"]["added"], 1, stage+" member installed")
        equal(len(row["packets"]), 1, stage+" one packet")
        packet = row["packets"][0]
        equal(packet["verdict"], 1, stage+" exhausted logical bucket drops")
        equal(packet["counter_delta"], {"id_counts/"+logical+"/match": 1,
              "id_counts/"+logical+"/drop": 1}, stage+" logical counter delta")
        equal(packet["last_update_changed"], {"id_rl_states/"+logical:
              touched if stage == "seed" else [False]*cpus}, stage+" timestamp relation")
        for moment in ("maps_before_packets", "maps_after_packets"):
            for table in ("rl_states", "cidr_rl_states"):
                equal(row[moment][table], {}, stage+" legacy tuple bucket absent "+moment+"/"+table)
        equal(row["maps_after_packets"]["id_rl_states"], {logical: bucket}, stage+" exhausted tokens preserved")
    equal(seed["rate_initial"]["id_rl_states"], {logical: bucket}, "explicit empty rate seed")
    equal(seed["maps_after_packets"]["id_counts"], {logical: [1, 1]}, "seed logical counts")
    equal(move["maps_before_packets"]["id_rl_states"], seed["maps_after_packets"]["id_rl_states"], "full retains bucket")
    equal(move["maps_before_packets"]["id_counts"], {logical: [1, 1]}, "full retains counts")
    equal(move["maps_after_packets"]["id_counts"], {logical: [2, 2]}, "counts continue after key move")
    # Check the installed key really moved while the row remains conditional.
    keys = []
    for row in (seed, move):
        maps = row["maps_before_packets"]
        installed = dict(maps["blacklist"], **maps["blacklist_b"])
        equal(len(installed), 1, "one exact row")
        key, value = next(iter(installed.items()))
        equal(bytes.fromhex(value)[28], 1, "conditional row flag")
        keys.append(bytes.fromhex(key))
    equal(keys[0][34:36], bytes([0, 80]), "seed port 80")
    equal(keys[1][34:36], bytes(2), "moved wildcard port")
    equal(keys[0][:34]+keys[0][36:], keys[1][:34]+keys[1][36:], "only key port moved")
    return checks


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("records")
    parser.add_argument("--possible-cpus", type=int, required=True)
    parser.add_argument("--packet-cpu", type=int, required=True)
    args = parser.parse_args()
    count = check(json.loads(Path(args.records).read_text()), args.possible_cpus, args.packet_cpu)
    print("CUT53_I12A_INDEPENDENT assertions=%d logical_counts=continued tokens=continued legacy_tuple=absent" % count)
