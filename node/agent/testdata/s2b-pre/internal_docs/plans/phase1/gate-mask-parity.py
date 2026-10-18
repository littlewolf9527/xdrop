#!/usr/bin/env python3
"""S1-5: fail-closed whitelist order, masks and field-source parity.

AUTH is the independent F-067 baseline, never regenerated from the tested tree.
--ck writes only a violation count to stdout; the complete input identity and
numbered criterion failures are one JSON record on stderr. Callers must check
both the process status and the count, and compare input identity themselves.
"""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

BASELINE = "bd686710e3fd9fbb54bf889b2cc1d197873af906"
FIELDS = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
AUTH = {
    "src_ip": 0x0000000261E66F01,
    "dst_ip": 0x00000003E670341F,
    "src_port": 0x00000003FF868043,
    "dst_port": 0x0000000399F15887,
    "protocol": 0x000000015555E22F,
}
DEAD = {20, 32}
EXPECTED = set(range(34)) - {19} - DEAD
# Independent names/IDs frozen from 126b4cb xdrop.h (not the tested root).
HISTORICAL_ROSTER = {'COMBO_EXACT_5TUPLE': 0,
 'COMBO_WILDCARD_SRC_IP': 1,
 'COMBO_WILDCARD_SRC_IP_PORT': 2,
 'COMBO_DST_IP_PROTO': 3,
 'COMBO_DST_IP_ONLY': 4,
 'COMBO_PROTO_ONLY': 5,
 'COMBO_SRC_PORT_ONLY': 6,
 'COMBO_DST_PORT_ONLY': 7,
 'COMBO_SRC_IP_ONLY': 8,
 'COMBO_SRC_IP_PROTO': 9,
 'COMBO_SRC_DST_IP': 10,
 'COMBO_SRC_IP_DST_PORT': 11,
 'COMBO_DST_IP_DST_PORT': 12,
 'COMBO_SRC_DST_IP_PROTO': 13,
 'COMBO_SRC_IP_DST_PORT_PROTO': 14,
 'COMBO_SRC_PORT_PROTO': 15,
 'COMBO_DST_PORT_PROTO': 16,
 'COMBO_SRC_IP_SRC_PORT': 17,
 'COMBO_SRC_IP_SRC_PORT_PROTO': 18,
 'COMBO_DST_IP_DST_PORT_PROTO': 20,
 'COMBO_SRC_DST_IP_DST_PORT': 21,
 'COMBO_SRC_DST_IP_DST_PORT_PROTO': 22,
 'COMBO_SRC_IP_PORTS': 23,
 'COMBO_SRC_IP_PORTS_PROTO': 24,
 'COMBO_DST_IP_SRC_PORT': 25,
 'COMBO_DST_IP_SRC_PORT_PROTO': 26,
 'COMBO_PORTS_ONLY': 27,
 'COMBO_PORTS_PROTO': 28,
 'COMBO_SRC_DST_IP_SRC_PORT': 29,
 'COMBO_SRC_DST_IP_SRC_PORT_PROTO': 30,
 'COMBO_DST_IP_PORTS': 31,
 'COMBO_DST_IP_PORTS_PROTO': 32,
 'COMBO_ALL_EXCEPT_PROTO': 33}
CONTRACTS = {"pre-s2a": set(range(34)) - {19}, "s2a": EXPECTED}
INPUTS = ("node/bpf/xdrop.h", "node/bpf/combo_masks.h", "node/bpf/xdrop_gate.c")


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def check(root, contract):
    report = {"authority_baseline": BASELINE, "contract": contract, "root": str(root),
              "inputs": {}, "call_count": 0, "order": [], "errors": []}

    def fail(criterion, detail):
        report["errors"].append({"criterion": criterion, "detail": detail})

    def read(relative):
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError(f"input escapes root: {relative} -> {path}")
        data = path.read_bytes()
        report["inputs"][relative] = {"path": str(path),
                                             "sha256": hashlib.sha256(data).hexdigest()}
        return strip_comments(data.decode("utf-8"))

    try:
        if contract not in CONTRACTS:
            raise ValueError("explicit known combo contract required")
        active = CONTRACTS[contract]
        hdr, masks, gate = (read(p) for p in INPUTS)
        hdr = re.sub(r"\\\r?\n[ \t]*", " ", hdr)
        defines = re.findall(r"^\s*#define\s+(COMBO_[A-Z0-9_]+)\s+(\d+)\s*$", hdr, re.M)
        if len(re.findall(r"^\s*#define\s+COMBO_", hdr, re.M)) != len(defines):
            raise ValueError("unknown COMBO definition syntax")
        names = [name for name, _ in defines]
        if len(names) != len(set(names)):
            raise ValueError("duplicate COMBO symbol in xdrop.h")
        numbers = {name: int(number) for name, number in defines}
        roster = [n for name, n in numbers.items() if name != "COMBO_MAX"]
        wanted_roster = {name: n for name, n in HISTORICAL_ROSTER.items() if n in active}
        if numbers != dict(wanted_roster, COMBO_MAX=34) or len(roster) != len(active) or set(roster) != active:
            raise ValueError(f"xdrop.h roster differs from explicit {contract} contract")

        # Independently compare fixed AUTH against the generated baseline header.
        tables = re.findall(r"static\s+const\s+__u8\s+combo_field_mask\[\]\s*=\s*\{([^}]+)\}\s*;", masks, re.S)
        bitmaps = re.findall(r"^#define\s+COMBO_VALID_BITMAP\s+(0x[0-9A-Fa-f]+)ULL\s*$", masks, re.M)
        if len(tables) != 1 or len(bitmaps) != 1 or int(bitmaps[0], 16) != sum(1 << n for n in active):
            raise ValueError("missing or invalid combo table / valid bitmap")
        constants = {}
        for symbol, bit in re.findall(r"^#define\s+(CM_\w+)\s+\(1u << (\d+)\)\s*$", masks, re.M):
            if symbol in constants:
                raise ValueError(f"duplicate mask constant: {symbol}")
            constants[symbol] = 1 << int(bit)
        expected_constants = {"CM_" + field.upper(): 1 << i for i, field in enumerate(FIELDS)}
        if constants != expected_constants:
            raise ValueError("mask field definitions differ from independent baseline")
        entries = tables[0].split(",")
        if entries[-1].strip():
            raise ValueError("unrecognized combo table tail")
        parsed = []
        for entry in entries[:-1]:
            match = re.fullmatch(r"\s*\[(\d+)\]\s*=\s*(.*?)\s*", entry, re.S)
            if not match:
                raise ValueError(f"unknown combo entry: {entry!r}")
            index, expr = int(match[1]), match[2]
            tokens = [part.strip() for part in expr.split("|")]
            if expr == "0":
                value = 0
            else:
                if len(tokens) != len(set(tokens)) or any(t not in constants for t in tokens):
                    raise ValueError(f"unknown / duplicate mask expression: {expr}")
                value = sum(constants[t] for t in tokens)
            parsed.append(index)
            expected = sum(1 << i for i, field in enumerate(FIELDS) if AUTH[field] >> index & 1)
            if index not in active:
                expected = 0  # Holes must be zero, not skipped.
            if value != expected:
                fail(4, f"AUTH vs combo_masks.h mismatch at combo {index}: {value} != {expected}")
        if parsed != list(range(34)):
            raise ValueError("combo table must contain exactly indices 0..33 in order")

        # Remove complete preprocessor directives, including the macro definition,
        # then count every remaining macro token, not merely regex successes.
        gate = re.sub(r"\\\r?\n", " ", gate)
        gate = re.sub(r"^[ \t]*#[^\n]*", "", gate, flags=re.M)
        pattern = r"\bWL_COMBO_CHECK\s*\(\s*(COMBO_[A-Z0-9_]+)\s*,\s*\{([^{}]*)\}\s*\)"
        blocks = list(re.finditer(pattern, gate, re.S))
        residual = re.sub(pattern, "", gate, flags=re.S)
        if re.search(r"\bWL_COMBO_CHECK\b", residual):
            fail(5, "unparsed WL_COMBO_CHECK invocation")
        order = [numbers.get(m[1], -1) for m in blocks]
        report["call_count"], report["order"] = len(blocks), order
        if len(blocks) != 31 or set(order) != EXPECTED:
            fail(1, f"call_count={len(blocks)} (want 31); missing={sorted(EXPECTED-set(order))}; extra={sorted(set(order)-EXPECTED)}")
        duplicates = sorted(b for b, n in Counter(order).items() if n > 1)
        if duplicates:
            fail(2, f"duplicate combo indices: {duplicates}")
        if order != sorted(order):
            fail(3, f"source order is not ascending: {order}")
        for block, index in zip(blocks, order):
            seen = set()
            statements = block[2].split(";")
            if statements[-1].strip():
                fail(5, f"combo {index}: unterminated statement {statements[-1]!r}")
            for statement in statements[:-1]:
                statement = statement.strip()
                copy = re.fullmatch(r"ip_copy\s*\(\s*&lookup\.(src_ip|dst_ip)\s*,\s*&key\.(src_ip|dst_ip)\s*\)", statement)
                zero = re.fullmatch(r"ip_zero\s*\(\s*&lookup\.(src_ip|dst_ip)\s*\)", statement)
                scalar = re.fullmatch(r"lookup\.(src_port|dst_port|protocol)\s*=\s*(0|key\.(src_port|dst_port|protocol))", statement)
                if copy:
                    field, source = copy[1], copy[2]
                elif zero:
                    field, source = zero[1], None
                elif scalar:
                    field, source = scalar[1], scalar[3]
                else:
                    fail(5, f"combo {index}: unknown statement/expression {statement!r}")
                    continue
                if field in seen:
                    fail(5, f"combo {index}: duplicate assignment to {field}")
                seen.add(field)
                if index < 0:
                    fail(5, f"unknown combo symbol {block[1]}")
                    continue
                expected_source = field if AUTH[field] >> index & 1 else None
                if source != expected_source:
                    fail(4, f"combo {index}: {field} source={source!r}, want={expected_source!r}")
            if seen != set(FIELDS):
                fail(5, f"combo {index}: missing fields {sorted(set(FIELDS)-seen)}")
    except (OSError, UnicodeError, ValueError) as error:
        fail(5, str(error))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="absolute tested source root; no cwd fallback")
    parser.add_argument("--ck", action="store_true")
    parser.add_argument("--contract", required=True, choices=tuple(CONTRACTS))
    args = parser.parse_args()
    if not args.root.is_absolute():
        parser.error("--root must be absolute")
    root = args.root.resolve()
    report = check(root, args.contract)
    count = len(report["errors"])
    print(json.dumps(report, ensure_ascii=False, sort_keys=True), file=sys.stderr)
    print(count if args.ck else f"whitelist calls={report['call_count']}; violations={count}")
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
