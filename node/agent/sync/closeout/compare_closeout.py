#!/usr/bin/env python3
"""Absolute comparison. The only projections are the sealed PLAN G3 exclusions."""
import argparse
import copy
import json
from pathlib import Path

COUNTERS = ('total_packets', 'dropped_packets', 'passed_packets',
            'whitelisted_packets', 'rate_limited_packets')
SYSTEM = ('cpu_percent', 'mem_total_mb', 'mem_used_mb', 'mem_percent',
          'uptime_seconds', 'load_avg_1', 'load_avg_5', 'load_avg_15')


def differences(actual, expected, path=()):
    if type(actual) is not type(expected):
        yield path, actual, expected
    elif isinstance(actual, dict):
        for key in sorted(actual.keys() | expected.keys()):
            if key not in actual or key not in expected:
                yield path + (key,), {'present': key in actual, 'value': actual.get(key)}, {'present': key in expected, 'value': expected.get(key)}
            else:
                yield from differences(actual[key], expected[key], path + (key,))
    elif isinstance(actual, list):
        if len(actual) != len(expected):
            yield path + ('length',), len(actual), len(expected)
        for i, (a, b) in enumerate(zip(actual, expected)):
            yield from differences(a, b, path + (i,))
    elif actual != expected:
        yield path, actual, expected


def response(path, body, removed=None):
    """Path-specific projection retains unknown fields and all ordered arrays."""
    out = copy.deepcopy(body)
    removed = {} if removed is None else removed

    def pop(mapping, key, name):
        if key in mapping:
            removed[name] = mapping.pop(key)

    if not isinstance(out, dict):
        return out
    if path == '/api/v1/rules':
        # Protocol 7 always pages in ID order; that order is part of the contract.
        if 'rules' in out:
            for index, rule in enumerate(out['rules']):
                if isinstance(rule.get('stats'), dict):
                    for field in ('drop_pps', 'match_bytes', 'drop_bytes'):
                        pop(rule['stats'], field, f'rules[{index}].stats.{field}')
    elif path.startswith('/api/v1/rules?'):
        for index, rule in enumerate(out.get('rules', [])):
            if isinstance(rule.get('stats'), dict):
                for field in ('drop_pps', 'match_bytes', 'drop_bytes'):
                    pop(rule['stats'], field, f'rules[{index}].stats.{field}')
    elif path == '/api/v1/whitelist':
        if 'entries' in out:
            out['entries'].sort(key=lambda r: r['id'])
    elif path == '/api/v1/stats':
        for field in ('dropped_pps', 'passed_pps', 'total_pps', 'capacity', 'total_bytes', 'dropped_bytes', 'passed_bytes'):
            pop(out, field, field)
        if isinstance(out.get('system'), dict):
            for field in SYSTEM:
                pop(out['system'], field, 'system.' + field)
    elif path == '/api/v1/stats/cpu':
        pop(out, 'per_cpu', 'per_cpu')
    return out


def project(records):
    projected, removed = {}, {}
    for name, value in records.items():
        rec = copy.deepcopy(value)
        if rec.get('family') == 'S7':
            if rec.get('legal_serial_pass') is not True:
                raise AssertionError('CLOSEOUT_WITNESS S7 legal serial assertion absent/false')
            projected[name] = {'family': 'S7', 'legal_serial_pass': True}
            removed[name] = rec
            continue
        exc = {}
        for key, path in (('body', rec.get('path', '')), ('installed', '/api/v1/rules'), ('installed_after', '/api/v1/rules'),
                          ('whitelist', '/api/v1/whitelist'), ('stats', '/api/v1/stats'),
                          ('cpu', '/api/v1/stats/cpu')):
            if key in rec:
                exc[key] = {}
                rec[key] = response(path, rec[key], exc[key])
        projected[name], removed[name] = rec, exc
    return projected, removed


def compare(actual, expected):
    return list(differences(project(actual)[0], project(expected)[0]))


def cpu_sum(stats, cpu):
    rows = cpu['per_cpu']
    if not rows or len({r['cpu'] for r in rows}) != len(rows):
        raise AssertionError('CPU slots empty or duplicated')
    for field in COUNTERS:
        if sum(row[field] for row in rows) != stats[field]:
            raise AssertionError('CLOSEOUT_WITNESS S5 cpu sum ' + field)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('actual', type=Path)
    p.add_argument('expected', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    actual, expected = (json.loads(path.read_text()) for path in (a.actual, a.expected))
    diff = compare(actual, expected)
    a.output.write_text(json.dumps({'differences': diff, 'excluded_actual': project(actual)[1],
                                    'excluded_expected': project(expected)[1]}, indent=2) + '\n')
    for name in sorted(actual.keys() | expected.keys()):
        count = sum(path and path[0] == name for path, _, _ in diff)
        print(f'CLOSEOUT_CELL name={name} differences={count}')
    print(f'CLOSEOUT_COMPARE records={len(actual)} expected_records={len(expected)} differences={len(diff)}')
    raise SystemExit(bool(diff))


if __name__ == '__main__':
    main()
