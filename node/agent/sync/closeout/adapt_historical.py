#!/usr/bin/env python3
"""Read-only S8 inputs. Historical assertions never enter the new oracle."""
import copy
import hashlib
import json
from pathlib import Path

HISTORICAL = Path(__file__).resolve().parent.parent / 'cut5a_replay'
FILES = ('scenarios.json', 'scenarios_p3.json', 'scenarios_p4.json',
         'scenarios_commit_p5.json', 'scenarios_p6.json')
IP_REMAP = {'192.0.2.': '10.10.2.', '198.51.100.': '10.20.100.',
            '203.0.113.': '10.30.113.', '2001:db8:': 'fd00:db8:'}


def private_inputs(value):
    if isinstance(value, dict):
        return {k: private_inputs(v) for k, v in value.items()}
    if isinstance(value, list):
        return [private_inputs(v) for v in value]
    if isinstance(value, str):
        for old, new in IP_REMAP.items():
            value = value.replace(old, new)
    return value


def snapshot():
    return {name: (HISTORICAL / name).read_bytes() for name in FILES}


def verify_unchanged(before):
    for name, data in before.items():
        assert (HISTORICAL / name).read_bytes() == data, 'historical input changed: ' + name
        print(f'CLOSEOUT_HISTORY_IMMUTABLE file={name} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}')


def adapt(packet_factory):
    before = snapshot()
    scenes, old_expect, counts = [], {}, {}
    for file in FILES:
        original = json.loads(before[file])
        nsteps = npackets = 0
        for source in original:
            scene = {'Family': 'S8', 'Name': file[:-5] + '/' + source['Name'], 'Source': file, 'Steps': []}
            for step in source['Steps']:
                case = scene['Name'] + '/' + step['Name']
                old_expect[case] = {k: v for k, v in step.items() if k.startswith('Expect')}
                out = {k: private_inputs(copy.deepcopy(v)) for k, v in step.items()
                       if not k.startswith(('Expect', 'Hits')) and k != 'Packets'}
                out['SourceFault'] = step.get('Fault', '')
                out['Packets'] = [packet_factory(name) for name in step.get('Packets', [])]
                scene['Steps'].append(out)
                nsteps += 1
                npackets += len(out['Packets'])
                assert not any(k.startswith(('Expect', 'Hits')) for k in out)
            scenes.append(scene)
        counts[file] = [len(original), nsteps, npackets]
        print(f'CLOSEOUT_S8_FILE file={file} scenes={len(original)} steps={nsteps} packets={npackets}')
    totals = [sum(row[i] for row in counts.values()) for i in range(3)]
    assert totals == [160, 354, 633], totals
    verify_unchanged(before)
    return scenes, old_expect, counts


def historical_expectation(file, fields):
    protocol = dict(zip(FILES, (2, 3, 4, 5, 6)))[file]
    candidates = {'scenarios.json': ['Expect'], 'scenarios_p3.json': ['ExpectP3', 'Expect'],
                  'scenarios_p4.json': ['ExpectP4', 'ExpectP3', 'Expect'],
                  'scenarios_commit_p5.json': ['ExpectP4', 'ExpectP3', 'Expect'],
                  'scenarios_p6.json': ['ExpectP6', 'Expect']}[file]
    field = next((key for key in candidates if fields.get(key)), None)
    return protocol, field, fields.get(field) if field else None


def historical_accepts(expect, status, body):
    """Audit-only interpretation of the old response predicate, never an oracle."""
    if not isinstance(body, dict): return False
    code = body.get('code')
    if expect in ('committed', 'deferred', 'unchanged'):
        if status != 200 or code != ('committed' if expect == 'deferred' else expect): return False
        return 'receipt' not in body if expect == 'unchanged' else body.get('receipt') == ('deferred' if expect == 'deferred' else 'confirmed')
    if expect in ('commit_failed', 'quiescence_failed', 'withdrawal_pending'): return status == 500 and code == expect
    if expect == 'welcome': return status == 200 and body.get('sync_protocol') == 6
    if expect in ('condition_group_required', 'condition_group_invalid', 'duplicate_key', 'table_full', 'group_undeclared', 'duplicate_id', 'cidr_overlap', 'condition_capacity', 'content_different'):
        return status == 409 and code == expect
    if expect == 'invalid': return status == 400 and code == 'validation_rejected'
    if expect == 'missing': return status == 404 and code == 'rule_not_found'
    if expect == 'publish_failure': return status == 500
    if expect == 'partial_rejection': return status == 200 and body.get('success') is True and body.get('failed', 0) != 0
    if expect == 'success': return status is not None and 200 <= status < 300 and body.get('success') is True and body.get('failed', 0) == 0
    if expect in ('logical_id_replay', 'duplicate_logical_id'): return status in (200, 409)
    raise ValueError('unknown historical assertion '+str(expect))
