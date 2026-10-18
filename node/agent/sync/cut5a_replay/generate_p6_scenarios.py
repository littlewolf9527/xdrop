#!/usr/bin/env python3
"""Only adds the J8 domain; historical generators and files remain immutable."""
import json
from pathlib import Path
from generate_p4_scenarios import rule
from reference_p4 import identity

HERE = Path(__file__).parent

def request(entry, r, accept, packets):
    if entry == 'full':
        step = dict(Name='install', Method='POST', Path='/api/v1/sync/atomic',
                    Body=dict(rules=[r]), Expect='condition_group_invalid',
                    ExpectP6='success' if accept else 'condition_group_invalid')
    else:
        step = dict(Name='install', Method='POST', Path='/api/v1/rules/commit',
                    Body=dict(groups=[dict(key=identity(r), rules=[r])]),
                    Expect='invalid', ExpectP6='committed' if accept else 'invalid')
    step['Packets'] = packets
    return step

def build():
    scenes = []
    for iscidr in (False, True):
        kind = 'cidr' if iscidr else 'exact'
        for entry in ('full', 'commit'):
            r = rule('j8', 5617, iscidr, action='rate_limit', rate_limit=7, match_anomaly=4)
            scenes.append(dict(Name=f'J8_accept_rate_{kind}_{entry}', Authority='J8 PLAN ④-1 / authorization 4 §2',
                               Steps=[request(entry, r, True, ['length_mismatch', 'length_mismatch', 'syn', 'miss'])]))
            both = dict(r, action='drop', tcp_flags='SYN'); both.pop('rate_limit')
            step = request(entry, both, True, ['length_mismatch', 'syn', 'length_mismatch_ack', 'ack'])
            step['Expect'] = step['ExpectP6']
            scenes.append(dict(Name=f'J8_and_{kind}_{entry}', Authority='J8 PLAN ④-1 regression (no allowance)', Steps=[step]))
            for invalid in ('unbounded', 'ipv6'):
                bad = dict(r)
                if invalid == 'unbounded':
                    if iscidr: bad['src_cidr'] = '0.0.0.0/0'
                    else: bad.pop('src_ip')
                else:
                    bad['match_anomaly'] = 1
                    bad['src_cidr' if iscidr else 'src_ip'] = '2001:db8::/64' if iscidr else '2001:db8::1'
                scenes.append(dict(Name=f'J8_rejected_{invalid}_{kind}_{entry}', Authority='J8 authorization 4 §2 error text only',
                                   Steps=[request(entry, bad, False, ['syn', 'length_mismatch'])]))
    return scenes

def historical_outputs():
    # Run each unchanged generator in an isolated copy, compare EVERY historical
    # scenario output. This function never writes a historical repository file.
    import shutil
    import subprocess
    import sys
    import tempfile
    with tempfile.TemporaryDirectory(prefix='cut56-historical-generators-') as folder:
        dest = Path(folder)
        for path in HERE.iterdir():
            if path.suffix in ('.py', '.json'): shutil.copy2(path, dest / path.name)
        originals = {p.name: p.read_bytes() for p in HERE.glob('scenarios*.json') if p.name != 'scenarios_p6.json'}
        for name in ('generate.py', 'generate_p3_scenarios.py', 'generate_p4_scenarios.py', 'generate_p5_scenarios.py'):
            if (dest / name).exists():
                proc = subprocess.run([sys.executable, str(dest / name)], cwd=dest, capture_output=True, text=True)
                print(proc.stdout, end=''); print(proc.stderr, end='')
                if proc.returncode: raise RuntimeError(name + ' failed')
        # p4's checked-in artifact includes a second, independent oracle stage.
        # Reproduce that stage too; never copy the stored Hits fields as evidence.
        import os
        from reference_p4 import inputs
        historical = json.loads((dest / 'scenarios_p4.json').read_text())
        oracle_in, oracle_out = dest / 'oracle-input.json', dest / 'oracle.json'
        oracle_in.write_text(json.dumps(inputs(historical), indent=2) + '\n')
        root = HERE.resolve().parents[3]
        env = dict(os.environ, GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local',
                   XDROP_CUT54_ORACLE_INPUT=str(oracle_in), XDROP_CUT54_ORACLE_OUT=str(oracle_out))
        proc = subprocess.run(['go', 'test', './eval', '-run', '^TestCut54ReplayOracle$', '-count=1', '-v'],
                              cwd=root / 'node/agent', env=env, capture_output=True, text=True)
        print(proc.stdout, end=''); print(proc.stderr, end='')
        if proc.returncode: raise RuntimeError('historical p4 oracle stage failed')
        oracle = json.loads(oracle_out.read_text())
        for scene in historical:
            for step in scene['Steps']:
                case = scene['Name'] + '/' + step['Name']
                for version in ('P3', 'P4'):
                    step['Hits' + version] = [bool(x['RuleID']) for x in oracle[case][version]]
        (dest / 'scenarios_p4.json').write_text(json.dumps(historical, indent=2) + '\n')
        for name, old in sorted(originals.items()):
            if (dest / name).read_bytes() != old: raise AssertionError('historical scenario changed: ' + name)
            print('CUT56_HISTORICAL_SCENARIO name=%s bytes=%d identical=1' % (name, len(old)))
        return len(originals)

if __name__ == '__main__':
    scenes = build()
    (HERE / 'scenarios_p6.json').write_text(json.dumps(scenes, indent=2) + '\n')
    historical = historical_outputs()
    print('CUT56_SCENARIOS scenes=%d steps=%d packets=%d historical_identical=%d' %
          (len(scenes), sum(len(s['Steps']) for s in scenes), sum(len(v['Packets']) for s in scenes for v in s['Steps']), historical))
