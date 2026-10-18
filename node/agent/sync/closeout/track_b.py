#!/usr/bin/env python3
"""Real-agent wiring acceptance; all mutable system operations are lab-only."""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

from compare_closeout import COUNTERS, cpu_sum, differences, response

HERE = Path(__file__).resolve().parent
ADDRESS = '10.255.0.1'
B5_RECORD = 'B5-restart-record.json'  # Reserved for full evidence, never an equal() cell.


def need(value, message):
    if not value:
        raise AssertionError(message)


def command(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2)+'\n')


def pins():
    root = Path('/sys/fs/bpf/xdrop')
    return sorted((p.name, p.lstat().st_ino) for p in root.iterdir()) if root.exists() else []


def config_from_example(example, values):
    # Consume only the public example; retain its field shape, never a real config.
    shape, section = {}, None
    for line in Path(example).read_text().splitlines():
        if line and not line.startswith((' ', '#')) and line.endswith(':'):
            section = line[:-1]
            shape[section] = set()
        elif line.startswith('  ') and not line.lstrip().startswith('#') and ':' in line and section:
            shape[section].add(line.strip().split(':', 1)[0])
    need(all(section in shape and set(fields) <= shape[section] for section, fields in values.items()), 'config example shape drift')
    return '\n'.join(section+':\n'+'\n'.join('  '+k+': '+json.dumps(v) for k, v in fields.items()) for section, fields in values.items())+'\n'



def stats_delta(stats, before):
    # Main-owned pinned counters survive restart; keep every other response field.
    return dict(stats, **{k: stats[k]-before[k] for k in (*COUNTERS, 'cond_row_missing', 'mapped_v6_dropped')})


def cpu_delta(cpu, before):
    old = {r['cpu']: r for r in before['per_cpu']}
    rows = cpu['per_cpu']
    need(len(old) == len(before['per_cpu']) and len(rows) == len(old) and
         {r['cpu'] for r in rows} == set(old), 'CPU baseline slots changed or duplicated')
    return [dict(cpu=r['cpu'], **{k: r[k]-old[r['cpu']][k] for k in COUNTERS})
            for r in sorted(rows, key=lambda r: r['cpu'])]


def sender(path, interface, cpu):
    packets = read(path)
    need(os.sched_getaffinity(0) == {cpu}, 'sender not pinned to one CPU')
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((interface, 0))
        started = time.monotonic_ns()
        for p in packets:
            frame = bytes.fromhex(p['Frame'])
            need(sock.send(frame) == len(frame), 'short raw send')
        elapsed = time.monotonic_ns()-started
    print(f'CLOSEOUT_SEND packets={len(packets)} cpu={cpu} elapsed_ns={elapsed}', flush=True)


class Supervisor:
    def __init__(self, args):
        self.a, self.s = args, Path(args.scratch)
        self.agent = None
        self.agent_logs = []
        self.key = secrets.token_hex(32)
        self.legacy = [secrets.token_hex(32), secrets.token_hex(32)]
        self.fixture = read(args.artifacts+'/track-b-fixture.json')
        self.expected = read(args.artifacts+'/track-b-expected.json')
        self.data = read(args.scenes)
        self.expected_a = read(args.artifacts+'/expected.json')
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, method, path, body=None, key=True):
        headers = {'Content-Type': 'application/json'}
        if key:
            headers['X-API-Key'] = self.key
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f'http://{ADDRESS}:18080'+path, data=data, method=method, headers=headers)
        try:
            result = self.http.open(req, timeout=15)
        except urllib.error.HTTPError as e:
            result = e
        with result:
            raw = result.read()
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = raw.decode()
            return result.code, body

    def get(self, path):
        code, body = self.request('GET', path)
        need(code == 200, 'GET failed '+path)
        return body

    def equal(self, name, actual, expected):
        diff = list(differences(actual, expected))
        write(self.s/(name.replace('/', '_')+'.json'), dict(actual=actual, expected=expected, differences=diff))
        print(f'CLOSEOUT_CELL name={name} differences={len(diff)}', flush=True)
        need(not diff, 'CLOSEOUT_WITNESS '+name+' '+repr(diff))

    def start_agent(self, pinning='require', observe=False, legacy=False):
        need(self.agent is None, 'agent already running')
        values = dict(server=dict(port=18080, interface='closeout0'),
                      bpf=dict(main_path=self.a.main_elf, gate_path=self.a.gate_elf, pinning=pinning,
                               xdp_mode='generic', rate_limit_divisor=1),
                      auth=dict(node_api_key=self.key))
        conf = self.s/'agent-private.yaml'
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(config_from_example(self.a.example, values))
            if legacy:
                f.write('  controller_url: '+json.dumps(self.legacy[0])+'\n  controller_sync_key: '+json.dumps(self.legacy[1])+'\n')
        log = self.s/('agent-'+str(len(self.agent_logs))+'.log')
        self.agent_logs.append(log)
        started = time.monotonic()
        with log.open('w') as f:
            self.agent = subprocess.Popen([self.a.agent, '-config', str(conf)], stdout=f, stderr=subprocess.STDOUT)
        # B-0.3 is immediate and applies to every restart in this same supervisor.
        try:
            need(os.readlink(f'/proc/{self.agent.pid}/ns/mnt') == os.readlink('/proc/self/ns/mnt'), 'B-0 agent mount namespace differs')
        except Exception:
            self.stop_agent()
            raise
        print('CLOSEOUT_B0 agent_mnt_equal=1 supervisor_pid=%d agent_pid=%d' % (os.getpid(), self.agent.pid), flush=True)
        while time.monotonic()-started < 180:
            if self.agent.poll() is not None:
                if observe:
                    return dict(exited_before_api=True, api_reachable=False, exit_code=self.agent.returncode)
                raise AssertionError('agent exited before API; see private agent log')
            try:
                if self.request('GET', '/api/v1/health')[0] == 200:
                    if observe:
                        return dict(exited_before_api=False, api_reachable=True, exit_code=None)
                    return time.monotonic()-started
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.05)
        if observe:
            return dict(exited_before_api=False, api_reachable=False, exit_code=self.agent.poll())
        raise AssertionError('agent API unavailable after bounded startup wait')

    def stop_agent(self):
        if self.agent is not None:
            if self.agent.poll() is None:
                self.agent.terminate()
                try:
                    self.agent.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.agent.kill()
                    self.agent.wait()
            self.agent = None

    def push_fixture(self):
        # The harness acts as controller: only enabled rules enter node requests.
        rules = [{k: v for k, v in r.items() if k != 'enabled'} for r in self.fixture['rules'] if r.get('enabled', True)]
        need(self.request('POST', '/api/v1/sync/atomic', {'rules': rules})[0] == 200, 'fixture atomic push')
        need(self.request('POST', '/api/v1/sync/whitelist', {'entries': self.fixture['entries']})[0] == 200, 'fixture whitelist push')

    def send(self, packets, window=None):
        path = self.s/'packets.json'
        write(path, packets)
        started = time.monotonic_ns()
        command(['ip', 'netns', 'exec', self.a.peer, 'taskset', '-c', str(self.a.cpu), sys.executable,
                 __file__, '--send', str(path), '--cpu', str(self.a.cpu)])
        elapsed = time.monotonic_ns()-started
        if window:
            need(elapsed < window, 'CLOSEOUT_WITNESS B-6 no-refill window exceeded')

    def snapshot(self, label):
        path = self.s/(label+'-bucket.json')
        env = dict(os.environ, XDROP_CLOSEOUT_PIN_SNAPSHOT=str(path), XDROP_CLOSEOUT_PIN_ID=str(self.fixture['bucket_id']),
                   XDROP_CLOSEOUT_AGENT_PID=str(self.agent.pid))
        command([self.a.sync_test, '-test.run=^TestCloseoutPinnedSnapshot$', '-test.v'], env=env)
        return read(path)

    def installed(self, name):
        actual = dict(installed=response('/api/v1/rules', self.get('/api/v1/rules')),
                      whitelist=response('/api/v1/whitelist', self.get('/api/v1/whitelist')),
                      rules_count=self.get('/api/v1/stats')['rules_count'])
        expected = dict(installed=response('/api/v1/rules', self.expected['installed']),
                        whitelist=response('/api/v1/whitelist', self.expected['whitelist']), rules_count=self.expected['rules_count'])
        self.equal(name, actual, expected)
        if name.startswith('B-3/'):
            need('startup-disabled' not in [r['id'] for r in actual['installed']['rules']], 'B-3 disabled rule installed')
            print('CLOSEOUT_B3 rules=%d whitelist=%d disabled_absent=1' % (actual['rules_count'], actual['whitelist']['count']), flush=True)

    def b1(self):
        routes = read(self.a.routes)
        probed = 0
        for route in routes:
            method = route['method']
            probe_id = 'route-probe-'+method.lower()
            path = route['path'].replace(':id', probe_id)
            body = {} if method not in ('GET', 'DELETE') or path.endswith('/batch') else None
            code, welcome = self.request(method, path, body, key=route['auth'])
            self.equal('B-1/route/'+method+path, code not in (401, 404), True)
            if route['auth']:
                self.equal('B-1/auth/'+method+path, self.request(method, path, body, False)[0], 401)
            if path == '/':
                self.equal('B-1/welcome', welcome['sync_protocol'], 11)
            probed += 1
        self.equal('B-1/execution', probed, 10)
        auth = sum(r['auth'] for r in routes)
        self.equal('B-1/auth-count', auth, 8)
        from generate_closeout_scenarios import deleted_routes
        removed = deleted_routes()[0]['Steps'][1:]
        before = [self.get('/api/v1/rules'), self.get('/api/v1/whitelist')]
        for row in removed:
            name = 'B-1/deleted/'+row['Method']+row['Path']
            self.equal(name, list(self.request(row['Method'], row['Path'], {})), [404, '404 page not found'])
            after = [self.get('/api/v1/rules'), self.get('/api/v1/whitelist')]
            self.equal(name+'/unchanged', [response(p,v) for p,v in zip(('/api/v1/rules','/api/v1/whitelist'),after)],
                       [response(p,v) for p,v in zip(('/api/v1/rules','/api/v1/whitelist'),before)])
        print(f'CLOSEOUT_B1 routes={probed} auth={auth} deleted={len(removed)}', flush=True)

    def installed_observation(self):
        actual = dict(installed=response('/api/v1/rules', self.get('/api/v1/rules')),
                      whitelist=response('/api/v1/whitelist', self.get('/api/v1/whitelist')),
                      rules_count=self.get('/api/v1/stats')['rules_count'])
        expected = {k: self.expected[k] for k in actual}
        expected['installed'] = response('/api/v1/rules', expected['installed'])
        expected['whitelist'] = response('/api/v1/whitelist', expected['whitelist'])
        return dict(actual=actual, expected=expected, differences=list(differences(actual, expected)))

    def b5(self):
        self.stop_agent()
        required = self.start_agent(observe=True)
        print('CLOSEOUT_B5_REQUIRE api_reachable=%d' % int(required['api_reachable']), flush=True)
        self.equal('B-5/require', required['api_reachable'], True)
        self.push_fixture()
        self.send(self.fixture['packets'][-3:])
        before = self.snapshot('before-restart')
        active = [r for r in before.get('slots', []) if r['last_update_present']]
        consumed = before['present'] and len(active) == 1 and active[0]['tokens'] == 0
        need(consumed, 'CLOSEOUT_WITNESS B-5/not-executed consumed_on_one_cpu=0')
        self.stop_agent()
        restarted = self.start_agent(observe=True)
        need(restarted['api_reachable'], 'CLOSEOUT_WITNESS B-5/restart-require')
        # No probes or writes between restart and this observation.
        after = self.snapshot('after-restart')
        expected = self.expected['bucket_after_restart']
        print('CLOSEOUT_B5_BUCKET precondition=1 present=%d expected_present=%d' %
              (int(after['present']), int(expected['present'])), flush=True)
        self.equal('B-5/bucket', dict(present=after['present']), expected)
        health = self.get('/api/v1/health')
        self.equal('B-5/cold-health', health, self.character('TD020-health')['initial'])
        self.push_fixture()
        self.installed('B-5/installed')
        self.equal('B-5/restored-health', self.get('/api/v1/health'), dict(status='healthy'))
        write(self.s/B5_RECORD, dict(require=required, startup=restarted, before=before, after=after,
              consumed_on_one_cpu=consumed, cold_health=health, empty_window_record_only=True))
        self.b5_checked = True
        print('CLOSEOUT_B5 restarts=1 require=1 bucket_read_before_probe=1', flush=True)

    def check_cpu_delta(self, name, stats, cpu, before, expected):
        cpu_sum(stats, cpu)
        need(self.a.cpu in {r['cpu'] for r in before['per_cpu']}, 'sender CPU missing from baseline')
        want = [dict(cpu=r['cpu'], **{k: expected[k] if r['cpu'] == self.a.cpu else 0 for k in COUNTERS})
                for r in sorted(before['per_cpu'], key=lambda r: r['cpu'])]
        self.equal(name, cpu_delta(cpu, before), want)

    def b6(self):
        self.stop_agent()
        self.start_agent()
        self.push_fixture()
        before, cpu_before = self.get('/api/v1/stats'), self.get('/api/v1/stats/cpu')
        cpu_sum(before, cpu_before)
        self.send(self.fixture['packets'], self.fixture['no_refill_ns'])
        after, cpu_after = self.get('/api/v1/stats'), self.get('/api/v1/stats/cpu')
        write(self.s/'B-6-raw-stats.json', dict(before=before, cpu_before=cpu_before, after=after, cpu_after=cpu_after))
        self.equal('B-6/counts', {k: after[k]-before[k] for k in COUNTERS}, self.expected['delta'])
        cpu_sum(after, cpu_after)
        old = {r['cpu']: r for r in cpu_before['per_cpu']}
        changed = [r['cpu'] for r in cpu_after['per_cpu'] if r['total_packets'] != old[r['cpu']]['total_packets']]
        self.equal('B-6/one-cpu', changed, [self.a.cpu])
        self.check_cpu_delta('B-6/cpu-delta', after, cpu_after, cpu_before, self.expected['delta'])
        print('CLOSEOUT_B6 classes=4 packets=6 active_cpus=1', flush=True)

    def b7(self):
        scenes = [s for s in self.data['Scenes'] if s.get('TrackB') and s['Family'] == 'S1']
        need(len(scenes) == 3 and all(not x.get('Fault') for s in scenes for x in s['Steps']), 'B-7 fault-free selection')
        steps, baselines = 0, []
        for scene in scenes:
            self.stop_agent()
            # Policy is cleared on restart; pinned main counters are cumulative.
            self.start_agent()
            before, cpu_before = self.get('/api/v1/stats'), self.get('/api/v1/stats/cpu')
            cpu_sum(before, cpu_before)
            baselines.append(before)
            write(self.s/('B-7_'+scene['Name'].replace('/', '_')+'-stats-baseline.json'),
                  dict(scene=scene['Name'], stats=before, cpu=cpu_before))
            rate_started = {}
            for row in scene['Steps']:
                name = scene['Name']+'/'+row['Name']
                expected = self.expected_a[name]
                status, body = self.request(row['Method'], row['Path'], row['Body'])
                reply = response(row['Path'], expected['body'])
                if row['Path'] == '/api/v1/stats':
                    cpu = self.get('/api/v1/stats/cpu')
                    self.check_cpu_delta('B-7/'+name+'/cpu_delta', body, cpu, cpu_before, expected['body'])
                    write(self.s/('B-7_'+name.replace('/', '_')+'-raw-stats.json'), dict(stats=body, cpu=cpu))
                    body = stats_delta(body, before)
                    reply['xdp_info'] = self.expected['xdp_info']
                self.equal('B-7/'+name+'/reply', [status, response(row['Path'], body)],
                           [expected['status'], reply])
                self.equal('B-7/'+name+'/installed', response('/api/v1/rules', self.get('/api/v1/rules')),
                           response('/api/v1/rules', expected['installed']))
                self.equal('B-7/'+name+'/whitelist', response('/api/v1/whitelist', self.get('/api/v1/whitelist')),
                           response('/api/v1/whitelist', expected['whitelist']))
                rates = row['RateLimits']
                rate_started = {k: v for k, v in rate_started.items() if k in rates}
                started = time.monotonic_ns()
                for id in rates:
                    rate_started.setdefault(id, started)
                self.send(row['Packets'])
                for id, rate in rates.items():
                    need(time.monotonic_ns()-rate_started[id] < 1000000000//rate, 'B-7 no-refill window '+name)
                self.equal('B-7/'+name+'/installed_after', response('/api/v1/rules', self.get('/api/v1/rules')),
                           response('/api/v1/rules', expected['installed_after']))
                steps += 1
            after, cpu_after = self.get('/api/v1/stats'), self.get('/api/v1/stats/cpu')
            write(self.s/('B-7_'+scene['Name'].replace('/', '_')+'-stats-after.json'), dict(stats=after, cpu=cpu_after))
            self.equal('B-7/'+scene['Name']+'/stats_after', response('/api/v1/stats', stats_delta(after, before)),
                       dict(response('/api/v1/stats', expected['stats']), xdp_info=self.expected['xdp_info']))
            self.check_cpu_delta('B-7/'+scene['Name']+'/cpu_after', after, cpu_after, cpu_before, expected['stats'])
        print('CLOSEOUT_B7_STATS_BASELINE scenes=%d first_nonzero=%d' %
              (len(baselines), int(any(baselines[0][k] != 0 for k in COUNTERS))), flush=True)
        print(f'CLOSEOUT_B7 scenes=3 steps={steps}', flush=True)

    def characterize(self):
        self.stop_agent()
        elapsed = self.start_agent()
        initial = self.get('/api/v1/health')
        actual = dict(rules=self.get('/api/v1/rules')['count'], whitelist=self.get('/api/v1/whitelist')['count'])
        self.equal('startup-empty', actual, self.character('startup-empty'))
        need(self.request('POST', '/api/v1/sync/atomic', {'rules': []})[0] == 200, 'health atomic push')
        need(self.request('POST', '/api/v1/sync/whitelist', {'entries': []})[0] == 200, 'health whitelist push')
        self.equal('TD020-health', dict(initial=initial, after=self.get('/api/v1/health')), self.character('TD020-health'))
        print(f'CLOSEOUT_B4 startup_seconds={elapsed:.9f} character_leaves=2', flush=True)
        need(getattr(self, 'b5_checked', False), 'G2 missing B-5 judgment')
        print(f'CLOSEOUT_CHARACTER_B leaves=2 manifest={len(self.data["Characterizations"])}', flush=True)

    def character(self, leaf):
        return next(c['Expected'] for c in self.data['Characterizations'] if c['Leaf'] == leaf)

    def b8(self):
        self.stop_agent()
        self.start_agent(legacy=True)
        lines = self.agent_logs[-1].read_text().splitlines()
        warns = [line for line in lines if 'deprecated and ignored' in line and 'WARN' in line]
        self.equal('B-8/legacy-warn', len(warns), 1)
        self.equal('B-8/cold-health', self.get('/api/v1/health'), self.character('TD020-health')['initial'])
        self.equal('B-8/empty', dict(rules=self.get('/api/v1/rules')['count'], whitelist=self.get('/api/v1/whitelist')['count']), self.character('startup-empty'))
        self.push_fixture()
        self.equal('B-8/restored-health', self.get('/api/v1/health'), {'status': 'healthy'})
        need(self.agent.poll() is None, 'legacy config process stopped')
        print(f'CLOSEOUT_B8 legacy_warn={len(warns)} continued=1 cold_degraded=1 pushed_healthy=1', flush=True)

    def run(self):
        command(['mount', '--make-rprivate', '/'])
        command(['mount', '-t', 'bpf', 'bpf', '/sys/fs/bpf'])
        try:
            dev = os.stat('/sys/fs/bpf').st_dev
            need(dev != self.a.host_dev, 'B-0 private bpffs has host st_dev')
            mounts = Path('/proc/self/mountinfo').read_text()
            write(self.s/'B-0-mount.json', dict(host_dev=self.a.host_dev, private_dev=dev, mountinfo=mounts))
            need(any(line.split()[4] == '/sys/fs/bpf' and line.split(' - ')[1].split()[0] == 'bpf'
                     for line in mounts.splitlines()), 'B-0 private mount is not bpf')
            print('CLOSEOUT_B0 before_agent=1 dev_different=1 fstype_bpf=1', flush=True)
            selected = set(read(self.s/'supervisor-control.json')['run'])
            if selected != {'B-5'}: self.start_agent()
            need(selected <= {'B-1', 'B-3', 'B-5', 'B-6', 'B-7', 'G2', 'B-8'}, 'unknown supervisor command')
            print('CLOSEOUT_SUPERVISOR control_file=1 persistent_mount=1', flush=True)
            for name, function in [('B-3', lambda: (self.push_fixture(), self.installed('B-3/installed'))), ('B-5', self.b5), ('B-6', self.b6),
                                   ('B-7', self.b7), ('B-1', self.b1), ('G2', self.characterize), ('B-8', self.b8)]:
                if name in selected:
                    function()
                    print('CLOSEOUT_TRACK_B cell='+name+' executed=1', flush=True)
        finally:
            self.stop_agent()
            conf = self.s/'agent-private.yaml'
            if conf.exists():
                conf.unlink()
            try:
                for log in self.agent_logs:
                    text = log.read_text()
                    need(all(secret not in text for secret in [self.key, *self.legacy]), 'secret unexpectedly logged')
                print('CLOSEOUT_SECRETS logs_checked=1', flush=True)
            finally:
                command(['umount', '/sys/fs/bpf'])
            print('CLOSEOUT_B0 private_bpffs_unmounted=1', flush=True)


def host(args):
    need(sys.platform == 'linux' and os.geteuid() == 0, 'lab Linux root required')
    scratch = Path(args.scratch).resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    need(not (scratch/'agent-private.yaml').exists(), 'scratch credential collision')
    before, dev = pins(), os.stat('/sys/fs/bpf').st_dev
    suffix = secrets.token_hex(5)
    agent_ns, peer_ns = 'cl-a-'+suffix, 'cl-p-'+suffix
    owned = []
    selected = args.only.split(',') if args.only else ['B-1', 'B-3', 'B-5', 'B-6', 'B-7', 'G2', 'B-8']
    write(scratch/'supervisor-control.json', {'run': selected})
    try:
        for name in (agent_ns, peer_ns):
            command(['ip', 'netns', 'add', name])
            owned.append(name)
        command(['ip', '-n', agent_ns, 'link', 'add', 'closeout0', 'type', 'veth', 'peer', 'name', 'closeout1', 'netns', peer_ns])
        for name, interface in ((agent_ns, 'closeout0'), (peer_ns, 'closeout1')):
            command(['ip', 'netns', 'exec', name, 'sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=1'])
            command(['ip', '-n', name, 'link', 'set', 'lo', 'up'])
            command(['ip', '-n', name, 'link', 'set', interface, 'up'])
        command(['ip', '-n', agent_ns, 'addr', 'add', ADDRESS+'/32', 'dev', 'lo'])
        argv = [sys.executable, __file__, *sys.argv[1:], '--supervisor', '--peer', peer_ns, '--host-dev', str(dev)]
        command(['ip', 'netns', 'exec', agent_ns, 'unshare', '--mount', '--', *argv])
    finally:
        errors = []
        for name in reversed(owned):
            try:
                command(['ip', 'netns', 'delete', name])
            except subprocess.CalledProcessError as error:
                errors.append(str(error))
        after = pins()
        write(scratch/'B-0-host-pins.json', dict(before=before, after=after))
        need(before == after, 'B-0 host pin names/inodes changed')
        need(not errors, 'owned netns cleanup failed: '+repr(errors))
        print('CLOSEOUT_B0 host_pins_equal=1 owned_netns_remaining=0', flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('scratch', 'agent', 'main-elf', 'gate-elf', 'sync-test', 'artifacts', 'example', 'peer', 'scenes', 'routes', 'only', 'send'):
        p.add_argument('--'+name, default='')
    p.add_argument('--cpu', type=int, default=0)
    p.add_argument('--host-dev', type=int, default=-1)
    p.add_argument('--supervisor', action='store_true')
    args = p.parse_args()
    if args.send:
        sender(args.send, 'closeout1', args.cpu)
    elif args.supervisor:
        Supervisor(args).run()
    else:
        host(args)


if __name__ == '__main__':
    def terminate(signum, frame):
        raise KeyboardInterrupt('signal '+str(signum))
    signal.signal(signal.SIGTERM, terminate)
    main()
