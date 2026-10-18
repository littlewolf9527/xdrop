#!/usr/bin/env python3
"""Bind reviewed source and kit bytes without a circular DELIVERY digest."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--baseline', required=True)
a = p.parse_args()
source, kit = a.source.resolve(), Path(__file__).resolve().parent
head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
assert a.baseline == subprocess.check_output(['git', '-C', str(source), 'rev-parse', a.baseline], text=True).strip()
names = subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', 'controller', 'node/agent', 'node/bpf']).decode().split('\0')
deleted = set(subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z', '--deleted', '--', 'controller', 'node/agent', 'node/bpf']).decode().split('\0'))
names = sorted({n for n in names if n and n not in deleted and Path(n).name not in {'config.yaml', 'INFRASTRUCTURE.md'} and not (source/n).is_symlink()})
assert 'controller/core/api/ff_lab_test.go' in names
sha = lambda b: hashlib.sha256(b).hexdigest()
files = {n: sha((source/n).read_bytes()) for n in names}
(kit/'SOURCE_SHA256.json').write_text(json.dumps({'head': head, 'baseline': a.baseline, 'test_sha256': files['controller/core/api/ff_lab_test.go'], 'files': files}, indent=1)+'\n')
members = sorted(p.relative_to(kit).as_posix() for p in kit.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
(kit/'SHA256SUMS').write_text(''.join(sha((kit/n).read_bytes())+'  '+n+'\n' for n in members))
print('MANIFEST head=%s baseline=%s source_files=%d kit_files=%d' % (head, a.baseline, len(names), len(members)))
