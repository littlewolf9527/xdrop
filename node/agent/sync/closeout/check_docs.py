"""G10: compare document route headings with the production AST export."""
import argparse
import collections
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def check(text, routes):
    headings = re.findall(r'^### `(GET|POST|PUT|DELETE) ([^`]+)`$', text, re.M)
    expected = collections.Counter((r['method'], r['path']) for r in routes)
    actual = collections.Counter(headings)
    assert actual == expected, f'route headings differ: {actual - expected}; missing: {expected - actual}'
    assert len(headings) == 10 and all(n == 1 for n in actual.values()), 'route uniqueness'
    assert re.search(r'^## (Node and controller responsibilities|节点与控制器的分工)$', text, re.M), 'responsibility section absent'
    assert '不主动拉取' in text or 'does not actively pull' in text, 'no-pull contract absent'
    history = False
    for line in text.splitlines():
        if line.startswith('## '):
            history = line in ('## Protocol changes', '## 协议版本变更表')
        exempt = history and re.match(r'^\|\s*[2-7]\s*\|', line)
        assert 'withdrawal_pending' not in line or exempt, 'nonhistorical withdrawal_pending: '+line
        if history and line.strip() and not (line.startswith('## ') or line.startswith('|')):
            history = False
    return len(headings)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[4])
    ap.add_argument('--document', required=True, type=Path)
    ap.add_argument('--main-test', type=Path)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix='xdrop-docs-') as scratch:
        out = Path(scratch)/'routes.json'
        env = dict(os.environ, XDROP_CLOSEOUT_ROUTE_EXPORT=str(out), GOPROXY='off', GOSUMDB='off')
        command = [str(args.main_test), '-test.run=^TestCloseoutRoutes$', '-test.v', '-test.count=1'] if args.main_test else ['go', 'test', '-run', '^TestCloseoutRoutes$', '-count=1', '-v', '.']
        result = subprocess.run(command, cwd=args.root/'node/agent', env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout, end='')
        assert result.returncode == 0 and len(re.findall(r'CLOSEOUT_ROUTES routes=10 auth=8 ast_controls=5(?![0-9])', result.stdout)) == 1, 'AST control failed'
        routes = json.loads(out.read_text())
        text = args.document.read_text()
        count = check(text, routes)
        rejected = 0
        for suffix in ('\n### `GET /api/v1/extra`\n', '\n### `GET /`\n'):
            try: check(text + suffix, routes)
            except AssertionError: rejected += 1
        assert rejected == 2, 'positive controls not rejected'
        with tempfile.TemporaryDirectory(prefix='xdrop-docs-control-') as control:
            bad, good = Path(control)/'bad.md', Path(control)/'good.md'
            bad.write_text(text+'\nwithdrawal_pending\n')
            try: check(bad.read_text(), routes)
            except AssertionError: pass
            else: raise AssertionError('G6 outside-history positive control survived')
            good.write_text(text+'\n## Protocol changes\n\n| 7 | withdrawal_pending |\n')
            check(good.read_text(), routes)
        print('CLOSEOUT_DOCS_G6 file=%s outside_history_red=1 history_only_green=1' % args.document.name)
        print(f'CLOSEOUT_DOCS file={args.document.name} routes={count} extra_control=1 duplicate_control=1')


if __name__ == '__main__': main()
