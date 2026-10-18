"""Translate business writes; never consult historical Expect/Hits fields."""
import copy
from reference_closeout import State, groupkey, identity, normalized

RULES = '/api/v1/rules'
WL = '/api/v1/whitelist'


def translate(step, state, case):
    out = copy.deepcopy(step)
    method, path, body = step['Method'], step.get('Path', ''), step.get('Body')
    if method == 'RESTART':
        rules = [{k: v for k, v in r.items() if k != 'enabled'} for r in body['rules'] if r.get('enabled', True)]
        out['Requests'] = [dict(Method='POST', Path='/api/v1/sync/atomic', Body=dict(rules=rules)),
                           dict(Method='POST', Path='/api/v1/sync/whitelist', Body=dict(entries=[]))]
        return out, '§3 Q-A8: restart then push atomic and empty whitelist'
    if path.startswith(WL) and method in ('POST', 'DELETE'):
        current = {r['id']: copy.deepcopy(r) for r in state.whitelist}
        if method == 'DELETE':
            ids = body['ids'] if path.endswith('/batch') else [path.rsplit('/', 1)[1]]
            for id in ids: current.pop(id, None)
        else:
            for r in body['entries'] if path.endswith('/batch') else [body]: current[r['id']] = r
        out.update(Method='POST', Path='/api/v1/sync/whitelist', Body=dict(entries=list(current.values())))
        return out, '§3 Q-W: full whitelist; incremental response contract retired'
    if not (path == RULES or path.startswith(RULES+'/')) or method not in ('POST', 'PUT', 'DELETE') or path == RULES+'/commit':
        return out, None
    # DELETE with no matching member has no group key to declare: the retired
    # not-found entry contract executes as a literal 404, without invented keys.
    current = {r['id']: copy.deepcopy(r) for r in state.installed}
    declared = {}
    if method == 'DELETE':
        ids = body['ids'] if path.endswith('/batch') else [path.rsplit('/', 1)[1]]
        incoming = []
    else:
        incoming = body['rules'] if path.endswith('/batch') else [body]
        incoming = list({r['id']: r for r in incoming}.values())
        ids = [r['id'] for r in incoming]
    for id in ids:
        old = current.pop(id, None)
        if old: declared[groupkey(old)] = identity(old)
    for r in incoming:
        r = normalized(r)
        declared[groupkey(r)] = identity(r)
        current[r['id']] = r
    if not declared:
        return out, '§3 A2: entry contract retired; absent delete executes 404'
    groups = [dict(key=key, rules=[r for r in current.values() if groupkey(r) == k]) for k, key in declared.items()]
    out.update(Method='POST', Path=RULES+'/commit', Body=dict(groups=groups))
    if case == 'scenarios_commit_p5/I15_failure_9a/retire': out['Fault'] = 'Rc'
    return out, '§3 A2: whole-group commit; incremental/batch entry contract retired'


def translate_scenes(scenes):
    migration = []
    for scene in scenes:
        state = State()
        for index, source in enumerate(scene['Steps']):
            case = scene['Name']+'/'+source['Name']
            step, reason = translate(source, state, case)
            if step.get('Fault') == 'c-2':
                step['Fault'] = step['SourceFault'] = ''
                reason = 'PLAN 4-3/4-6: c-2 withdrawal injection retired; request retained under protocol 8'
            if reason:
                migration.append(dict(case=case, reason=reason, source=dict(Method=source['Method'], Path=source.get('Path', '')),
                                      translated=dict(Method=step['Method'], Path=step.get('Path', ''), Requests=len(step.get('Requests', [step])))))
            scene['Steps'][index] = step
            state.request(step)
    return migration
