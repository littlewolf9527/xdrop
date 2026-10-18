import {
  describe, it, expect
} from 'vitest'
import ts from 'typescript'
import rawTypes from '../src/api/types.ts?raw'
import {
  contracts
} from '../src/api/contract'
import {
  messages
} from '../src/i18n'
const source = ts.createSourceFile('types.ts', rawTypes, ts.ScriptTarget.Latest, true)
const interfaces = new Map<string, ts.InterfaceDeclaration>()
source.forEachChild(n => {
  if (ts.isInterfaceDeclaration(n)) interfaces.set(n.name.text, n)
})
function leaves(node: ts.TypeNode, prefix = '', inheritedNull = false): {
  path: string;
  nullable: boolean
}[] {
  if (ts.isUnionTypeNode(node)) {
    const nullable = inheritedNull || node.types.some(n => n.getText(source) === 'null')
    return node.types.filter(n => n.getText(source) !== 'null').flatMap(n => leaves(n, prefix, nullable))

  }
  if (ts.isArrayTypeNode(node)) return node.elementType.kind === ts.SyntaxKind.UnknownKeyword ? [{
    path: prefix, nullable: inheritedNull
  }] : leaves(node.elementType, prefix + '[]', inheritedNull)
  if (ts.isTypeReferenceNode(node)) {
    const shape = interfaces.get(node.typeName.getText(source))
    if (shape) return [
      ...(shape.heritageClauses || []).flatMap(c => c.types.flatMap(t => interfaceLeaves(t.expression.getText(source), prefix, inheritedNull))),
      ...shape.members.flatMap(m => ts.isPropertySignature(m) && m.type ? leaves(m.type, prefix ? prefix + '.' + m.name.getText(source) :
        m.name.getText(source), inheritedNull) : []),
    ]

  }
  return [{
    path: prefix, nullable: inheritedNull
  }]
}
function interfaceLeaves(name: string, prefix: string, inheritedNull: boolean): {
  path: string;
  nullable: boolean
}[] {
  const shape = interfaces.get(name)
  if (!shape) throw new Error('Unknown interface ' + name)
  return [...(shape.heritageClauses || []).flatMap(c => c.types.flatMap(t => interfaceLeaves(t.expression.getText(source), prefix,
    inheritedNull))), ...shape.members.flatMap(m => ts.isPropertySignature(m) && m.type ? leaves(m.type, prefix ? prefix + '.' +
      m.name.getText(source) : m.name.getText(source), inheritedNull) : [])]
}
function flatten(value: Record<string, unknown>, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(value).flatMap(([k, v]) => typeof v === 'string' ? [[prefix + k, v]] : Object.entries(flatten(
    v as Record<string, unknown>, prefix + k + '.'))))
}
const forbidden = /钥匙|放行|下发|限流|锁定|重试|稍后|原型|示例/g
export const forbiddenCount = (value: Record<string, unknown>) => Object.values(flatten(value)).join('\n').match(forbidden)?.length || 0
describe('contract and language gates', () => {
  it('reverse coverage for every UI response field and nullable parent', () => {
    const map = interfaces.get('ResponseMap')!
    expect(map.members.some(m => ts.isPropertySignature(m) && m.name.getText(source) === 'error')).toBe(true)
    expect(contracts.filter(e => e.root === 'error' && e.status === 401).map(e => e.path).sort()).toEqual(['code', 'message'])
    for (const member of map.members) if (ts.isPropertySignature(member) && member.type) {
      const root = member.name.getText(source), groups = [...new Set(contracts.filter(e => e.root === root).map(e => e.endpoint + '|' + (
        e.event || '')))]
      expect(groups.length, root).toBeGreaterThan(0)
      for (const group of groups) for (const field of leaves(member.type)) {
        const entry = contracts.find(e => e.root === root && e.endpoint + '|' + (e.event || '') === group && e.path === field.path)
        expect(entry, `${root} ${group} ${field.path}`).toBeDefined()
        if (field.nullable) expect(entry?.nullable, field.path).toBe(true)

      }

    }

  })
  it('all three dictionaries have identical nonempty keys', () => {
    const keys = Object.keys(flatten(messages['zh-CN'])).sort();
    for (const values of Object.values(messages)) {
      expect(Object.keys(flatten(values)).sort()).toEqual(keys);
      expect(Object.values(flatten(values)).every(v => v.trim())).toBe(true)
    }
  })
  it('V10 Chinese forbidden words and positive control', () => {
    expect(forbiddenCount({
      fake: 'API 钥匙；放行；下发；限流；锁定；重试；稍后；原型；示例'
    })).toBe(9);
    expect(forbiddenCount(messages['zh-CN'])).toBe(0)
  })
})

it('V-r9g error code and message remain in the response contract', () => {
  const map = interfaces.get('ResponseMap')!
  expect(map.members.some(m => ts.isPropertySignature(m) && m.name.getText(source) === 'error')).toBe(true)
  expect(contracts.filter(e => e.root === 'error' && e.status === 401).map(e => e.path).sort()).toEqual(['code', 'message'])
})

it('settings response additions cover four DTOs, both Node transports and three nullable credential fields', () => {
  const required = {
    users: ['[].username','[].role','[].created_at','[].created_by','[].password_changed_at'],
    credentials: ['[].id','[].name','[].created_at','[].created_by','[].retire_at','[].revoked_at','[].revoked_by','[].active'],
    issued: ['id','name','key','created_at','retired[].id','retired[].retire_at'],
    nodeTest: ['reachable','compatible','key_accepted','message'],
    settings: ['session_hours','audit_retention_days','history_retention_days','reconcile_interval_minutes','default_language'],
  }
  for (const [root, fields] of Object.entries(required)) for (const path of fields) expect(contracts.some(e => e.root === root && e.path === path), root + ' ' + path).toBe(true)
  for (const path of ['[].retire_at','[].revoked_at','[].revoked_by']) expect(contracts.find(e => e.root === 'credentials' && e.path === path)?.nullable).toBe(true)
  for (const endpoint of ['GET /api/v1/nodes','GET /api/v1/events']) for (const path of ['nodes[].base_url','nodes[].key_unreadable']) expect(contracts.some(e => e.root === 'nodes' && e.endpoint === endpoint && e.path === path)).toBe(true)
})
