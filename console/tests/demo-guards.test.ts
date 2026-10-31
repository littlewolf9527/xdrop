// @vitest-environment node
import { expect, it } from 'vitest'
import ts from 'typescript'
import { readFileSync } from 'node:fs'

it('G13 entry has exactly the ordered shim, application and badge statements', () => {
  const source = ts.createSourceFile('main.ts', readFileSync(new URL('../demo/main.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  expect(source.statements).toHaveLength(3)
  const first = source.statements[0]!
  expect(ts.isImportDeclaration(first)).toBe(true)
  if (!ts.isImportDeclaration(first)) throw new Error('Missing shim import')
  expect(first.importClause).toBeUndefined()
  expect(ts.isStringLiteral(first.moduleSpecifier) && first.moduleSpecifier.text).toBe('./shim')
  for (const [index, path] of [[1, '../src/main'], [2, './badge']] as const) {
    const statement = source.statements[index]!
    expect(ts.isExpressionStatement(statement)).toBe(true)
    if (!ts.isExpressionStatement(statement) || !ts.isAwaitExpression(statement.expression)) throw new Error('Expected top-level awaited import')
    const expression = statement.expression.expression
    expect(ts.isCallExpression(expression)).toBe(true)
    if (!ts.isCallExpression(expression)) throw new Error('Missing import call')
    expect(expression.expression.kind).toBe(ts.SyntaxKind.ImportKeyword)
    expect(expression.arguments).toHaveLength(1)
    const argument = expression.arguments[0]!
    expect(ts.isStringLiteral(argument) && argument.text).toBe(path)
  }
})

it('G11 Pages workflow has exactly the approved actions, triggers and permissions', () => {
  const text = readFileSync(new URL('../../.github/workflows/demo.yml', import.meta.url), 'utf8')
  const actions = [
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e',
    'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1',
    'actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d',
    'actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9',
    'actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346',
  ]
  const uses = [...text.matchAll(/uses:\s*([^\s#]+)/g)].map(match => match[1])
  expect(uses).toEqual(actions)
  for (const action of uses) expect(action).toMatch(/^actions\/[a-z-]+@[a-f0-9]{40}$/)
  const permissions = /^permissions:\n((?:[ \t].*\n)+)/m.exec(text)?.[1]
  expect(permissions?.trim().split('\n').map(line => line.trim()).sort()).toEqual(['contents: read','id-token: write','pages: write'])
  expect(text).not.toContain('secrets.')
  expect(text).not.toContain('pull_request')
  expect(text).toMatch(/^on:\n  push:\n    branches: \[main\]\n/m)
  expect(text).toMatch(/^  workflow_dispatch:\s*$/m)
  const paths = /    paths:\n((?:      - .*\n)+)/.exec(text)?.[1]
  expect(paths?.trim().split('\n').map(line => line.trim().replace(/^- ['"]?|['"]$/g, ''))).toEqual([
    'console/**','controller/go.mod','controller/go.sum','node/agent/go.mod','node/agent/go.sum','node/bpf/**','.github/workflows/demo.yml',
  ])
  expect(text).toMatch(/concurrency:\n  group: pages\n  cancel-in-progress: false/)
  expect(text).toMatch(/  build:\n    runs-on: ubuntu-latest/)
  expect(text).toMatch(/  deploy:\n    runs-on: ubuntu-latest\n    needs: build/)
  expect(text).toContain('fetch-depth: 0')
  expect(text).toContain('go-version-file: node/agent/go.mod')
  expect(text).toContain("node-version: '24'")
  expect(text).toContain('cache: npm')
  expect(text).toContain('cache-dependency-path: console/package-lock.json')
  expect(text).toMatch(/- run: npm ci\n        working-directory: console/)
  expect(text).toMatch(/- run: XDROP_VERSION=\$\(git describe --tags --always\) npm run build:demo\n        working-directory: console/)
  expect(text).toMatch(/uses: actions\/upload-pages-artifact@[^\n]+\n        with:\n          path: console\/demo-dist/)
  expect(text).toMatch(/environment:\n      name: github-pages\n      url: \$\{\{ steps\.deployment\.outputs\.page_url \}\}/)
  expect(text).toMatch(/uses: actions\/deploy-pages@[^\n]+\n        id: deployment/)
})
