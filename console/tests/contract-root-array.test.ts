import { it, expect, vi } from 'vitest'
vi.mock('node:fs/promises', () => ({ readFile: async () => 'export const contracts: ContractEntry[] = []// END CONTRACT JSON' }))
vi.mock('node:url', () => ({ fileURLToPath: () => '/__test_contract_root__.mjs' }))
// @ts-expect-error Existing declaration omits this JavaScript export; that declaration is frozen.
import { resolvePath } from '../scripts/contract-check.mjs'
it('G10 V19 root array hit, missing member, empty uncovered; nested arrays unchanged', () => {
  expect(resolvePath([{id:'a'},{id:'b'}],'[].id')).toBe('hit')
  expect(resolvePath([{id:'a'},{}],'[].id')).toBe('missing')
  expect(resolvePath([],'[].id')).toBe('uncovered')
  expect(resolvePath({items:[{x:1}]},'items[].x')).toBe('hit')
  expect(resolvePath({items:[{x:1},{}]},'items[].x')).toBe('missing')
  expect(resolvePath({items:[]},'items[].x')).toBe('uncovered')
})
