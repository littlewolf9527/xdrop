import { it, expect, vi } from 'vitest'
// Isolate CLI startup I/O; the prerequisite and path resolver stay real.
vi.mock('node:fs/promises', () => ({
  readFile: async () => 'export const contracts: ContractEntry[] = []// END CONTRACT JSON'
}))
vi.mock('node:url', () => ({ fileURLToPath: () => '/__test_contract_check__.mjs' }))
import * as contractCheck from '../scripts/contract-check.mjs'
const { requireSampledCPU } = contractCheck
const { resolvePath } = contractCheck as typeof contractCheck & {
  resolvePath(value: unknown, path: string, nullable?: boolean): 'hit' | 'missing' | 'uncovered'
}

it('V-r8 lab CPU prerequisite accepts any sampled node and rejects unsampled lists', () => {
  const offline = { name: 'edge-03', online: false, stats: null }
  const online = { name: 'edge-01', online: true, stats: { system: { cpu_percent: 12.5 } } }
  expect(() => requireSampledCPU({ nodes: [offline, online] })).not.toThrow()
  expect(() => requireSampledCPU({ nodes: [online, offline] })).not.toThrow()
  expect(() => requireSampledCPU({ nodes: [{ stats: { system: { cpu_percent: 0 } } }] })).not.toThrow()
  for (const nodes of [[offline, { name: 'edge-02', stats: null }], []]) {
    expect(() => requireSampledCPU({ nodes })).toThrow('Lab node control requires a sampled CPU value')
  }
})

it('V-r11h real path resolver prioritizes partial missing arrays and handles nullable parents', () => {
  const path = 'nodes[].rates.dropped_packets'
  expect(resolvePath({ nodes: [{ rates: { dropped_packets: 1 } }, { rates: { passed_packets: 2 } }] }, path)).toBe('missing')
  expect(resolvePath({ nodes: [] }, path)).toBe('uncovered')
  expect(resolvePath({ nodes: [{ rates: null }] }, path, true)).toBe('hit')
  expect(resolvePath({ nodes: [{ rates: { dropped_packets: 1 } }, { rates: { dropped_packets: 2 } }] }, path)).toBe('hit')
})
