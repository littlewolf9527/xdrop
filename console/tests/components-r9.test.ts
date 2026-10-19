import { it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { messages } from '../src/i18n'
import type { Node, Rule } from '../src/api/types'
const { state } = vi.hoisted(() => ({ state: {
  top: { targets: [] as { target: string; dropped_pps: number; dropped_bytes_ps: number; share: number | null }[],
    rules: [] as { rule_id: string; target: string; dropped_pps: number; dropped_bytes_ps: number; share: number | null }[] },
  rules: {} as Record<string, Rule>, theme: 'light', now: 0, range: '15m',
  history: { step_s: 5, points: [] as { t: number; dropped_pps: number; passed_pps: number; dropped_bytes_ps: number; passed_bytes_ps: number }[] }
} }))
vi.mock('../src/state', () => ({ state, request: vi.fn(), captureSession: vi.fn() }))
vi.mock('vue-echarts', () => ({ default: { name: 'ChartProbe', props: ['option'], template: '<div />' } }))
import TopTable from '../src/components/TopTable.vue'
import TrafficChart from '../src/components/TrafficChart.vue'
import NodeTable from '../src/components/NodeTable.vue'
const global = () => ({ plugins: [createI18n({ legacy: false, locale: 'zh-CN', messages })] })
it.each([false, true])('V-r9h actual TopTable escapes target markup rules=%s', rules => {
  const target = '<img data-probe="target" onerror="void 0">'
  state.top.targets = [{ target, dropped_pps: 1, dropped_bytes_ps: 2, share: 1 }]
  state.top.rules = [{ ...state.top.targets[0]!, rule_id: 'test-rule' }]
  const wrapper = mount(TopTable, { props: { rules }, global: global() })
  expect(wrapper.text()).toContain(target)
  expect(wrapper.find('img[data-probe="target"]').exists()).toBe(false)
  wrapper.unmount()
})
it.each([false, true])('V-r9i actual chart option keeps missing buckets disconnected bytes=%s', bytes => {
  state.history.points = [101, 116].map(t => ({ t, dropped_pps: 1, passed_pps: 2, dropped_bytes_ps: 3, passed_bytes_ps: 4 }))
  const wrapper = mount(TrafficChart, { props: { bytes }, global: global() })
  const option = wrapper.findComponent({ name: 'ChartProbe' }).props('option') as {
    series: { connectNulls: boolean; data: [number, number | null][] }[]
  }
  expect(option.series).toHaveLength(2)
  for (const series of option.series) {
    expect(series.connectNulls).not.toBe(true)
    expect(series.data.map(point => point[0])).toEqual([101000, 106000, 111000, 116000])
    expect(series.data.slice(1, 3).map(point => point[1])).toEqual([null, null])
  }
  wrapper.unmount()
})
it('V-r9j actual NodeTable suppresses cached offline rates and online null rates', () => {
  const side = { state: 'normal', reason: '', confirmed_gen: 1, confirmable: true, rejected: [] }
  const node: Node = { name: 'edge-03', online: false, base_url: "http://192.0.2.1", key_unreadable: false, incompatible: false, rules: side, whitelist: side,
    health_at: '', health: { rules_synced: true, whitelist_synced: true }, stats: null,
    rates: { dropped_packets: 100, passed_packets: 200, dropped_bytes: 300, passed_bytes: 400 } }
  const nodes = [node, { ...node, name: 'edge-01', online: true, rates: null },
    { ...node, name: 'edge-02', stats: { system: { cpu_percent: 42, mem_percent: 43 } } }]
  const wrapper = mount(NodeTable, { props: { nodes }, global: global() })
  const rates = wrapper.findAll('.rate-pair span')
  expect(rates).toHaveLength(12)
  expect(rates.map(cell => cell.text())).toEqual(Array(12).fill('—'))
  wrapper.unmount()
})

it('V-td149 NodeTable deep chain column: cumulative count, muted zero, dash when offline or unreported', () => {
  const side = { state: 'normal', reason: '', confirmed_gen: 1, confirmable: true, rejected: [] }
  const node: Node = { name: 'edge-01', online: true, base_url: "http://192.0.2.1", key_unreadable: false, incompatible: false, rules: side, whitelist: side,
    health_at: '', health: { rules_synced: true, whitelist_synced: true },
    rates: { dropped_packets: 900, passed_packets: 47, dropped_bytes: 9000, passed_bytes: 4700 },
    stats: { system: { cpu_percent: 1, mem_percent: 2 }, ipv6_deep_chain_dropped: 1284 } }
  const nodes = [node, { ...node, name: 'edge-02', stats: { system: { cpu_percent: 1, mem_percent: 2 }, ipv6_deep_chain_dropped: 0 } },
    { ...node, name: 'edge-03', online: false }, { ...node, name: 'edge-04', stats: { system: { cpu_percent: 1, mem_percent: 2 } } },
    { ...node, name: 'edge-05', stats: null }]
  const wrapper = mount(NodeTable, { props: { nodes }, global: global() })
  const cells = wrapper.findAll('td.deep-chain')
  expect(cells.map(cell => cell.text())).toEqual(['1,284', '0', '—', '—', '—'])
  expect(cells.map(cell => cell.classes().filter(c => c === 'warn' || c === 'muted'))).toEqual([['warn'], ['muted'], [], [], []])
  expect(wrapper.findAll('thead th').map(th => th.text()).slice(2, 4)).toEqual(['丢弃', '深链?'])
  // Every row has one cell per header, and the deep chain cell sits under its header, not under 转发.
  const headers = wrapper.findAll('thead th').length
  for (const row of wrapper.findAll('tbody tr')) {
    const cells = row.findAll('td')
    expect(cells).toHaveLength(headers)
    expect(cells[3]!.classes()).toContain('deep-chain')
  }
  const first = wrapper.findAll('tbody tr')[0]!.findAll('td')
  expect([first[3]!.text(), first[4]!.find('span').text()]).toEqual(['1,284', '47 pps'])
  wrapper.unmount()
})

it('V-r11g cached rule description remains complete escaped text', () => {
  const target = '<img data-probe="cached-rule" onerror="void 0">'
  state.top.rules = [{ rule_id: 'cached-rule', target: '192.0.2.1', dropped_pps: 1, dropped_bytes_ps: 2, share: 1 }]
  state.rules['cached-rule'] = { logical_id: 7, dst_ip: target, dst_cidr: '', src_ip: '', src_cidr: '', protocol: 'tcp',
    src_port: 0, dst_port: 443, ttl: '64', dscp: null, icmp_type: null, icmp_code: null, fragment: null, pkt_len: null,
    tcp_flags: '', match_anomaly: 0, action: 'drop', rate_limit: 0 }
  const wrapper = mount(TopTable, { props: { rules: true }, global: global() })
  expect(wrapper.get('td.heat span').text()).toBe('#7 ' + target + ' TCP:443 TTL 64')
  expect(wrapper.find('img[data-probe="cached-rule"]').exists()).toBe(false)
  wrapper.unmount(); state.rules = {}
})
it.each([false, true])('V-r13a chart zero label omits scaled suffix bytes=%s', bytes => {
  state.history.points = [100, 105].map(t => ({ t, dropped_pps: 1200000, passed_pps: 320000,
    dropped_bytes_ps: 780000000, passed_bytes_ps: 250000000 }))
  const wrapper = mount(TrafficChart, { props: { bytes }, global: global() })
  const option = wrapper.findComponent({ name: 'ChartProbe' }).props('option') as {
    yAxis: { interval: number; axisLabel: { formatter(value: number): string } }
  }
  expect(option.yAxis.axisLabel.formatter(0)).toBe('0')
  expect(option.yAxis.axisLabel.formatter(1)).toBe(bytes ? '1G' : '1M')
  expect(Number.isInteger(option.yAxis.interval)).toBe(true)
  wrapper.unmount()
})
