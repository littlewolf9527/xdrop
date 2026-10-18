import { it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { ElTooltip } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import { messages } from '../src/i18n'
import { mockPlugin } from '../mock/server'
import type { ViteDevServer } from 'vite'
const { state } = vi.hoisted(() => ({ state: { rules: {}, top: {
  rules: [{ rule_id: 'A', target: '192.0.2.1', dropped_pps: 100, dropped_bytes_ps: 1000, share: null }],
  targets: [{ target: '192.0.2.1', dropped_pps: 100, dropped_bytes_ps: 1000, share: null }],
} } }))
vi.mock('../src/state', () => ({ state }))
import TopTable from '../src/components/TopTable.vue'
const help = {
  'zh-CN': '占比 = 该行丢包 ÷ 全部规则清洗丢包之和；有节点未上报时只按已上报的节点计算。',
  'ja-JP': '割合 = この行の破棄パケット数 ÷ 全ルールによる破棄パケット数の合計。未報告のノードがある場合は、報告済みのノードのみで計算します。',
  'en-US': 'Share = packets dropped by this row ÷ total packets dropped by all rules; if some nodes have not reported, only nodes that have reported are included.',
}
it.each(['zh-CN', 'ja-JP', 'en-US'] as const)('C5D2 share help %s', locale => {
  for (const rules of [false, true]) {
    const w = mount(TopTable, { props: { rules }, global: { plugins: [createI18n({ legacy: false, locale, messages })] } })
    expect(w.get('thead .rule-help').attributes('type')).toBe('button')
    expect(w.get('thead .rule-help').text()).toBe('')
    expect(w.findComponent(QuestionFilled).exists()).toBe(true)
    expect(messages[locale].shareHelp).toBe(help[locale])
    expect(w.getComponent(ElTooltip).props('content')).toBe(help[locale])
    expect(w.getComponent(ElTooltip).props('trigger')).toEqual(['hover', 'click'])
    expect(w.getComponent(ElTooltip).props('popperClass')).toBe('rule-help-popover')
    w.unmount()
  }
})
it.each([false, true])('C5D2 null share stays empty rules=%s', rules => {
  const w = mount(TopTable, { props: { rules }, global: { plugins: [createI18n({ legacy: false, locale: 'zh-CN', messages })] } })
  expect(w.get('td.num.muted').text()).toBe('—')
  expect((w.get('td.heat').element as HTMLElement).style.getPropertyValue('--w')).toBe('0%')
  w.unmount()
})
it('C5D2 mock populated rows have finite nonnull shares at most one', async () => {
  vi.useFakeTimers()
  try {
    let handler!: (req: unknown, res: unknown, next: () => void) => Promise<unknown>
    const server = { middlewares: { use: (fn: typeof handler) => { handler = fn } }, httpServer: { once: vi.fn() } }
    const plugin = mockPlugin(), configure = plugin.configureServer
    if (typeof configure !== 'function') throw new Error('missing configureServer')
    await configure.call({} as never, server as unknown as ViteDevServer)
    await handler({ url: '/api/v1/auth/login', method: 'POST', headers: {}, async *[Symbol.asyncIterator]() { yield JSON.stringify({ username: 'admin', password: 'example-password-1' }) } },
      { setHeader: vi.fn(), end: vi.fn() }, () => { throw new Error('unhandled login') })
    let raw = ''
    await handler({ url: '/api/v1/traffic/top', method: 'GET', headers: { cookie: 'xdrop_session=development-1' } },
      { setHeader: vi.fn(), end: (body: string) => { raw = body } }, () => { throw new Error('unhandled top') })
    const top = JSON.parse(raw)
    expect(top.rules).toHaveLength(5); expect(top.targets).toHaveLength(5)
    for (const row of [...top.rules, ...top.targets]) {
      expect(typeof row.share).toBe('number'); expect(Number.isFinite(row.share)).toBe(true)
      expect(row.share).toBeGreaterThan(0); expect(row.share).toBeLessThanOrEqual(1)
    }
  } finally { vi.clearAllTimers(); vi.useRealTimers() }
})
