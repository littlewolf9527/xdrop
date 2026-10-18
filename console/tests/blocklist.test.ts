import { it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import { i18n, messages } from '../src/i18n'
vi.mock('../src/state', async () => ({
  state: (await import('vue')).reactive({ user: { name: 'admin', role: 'admin' }, nodes: [], error: '', rules: {},
    capacity: { tightest: { name: 'blacklist', ratio: 0, exhausted: false }, dimensions: [] },
    top: { updated_at: null, targets_total: 0 }, overview: { dropped_pps: 0, passed_pps: 0, dropped_bytes_ps: 0, passed_bytes_ps: 0, nodes_online: 0, nodes_total: 0 },
    now: Date.now(), range: '15m', layout: { order: ['pps', 'bps', 'ip', 'rules'], split: 1 } }),
  canSettings: true, logout: vi.fn(), setRange: vi.fn(), restoreLayout: vi.fn(), swapPanels: vi.fn(), setSplit: vi.fn(),
  captureSession: () => ({ isCurrent: () => true }), request: vi.fn(async (path: string) => path.startsWith('/traffic') ? { rules: [], updated_at: null } : { items: [], next_after: null, counts: { all: 0, drop: 0, rate_limit: 0, disabled: 0 } })
}))
import App from '../src/App.vue'
import Rules from '../src/views/Rules.vue'
import Overview from '../src/views/Overview.vue'
afterEach(() => { i18n.global.locale.value = 'zh-CN' })
it.each([
  ['zh-CN', '黑名单', '白名单', '规则', '新建规则', '清洗规则', '规则容量'],
  ['ja-JP', 'ブロックリスト', '許可リスト', 'ルール', '新規', 'フィルター', 'ルール容量'],
  ['en-US', 'Blocklist', 'Allowlist', 'Rules', 'Create', 'Filters', 'Rule capacity'],
] as const)('R14-1 %s blocklist navigation and heading preserve rule terminology and route', async (lang, blocklist, whitelist, rules, createRule, topRules, ruleCapacity) => {
  i18n.global.locale.value = lang
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/rules', component: Rules }, { path: '/overview', component: Overview }, { path: '/:pathMatch(.*)*', component: { template: '<div />' } }] })
  await router.push('/rules'); await router.isReady()
  const w = mount(App, { global: { plugins: [router, i18n], stubs: { Preferences: true, ElDialog: true, TrafficChart: true, TopTable: true, NodeTable: true } } })
  try {
    await flushPromises()
    const links = w.findAll('.nav a')
    expect(links[1]!.text()).toBe(blocklist); expect(links[1]!.attributes('href')).toBe('/rules'); expect(links[1]!.attributes('aria-current')).toBe('page')
    expect(links[2]!.text()).toBe(whitelist); expect(links[2]!.attributes('href')).toBe('/whitelist')
    expect(router.currentRoute.value.path).toBe('/rules'); expect(w.get('.rules-page h1').text()).toBe(blocklist)
    expect(w.get('.rules-page .btn.primary').text()).toBe(createRule); expect(w.get('.cap > span').text()).toBe(ruleCapacity)
    expect(messages[lang].rules).toBe(rules)
    await router.push('/overview'); await flushPromises()
    const panel = w.findAll('.panel').find(p => p.find('a[href="/rules"]').exists())!
    expect(panel.get('h2').text()).toContain(topRules); expect(panel.get('h2').text()).toContain('Top 5')
    expect(panel.get('a[href="/rules"]').attributes('href')).toBe('/rules'); expect(w.get('.cap > span').text()).toBe(ruleCapacity)
  } finally { w.unmount() }
})
