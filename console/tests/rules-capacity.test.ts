import { it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ElDialog } from 'element-plus'
import { i18n, messages } from '../src/i18n'
import type { Capacity } from '../src/api/types'
vi.mock('vue-router', () => ({ useRoute: () => ({ path: '/rules' }) }))
vi.mock('../src/state', async () => ({ state: (await import('vue')).reactive({ capacity: null, nodes: [], user: { name: 'admin' }, error: '', lang: 'zh-CN', theme: 'light' }), canSettings: true, logout: vi.fn(), setLanguage: vi.fn(), setTheme: vi.fn() }))
import { state } from '../src/state'
import App from '../src/App.vue'
const dims = Object.keys(messages['zh-CN'].dimensions).map((name, i) => ({ name, used: 1000 + i * 100, admission_limit: 10000, ratio: (1000 + i * 100) / 10000, exhausted: false, limit_source: 'config' }))
function capacity(): Capacity { return { tightest: { name: dims[9]!.name, ratio: .19, exhausted: false }, dimensions: dims.map(d => ({ ...d })) } }
const app = () => mount(App, { attachTo: document.body, global: { plugins: [i18n], stubs: { RouterLink: { template: '<a><slot /></a>' }, RouterView: true, Preferences: true, transition: false } } })
afterEach(() => { state.capacity = null; i18n.global.locale.value = 'zh-CN' })
it.each(['zh-CN','ja-JP','en-US'] as const)('R10-1 %s capacity title, every dimension and Escape focus return', async lang => {
  i18n.global.locale.value = lang; state.capacity = capacity(); const w = app(), button = w.get('.cap')
  expect(button.get('span').text()).toBe(messages[lang].ruleCapacity); expect(button.text()).toContain('19%')
  expect(button.attributes('aria-haspopup')).toBe('dialog'); expect(button.attributes('aria-expanded')).toBeUndefined()
  expect(button.attributes('title')).toContain(messages[lang].capacityHelp); expect(button.attributes('title')).toContain(messages[lang].dimensions.logical_state)
  ;(button.element as HTMLElement).focus(); await button.trigger('click'); await flushPromises()
  const dialog = w.findComponent(ElDialog), element = document.querySelector('[role=dialog]')!
  expect(dialog.props('modelValue')).toBe(true); expect(element).not.toBeNull()
  const rows = element.querySelectorAll('tbody tr'); expect(rows.length).toBe(dims.length)
  for (const [i,d] of dims.entries()) {
    const cells = rows[i]!.querySelectorAll('td')
    expect(cells[0]!.textContent).toBe((messages[lang].dimensions as Record<string,string>)[d.name]); expect(cells[2]!.textContent).toBe(Math.round(d.ratio * 100) + '%')
    expect(cells[3]!.textContent).toBe(d.used.toLocaleString(lang) + ' / ' + d.admission_limit.toLocaleString(lang))
  }
  document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true })); await flushPromises()
  await vi.waitFor(() => expect(dialog.props('modelValue')).toBe(false)); await vi.waitFor(() => expect(document.activeElement).toBe(button.element)); expect(w.find('.capdrop').exists()).toBe(false)
  w.unmount()
})
it('R10-2 open capacity modal follows pushed capacity rather than a snapshot', async () => {
  state.capacity = capacity(); const w = app(); await w.get('.cap').trigger('click'); await flushPromises()
  state.capacity = { ...capacity(), dimensions: dims.map((d,i) => ({ ...d, used: 5100+i*100, ratio: (5100+i*100)/10000 })) }; await flushPromises()
  const rows = document.querySelectorAll('.capacity-table tbody tr')
  expect(rows.length).toBe(dims.length)
  state.capacity.dimensions.forEach((d,i) => { expect(rows[i]!.textContent).toContain(Math.round(d.ratio! * 100) + '%'); expect(rows[i]!.textContent).toContain(d.used.toLocaleString('zh-CN') + ' / ' + d.admission_limit.toLocaleString('zh-CN')) })
  w.unmount()
  state.capacity = null; const empty = app(); expect(empty.find('.cap').exists()).toBe(false); expect(empty.findComponent(ElDialog).exists()).toBe(false); empty.unmount()
})
