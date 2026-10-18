import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { i18n, messages } from '../src/i18n'
const hooks = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('../src/state', () => ({ request: hooks.request, captureSession: () => ({ isCurrent: () => true }), state: { user: { name: 'admin', role: 'admin' }, rules: {} } }))
import TemplatesTab from '../src/components/settings/TemplatesTab.vue'
import RuleDrawer from '../src/components/RuleDrawer.vue'
import WhitelistDrawer from '../src/components/WhitelistDrawer.vue'
import ImportDrawer from '../src/components/ImportDrawer.vue'
import { isOpenSelectTarget } from '../src/api/types'
import { templateCheck, templateCount } from '../src/settings'
import { parseImport } from '../src/import'
const wrappers: VueWrapper[] = []
const example = () => messages['zh-CN'].settingsUI.exampleRules
const button = (w: VueWrapper, text: string) => w.findAll('button').find(b => b.text() === text)!
async function form() {
  const w = mount(TemplatesTab, { attachTo: document.body, global: { plugins: [i18n] } }); wrappers.push(w)
  await flushPromises(); await button(w, '新建模板').trigger('click')
  return w
}
beforeEach(() => { i18n.global.locale.value = 'zh-CN'; hooks.request.mockReset().mockResolvedValue([]) })
afterEach(() => { wrappers.splice(0).forEach(w => w.unmount()) })
it('G2 details starts closed, then exposes seven fields and the complete five-line example', async () => {
  const w = await form(), details = w.get('details')
  expect(details.attributes('open')).toBeUndefined()
  expect(details.get('summary').text()).toBe('写法说明')
  ;(details.element as HTMLDetailsElement).open = true
  expect(details.element.hasAttribute('open')).toBe(true)
  expect(details.findAll('th code').map(c => c.text())).toEqual(['protocol','src_port','dst_port','tcp_flags','action','rate_limit','expires_in'])
  expect(details.get('pre').text()).toBe(example()); expect(example().split('\n')).toHaveLength(5)
  expect(example().split('\n')[0]).toBe('# DNS / NTP 反射：丢弃源端口 53、123 的 UDP，6 小时后失效')
  expect(example().split('\n')[3]).toBe('# SYN 洪水：SYN 置位且 ACK 未置位的 TCP 限速到每秒 5 万包')
})
it.each(['', '  \t', 'protocol=udp', 'protocol=udp\n'])('G2 append preserves prefix %j without extra newline', async prefix => {
  const w = await form(); await w.get('[name="body"]').setValue(prefix); await w.get('[name="name"]').setValue('DNS')
  await button(w, '填入范例').trigger('click')
  const value = (w.get('textarea').element as HTMLTextAreaElement).value
  expect(value).toBe(prefix + (prefix && !prefix.endsWith('\n') ? '\n' : '') + example())
  expect(templateCheck(value)).toEqual([]); expect(w.findAll('[role="alert"]')).toHaveLength(0)
  expect(button(w, '保存').attributes('disabled')).toBeUndefined()
})
it('G2 illegal prefix remains on line one after append', async () => {
  const w = await form(); await w.get('[name="body"]').setValue('a=1'); await button(w, '填入范例').trigger('click')
  const value = (w.get('textarea').element as HTMLTextAreaElement).value
  expect(value.startsWith('a=1\n')).toBe(true); expect(templateCheck(value)).toEqual([{ no: 1, key: 'templateLex' }])
  expect(w.get('[role="alert"]').text()).toContain('1'); expect(button(w, '保存').attributes('disabled')).toBeDefined()
})
it('G2 append is type button', async () => { const w = await form(); expect(button(w, '填入范例').attributes('type')).toBe('button') })
it('G2 V10 native click does not submit or send requests', async () => {
  const w = await form(); await w.get('[name="name"]').setValue('DNS'); await w.get('[name="body"]').setValue('protocol=udp')
  hooks.request.mockClear(); (button(w, '填入范例').element as HTMLButtonElement).click(); await flushPromises()
  expect(hooks.request).not.toHaveBeenCalled(); expect(w.find('form').exists()).toBe(true)
})
it('G2 append is disabled during writing', async () => {
  const w = await form(); await w.get('[name="name"]').setValue('DNS'); await w.get('[name="body"]').setValue('protocol=udp')
  let release!: (value: unknown) => void
  hooks.request.mockReturnValueOnce(new Promise(resolve => { release = resolve }))
  await w.get('form').trigger('submit'); expect(button(w, '填入范例').attributes('disabled')).toBeDefined()
  release({}); await flushPromises()
})
it.each(['zh-CN','ja-JP','en-US'] as const)('G3 %s parser accepts three rules without lexical errors', lang => {
  const rows = parseImport(messages[lang].settingsUI.exampleRules)
  expect(rows).toHaveLength(3); expect(rows.filter(row => row.lex)).toEqual([])
})
it.each(['zh-CN','ja-JP','en-US'] as const)('G3 %s fields and values match backend contract', lang => {
  expect(parseImport(messages[lang].settingsUI.exampleRules).map(row => row.patch)).toEqual([
    { protocol: 'udp', src_port: 53, action: 'drop', expires_in: '6h' },
    { protocol: 'udp', src_port: 123, action: 'drop', expires_in: '6h' },
    { protocol: 'tcp', tcp_flags: 'SYN,!ACK', action: 'rate_limit', rate_limit: 50000 },
  ])
})
it.each(['zh-CN','ja-JP','en-US'] as const)('G3 %s rate_limit is a positive integer', lang => {
  const rate = parseImport(messages[lang].settingsUI.exampleRules)[2]!.patch!.rate_limit
  expect(Number.isInteger(rate)).toBe(true); expect(rate).toBeGreaterThan(0)
})
it.each(['zh-CN','ja-JP','en-US'] as const)('G3 %s expiry is a nonzero Go duration', lang => {
  const rows = parseImport(messages[lang].settingsUI.exampleRules)
  for (const row of rows.slice(0, 2)) {
    const value = String(row.patch!.expires_in)
    expect(value).toMatch(/^([0-9]+(ns|us|µs|ms|s|m|h))+$/)
    expect((value.match(/[0-9]+/g) || []).some(n => Number(n) > 0)).toBe(true)
  }
})
it.each(['zh-CN','ja-JP','en-US'] as const)('G3 %s template count and precheck reuse existing helpers', lang => {
  const body = messages[lang].settingsUI.exampleRules
  expect(templateCount(body)).toBe(3); expect(templateCheck(body)).toEqual([])
})
it('G2 R1-1 writing prose has no literal backticks in any language', () => {
  for (const lang of ['zh-CN', 'ja-JP', 'en-US'] as const) for (const key of ['writingIntro', 'writingTarget'] as const) expect(messages[lang].settingsUI[key]).not.toContain(String.fromCharCode(96))
})
const drawerCases = [
  { name: 'RuleDrawer', component: RuleDrawer, field: '#dst_address', select: '#protocol' },
  { name: 'WhitelistDrawer', component: WhitelistDrawer, field: '#wl-dst_ip', select: '#wl-protocol' },
  { name: 'ImportDrawer', component: ImportDrawer, field: '#import-targets', select: '#import-template' },
]
for (const drawer of drawerCases) for (const mode of ['open', 'closed', 'throws'] as const) {
  it('G4 R1-4 ' + drawer.name + ' Escape with ' + mode + ' select', async () => {
    hooks.request.mockResolvedValue([{ id: 'template_1', name: 'DNS', body: 'protocol=udp' }])
    const w = mount(drawer.component, { attachTo: document.body, global: { plugins: [i18n] } }); wrappers.push(w)
    await flushPromises()
    if (drawer.name === 'ImportDrawer') { await w.findAll('[role="tab"]')[1]!.trigger('click'); await flushPromises() }
    await w.get(drawer.field).setValue('192.0.2.44')
    const select = w.get(drawer.select).element as HTMLSelectElement, nativeMatches = select.matches.bind(select)
    const spy = vi.spyOn(select, 'matches').mockImplementation(selector => {
      if (selector !== ':open') return nativeMatches(selector)
      if (mode === 'throws') throw new DOMException('Unsupported pseudo-class', 'SyntaxError')
      return mode === 'open'
    })
    const event = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    try {
      select.dispatchEvent(event); await flushPromises()
      expect(w.emitted('close') || []).toHaveLength(mode === 'open' ? 0 : 1)
      expect(event.defaultPrevented).toBe(mode !== 'open')
      expect((w.get(drawer.field).element as HTMLInputElement).value).toBe('192.0.2.44')
      expect(spy).toHaveBeenCalledWith(':open')
    } finally { spy.mockRestore() }
  })
}
it('G4 R1-4 shared target guard follows ancestors and leaves document targets unchanged', () => {
  const select = document.createElement('select'), option = document.createElement('option'), text = document.createTextNode('drop'); option.append(text); select.append(option)
  const nativeMatches = select.matches.bind(select), spy = vi.spyOn(select, 'matches').mockImplementation(selector => selector === ':open' || nativeMatches(selector))
  try { expect(isOpenSelectTarget(option)).toBe(true); expect(isOpenSelectTarget(text)).toBe(true); expect(isOpenSelectTarget(document)).toBe(false); expect(isOpenSelectTarget(null)).toBe(false) } finally { spy.mockRestore() }
})
