import { it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { i18n, messages } from '../src/i18n'
vi.mock('../src/state', () => ({ captureSession: () => ({ isCurrent: () => true }) }))
import About from '../src/views/About.vue'
const processModule = 'node:process', process = await import(processModule)
const { bpfSources } = await import('file://' + process.cwd() + '/scripts/third-party.mjs')
afterEach(() => { vi.unstubAllGlobals(); i18n.global.locale.value = 'zh-CN' })
it.each(['zh-CN', 'ja-JP', 'en-US'] as const)('R12-1 %s restores fixed localized notes and language-neutral source-derived BPF names', async lang => {
  const bpf = bpfSources(process.cwd() + '/../node/bpf').map((item: { entry: { group: string; name: string; version: string; license: string; note?: string } }) => item.entry)
  expect(bpf.map((item: { name: string }) => item.name)).toEqual(['bpf_helpers.h (dropbox/goebpf)', 'xdrop_main.c · xdrop_gate.c'])
  expect(bpf[1].note).toBe('ELF license 段声明 GPL；仓库 README：node/bpf 按 GPL-2.0')
  const values = [
    { group: 'browser', name: 'github.com/mattn/go-sqlite3', version: 'spoof', license: 'MIT', note: 'untrusted note' },
    { group: 'controller', name: 'github.com/mattn/go-sqlite3', version: 'v1.14.19', license: 'MIT', note: 'untrusted note' },
    { group: 'node', name: 'other-module', version: '1', license: 'MIT', note: '内含 SQLite（公有领域）' }, ...bpf,
  ]
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => values })); i18n.global.locale.value = lang
  const wrapper = mount(About, { global: { plugins: [i18n] } }); await flushPromises()
  const groups = wrapper.findAll('.about-group'), browser = groups[0]!, controller = groups[1]!, node = groups[2]!, bpfTable = groups[3]!
  expect(controller.get('tbody td').attributes('title')).toBe(messages[lang].sqliteNote)
  expect(bpfTable.findAll('tbody tr')[1]!.get('td').attributes('title')).toBe(messages[lang].bpfProgramNote)
  for (const cell of [browser.get('tbody td'), node.get('tbody td'), bpfTable.findAll('tbody tr')[0]!.get('td')]) expect(cell.attributes('title')).toBeUndefined()
  expect(bpfTable.findAll('tbody tr').map(row => row.get('td').text())).toEqual(['bpf_helpers.h (dropbox/goebpf)', 'xdrop_main.c · xdrop_gate.c'])
  expect(wrapper.html()).not.toContain('untrusted note'); expect(wrapper.text()).not.toContain(bpf[1].note)
  expect(wrapper.findAll('a').map(a => a.attributes('href'))).toEqual(['https://github.com/littlewolf9527/xdrop', '/third-party.txt'])
  wrapper.unmount()
})
