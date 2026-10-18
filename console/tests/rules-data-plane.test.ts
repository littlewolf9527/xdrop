import { it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { i18n, messages } from '../src/i18n'
vi.mock('../src/state', () => ({ captureSession: () => ({ isCurrent: () => true }) }))
import About from '../src/views/About.vue'
const fsModule = 'node:fs', osModule = 'node:os', processModule = 'node:process'
const fs = await import(fsModule), os = await import(osModule), process = await import(processModule)
const moduleURL = 'file://' + process.cwd() + '/scripts/third-party.mjs', { bpfSources, bpfWitness } = await import(moduleURL)
afterEach(() => { vi.unstubAllGlobals(); i18n.global.locale.value = 'zh-CN' })
it('R11-1 node and BPF groups render metadata as text with only the two fixed links', async () => {
  const values = [{ group:'node', name:'https://example.invalid/node',version:'node-version',license:'node-license' },{group:'bpf',name:'bpf-header',version:'',license:'GPL-2.0',note:'untrusted-note'}]
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ok:true,json:async()=>values}));i18n.global.locale.value='zh-CN'
  const w=mount(About,{global:{plugins:[i18n]}});await flushPromises()
  expect(w.findAll('.about-group')).toHaveLength(5)
  for(const group of ['node','bpf']) { const section=w.findAll('.about-group').find(s=>s.get('h2').text()===(group==='node'?messages['zh-CN'].nodeAgent:messages['zh-CN'].bpf))!;expect(section.findAll('tbody tr')).toHaveLength(1);expect(section.text()).toContain(values.find(v=>v.group===group)!.name) }
  const allowed=['/third-party.txt','https://github.com/littlewolf9527/xdrop'];expect(w.findAll('a').map(a=>a.attributes('href')).sort()).toEqual(allowed.sort())
  for(const element of w.findAll('*'))for(const [name,value]of Object.entries(element.attributes())) if(!(name==='href'&&allowed.includes(value))) for(const item of values)for(const raw of [item.name,item.version,item.license,item.note].filter(Boolean))expect(value).not.toContain(raw)
  w.unmount()
})
it('R11-2 BPF generation rejects unknown header copyright and non-GPL ELF declaration', () => {
  const dir=fs.mkdtempSync(os.tmpdir()+'/bpf-license-fixture-');fs.mkdirSync(dir+'/headers')
  try {
    fs.writeFileSync(dir+'/headers/bpf_helpers.h','// Copyright (c) 2019 Dropbox, Inc.\n');fs.writeFileSync(dir+'/xdrop_main.c','char _license[] SEC("license") = "GPL";')
    expect(bpfSources(dir).map((x: {entry:{license:string}})=>x.entry.license)).toEqual(['GPL-2.0','GPL-2.0'])
    const manifest = bpfSources(dir).map((x: { entry: unknown }) => x.entry)
    expect(bpfWitness(dir, manifest)).toBe(true)
    fs.writeFileSync(dir+'/headers/unknown.h','// Unknown copyright\n');expect(()=>bpfSources(dir)).toThrow('Unknown BPF header copyright');fs.unlinkSync(dir+'/headers/unknown.h')
    fs.writeFileSync(dir+'/xdrop_main.c','char _license[] SEC("license") = "MIT";');expect(()=>bpfSources(dir)).toThrow('Unexpected BPF license')
    for (const source of ['char _license[] SEC("license") = "GPL" "v3";', 'char _license[] SEC("license") = "GPL";\nchar extra[] SEC ("license") = "MIT";']) {
      fs.writeFileSync(dir + '/xdrop_main.c', source)
      expect(() => bpfSources(dir)).toThrow('Unexpected BPF license'); expect(bpfWitness(dir, manifest)).toBe(false)
    }
    fs.writeFileSync(dir + '/xdrop_main.c', 'char _license[] SEC \n ( "license" ) = \n "GPL";')
    expect(bpfSources(dir).map((x: {entry:{license:string}})=>x.entry.license)).toEqual(['GPL-2.0','GPL-2.0']); expect(bpfWitness(dir, manifest)).toBe(true)
  }finally{fs.rmSync(dir,{recursive:true})}
})
