import { it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { cwd } from 'node:process'
import { i18n, messages } from '../src/i18n'
import { ApiError } from '../src/api/client'
import { errorText, errorRules } from '../src/errors'
vi.mock('../src/state', () => ({ captureSession: () => ({ isCurrent: () => true }), login: vi.fn() }))
import About from '../src/views/About.vue'
import RuleError from '../src/components/RuleError.vue'
const fsModule = 'node:fs', osModule = 'node:os', cpModule = 'node:child_process', processModule = 'node:process'
const fs = await import(fsModule), os = await import(osModule), cp = await import(cpModule), { env } = await import(processModule)
const thirdPartyModule = 'file://' + cwd() + '/scripts/third-party.mjs'
const { goLicense } = await import(thirdPartyModule)
afterEach(() => vi.unstubAllGlobals())
it('C5-V16 all 28 backend error codes have nonempty translations in three languages', () => {
  const source = readFileSync(cwd() + '/../controller/core/api/errors.go', 'utf8')
  const block = source.slice(source.indexOf('var errorStatus'), source.indexOf('\n}', source.indexOf('var errorStatus')))
  const codes = [...block.matchAll(/"([a-z0-9_]+)"\s*:/g)].map(m => m[1]!)
  expect(codes).toHaveLength(28); expect(codes).toContain('mapped_ipv6'); expect(codes).toContain('invalid_rule')
  for (const dictionary of Object.values(messages)) for (const code of codes) expect((dictionary.errors as Record<string,string>)[code]?.trim(), code).toBeTruthy()
})
it('C5-V17 login throttle and invalid credentials equal loginFailed in all languages', () => {
  for (const dictionary of Object.values(messages)) { expect(dictionary.errors.login_throttled).toBe(dictionary.loginFailed); expect(dictionary.errors.invalid_credentials).toBe(dictionary.loginFailed) }
})
it('C5-V20 errors never render backend message and unknown codes use operationFailed', () => {
  for (const lang of ['zh-CN','ja-JP','en-US'] as const) {
    i18n.global.locale.value = lang
    for (const code of Object.keys(messages[lang].errors).filter(k => !['searchInvalid','exportExpired'].includes(k))) {
      expect(errorText(new ApiError(400, { code, message: 'BACKEND_PRIVATE_WORDING' }))).toBe((messages[lang].errors as Record<string,string>)[code])
    }
    expect(errorText(new ApiError(500, { code: 'unknown', message: 'BACKEND_PRIVATE_WORDING' }))).toBe(messages[lang].operationFailed)
  }
})
it('C5 capacity names and batch references are safe text', () => {
  i18n.global.locale.value = 'zh-CN'
  expect(errorText(new ApiError(409, { code: 'table_full', message: 'hidden', table: 'sv4' } as never))).toContain('IPv4 源地址')
  const error = new ApiError(409, { code: 'condition_capacity', message: 'hidden', rule_ids: ['batch:0', 'rule_'+'1'.repeat(32)] } as never)
  expect(errorRules(error)).toHaveLength(2)
  const w = mount(RuleError, { props: { error }, global: { plugins: [i18n] } })
  expect(w.text()).toContain('本次提交的这一条'); expect(w.findAll('button')).toHaveLength(1); expect(w.find('a').exists()).toBe(false); w.unmount()
})
it('C5-V22 version independent git describe witness', () => {
  const actual = env.XDROP_VERSION || cp.execFileSync('git', ['describe','--tags','--always','--dirty'], { cwd: cwd() + '/..', encoding: 'utf8' }).trim()
  expect(actual).not.toBe('dev'); expect(actual.length).toBeGreaterThan(0); expect(__XD_VERSION__).toBe(actual)
})
it('C5 conflict View inside a form searches without submitting the form', () => {
  const form = document.createElement('form'), submitted = vi.fn((event: Event) => event.preventDefault())
  form.addEventListener('submit', submitted); document.body.append(form)
  const id = 'rule_' + '1'.repeat(32), error = new ApiError(409, { code: 'rule_conflict', message: 'hidden', rule_id: id } as never)
  const w = mount(RuleError, { props: { error }, global: { plugins: [i18n] }, attachTo: form })
  ;(w.get('button').element as HTMLButtonElement).click()
  expect(w.emitted('search')).toEqual([[id]]); expect(submitted).not.toHaveBeenCalled()
  w.unmount(); form.remove()
})
it('C5-V28 about renders five JSON groups as text and href allowlist only', async () => {
  const hostile = 'https://example.invalid/'
  const values = [{ group:'browser',name:hostile,version:'1',license:'MIT' }, { group:'controller',name:'module',version:'v1',license:'MIT' }, { group:'go',name:'Go',version:'go1',license:'BSD-3-Clause' }, { group:'font',name:'IBM Plex',version:'5',license:'OFL-1.1' }]
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => values }))
  const w = mount(About, { global: { plugins: [i18n] } }); await flushPromises()
  expect(w.findAll('.about-group')).toHaveLength(5); expect(w.findAll('tbody tr')).toHaveLength(4); expect(w.text()).toContain(hostile)
  const hrefs = w.findAll('a').map(a => a.attributes('href'))
  expect(hrefs.every(h => ['/third-party.txt','https://github.com/littlewolf9527/xdrop'].includes(h!))).toBe(true)
  expect(w.get('a[href^="https://github.com"]').attributes('rel')).toBe('noopener'); expect(w.text()).toContain(__XD_VERSION__); w.unmount()
})
it('C5 login copyright is after form and contains neither version nor link', () => {
  const source = readFileSync(cwd() + '/src/views/Login.vue', 'utf8')
  expect(source).toContain('</form>\n    <p class="login-copyright">© 2026 LittleWolf</p>')
  const copyright = source.match(/<p class="login-copyright">([^<]+)<\/p>/)![1]!
  expect(copyright).toBe('© 2026 LittleWolf'); expect(source).not.toContain('__XD_VERSION__')
})
it('C5 ruling-2 Go license fixed paths, bundled fallback and non-Go failures', () => {
  const temp = fs.mkdtempSync(os.tmpdir() + '/go-license-fixture-'), root = temp + '/goroot'; fs.mkdirSync(root)
  const license = 'Copyright 2009 The Go Authors.\nRedistribution and use in source and binary forms\nNeither the name of Google LLC nor names of its contributors\n'
  try {
    fs.writeFileSync(root + '/LICENSE', license); expect(goLicense(root).selected).toBe('GOROOT/LICENSE')
    fs.unlinkSync(root + '/LICENSE'); fs.writeFileSync(temp + '/LICENSE', license); expect(goLicense(root).selected).toBe('GOROOT/../LICENSE')
    fs.unlinkSync(temp + '/LICENSE'); const bundled = goLicense(root)
    expect(bundled.selected).toBe('scripts/licenses/Go-BSD-3-Clause.txt'); expect(bundled.text).toMatch(/^Copyright 2009 The Go Authors\./)
    fs.writeFileSync(temp + '/LICENSE', license.replace('The Go Authors.', 'Another Author.')); expect(() => goLicense(root)).toThrow('Invalid Go Authors license')
    fs.writeFileSync(root + '/LICENSE', 'invalid'); fs.writeFileSync(temp + '/LICENSE', license); expect(() => goLicense(root)).toThrow('Invalid Go Authors license')
  } finally { fs.rmSync(temp, { recursive: true }) }
})
it('R4-4 R3-6 V28 metadata cannot populate any rendered attribute', async () => {
  const values = [{ group: 'browser', name: 'https://example.invalid/image', version: 'version-payload', license: 'license-payload', note: 'note-payload' }]
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => values }))
  const w = mount(About, { global: { plugins: [i18n] } }); await flushPromises()
  expect(w.text()).toContain(values[0]!.name)
  const allowed = ['/third-party.txt', 'https://github.com/littlewolf9527/xdrop']
  for (const value of Object.values(values[0]!)) expect(allowed).not.toContain(value)
  for (const element of [w.element, ...w.element.querySelectorAll('*')]) for (const attribute of element.attributes) {
    if (attribute.name === 'href') expect(allowed).toContain(attribute.value)
    for (const value of Object.values(values[0]!)) expect(attribute.value).not.toContain(value)
  }
  expect(w.findAll('a').map(a => a.attributes('href'))).toEqual(['https://github.com/littlewolf9527/xdrop', '/third-party.txt'])
  w.unmount()
})
