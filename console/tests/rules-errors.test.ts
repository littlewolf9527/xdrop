import { it, expect, vi, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
const processModule = 'node:process', { env } = await import(processModule)
import { mount, flushPromises } from '@vue/test-utils'
import { ApiError } from '../src/api/client'
import { errorText, ruleMessage } from '../src/errors'
import { i18n, messages } from '../src/i18n'
import RuleDrawer from '../src/components/RuleDrawer.vue'
import RuleError from '../src/components/RuleError.vue'
const hooks = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('../src/state', () => ({ request: hooks.request, captureSession: () => ({ isCurrent: () => true }), state: { user: { name: 'admin' } } }))
afterEach(() => { i18n.global.locale.value = 'zh-CN'; hooks.request.mockReset() })
const sources = ['controller/core/rules/canonical.go', 'controller/core/rules/admission.go', 'shared/condexpr/compile.go', 'shared/condexpr/parse.go']
const internal = ['unknown expression key %q', 'rule %s: %w', 'candidates have different five-tuples', 'missing/duplicate rule ID %q', 'missing/duplicate logical_id %d']
function sourceCalls(source: string) {
  const tokens = [...source.matchAll(/\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:\\.|[^"\\])*"|`[^`]*`|'(?:\\.|[^'\\])*'|[a-zA-Z_]\w*|[^\s]/g)].map(m => m[0]).filter(t => !t.startsWith('//') && !t.startsWith('/*'))
  const calls: { kind: string; args: string[][] }[] = []
  for (let i = 0; i < tokens.length; i++) {
    const bad = tokens[i] === 'bad' && tokens[i + 1] === '(' && tokens[i - 1] !== 'func'
    const other = ['fmt.Errorf', 'errors.New'].includes(tokens.slice(i, i + 3).join('')) && tokens[i + 3] === '('
    if (!bad && !other) continue
    const kind = bad ? 'bad' : tokens.slice(i, i + 3).join(''), args: string[][] = [], stack = ['(']
    let current: string[] = []
    for (let j = i + (bad ? 2 : 4); j < tokens.length; j++) {
      const token = tokens[j]!
      if (['(', '[', '{'].includes(token)) stack.push(token)
      if ([')', ']', '}'].includes(token)) {
        stack.pop()
        if (!stack.length) { args.push(current); current = []; break }
      }
      if (token === ',' && stack.length === 1) { args.push(current); current = [] } else current.push(token)
    }
    if (stack.length) throw new Error('Unclosed source call: ' + kind)
    calls.push({ kind, args })
  }
  return calls
}
const nonliteral = [
  ['controller/core/rules/canonical.go', 'cidr', 'err.Error()'],
  ['controller/core/rules/canonical.go', 'tcp_flags', 'e.Error()'],
  ['controller/core/rules/canonical.go', 'conditions', 'e.Error()'],
  ['controller/core/rules/admission.go', 'cidr', 'err.Error()'],
].map(tuple => JSON.stringify(tuple))
function example(format: string) {
  let index = 0
  return format.replace(/%[qdsw]/g, token => {
    if (token === '%q') return '"x"'
    if (token === '%d') return '255'
    if (token === '%w') return 'invalid decimal "01"'
    if (format.includes('requires protocol')) return index++ ? 'icmp,icmpv6' : 'icmp_type'
    return format.startsWith('protocol ') ? 'icmp' : format.startsWith('contradictory') ? 'SYN' : 'ttl'
  })
}
it('R8-1 source-derived message coverage and injected unknown positive control', () => {
  const calls = sources.flatMap(file => sourceCalls(readFileSync('../' + file, 'utf8')).map(call => ({ file, ...call })))
  const extracted: { file: string; field: string; format: string }[] = [], registered: string[] = [], unresolved: unknown[] = []
  const literal = (tokens: string[]) => tokens.length !== 1 ? undefined : /^"(?:\\.|[^"\\])*"$/.test(tokens[0]!) ? JSON.parse(tokens[0]!) as string : tokens[0]!.startsWith('`') ? tokens[0]!.slice(1, -1) : undefined
  for (const call of calls) {
    const field = call.kind === 'bad' ? literal(call.args[0] || []) || '' : 'conditions', expression = call.args[call.kind === 'bad' ? 1 : 0] || [], format = literal(expression)
    if (format !== undefined) extracted.push({ file: call.file, field, format })
    else {
      const tuple = JSON.stringify([call.file, field, expression.join('')])
      if (call.kind === 'bad' && nonliteral.includes(tuple)) registered.push(tuple)
      else unresolved.push({ file: call.file, field, kind: call.kind, expression: expression.join('') })
    }
  }
  expect(unresolved).toEqual([]); expect(registered.sort()).toEqual([...nonliteral].sort())
  expect(calls.length).toBe(extracted.length + registered.length)
  expect(new Set(extracted.map(x => x.file))).toContain('shared/condexpr/parse.go')
  expect(extracted.some(x => x.format === 'flags require tcp')).toBe(true)
  const uncovered = (items: typeof extracted) => items.filter(x => !internal.includes(x.format) && !ruleMessage(example(x.format), x.field))
  const fake = { file: 'positive-control', field: 'conditions', format: 'new unmatched rule error' }
  expect(uncovered([...extracted, fake])).toEqual([fake])
  if (env.R8_FAKE_SOURCE === '1') extracted.push(fake)
  expect(uncovered(extracted)).toEqual([])
})
const cases: [string, string, string, Record<string, string>?][] = [
  ['ip','ip','invalid IP address'], ['cidr','cidr','invalid network encoding'],
  ['portsProtocol','protocol','protocol does not support ports'], ['protocol','protocol','unknown protocol'],
  ['portRange','dst_port','port out of range'], ['rateRange','rate_limit','rate out of range'],
  ['ratePositive','rate_limit','rate must be positive'], ['action','action','unknown action'],
  ['mixedAddress','ip','exact IP and CIDR cannot be combined'], ['wide','tuple','rule field combination is not recognized'],
  ['anomalyRange','match_anomaly','anomaly out of range'], ['anomalyBits','match_anomaly','unknown anomaly bits'],
  ['anomalyTarget','match_anomaly','anomaly requires a bounded target'], ['anomalyIPv6','match_anomaly','anomaly is not supported for IPv6'],
  ['flagsTCP','tcp_flags','flags require tcp'], ['requiresProtocol','conditions','icmp_type requires protocol icmp,icmpv6',{key:'icmp_type',protos:'icmp,icmpv6'}],
  ['fragmentIPv4','conditions','fragment requires IPv4 address or CIDR anchor'],
  ['nonfirst','conditions','D2: nonfirst fragment or anomaly 0x08 cannot satisfy a port, TCP flags, or ICMP constraint'],
  ['conditionTarget','conditions','condition rule requires a five-tuple anchor'], ['lengthRange','conditions','legacy packet length outside 0-65535'],
  ['lengthBoth','conditions','new and legacy packet length coexist'], ['reversed','conditions','ttl: reversed interval',{key:'ttl'}],
  ['decimal','conditions','ttl: invalid decimal "01"',{value:'01'}], ['valueRange','conditions','ttl: value "256" outside 0-255',{value:'256',max:'255'}],
  ['illegal','conditions','ttl: illegal character',{key:'ttl'}], ['emptyExpression','conditions','ttl: empty expression',{key:'ttl'}],
  ['emptyItem','conditions','ttl: empty item',{key:'ttl'}], ['fragmentName','conditions','fragment: invalid name "x"',{value:'x'}],
  ['interval','conditions','ttl: invalid interval "x"',{key:'ttl',value:'x'}], ['emptySet','conditions','ttl: empty set',{key:'ttl'}],
  ['fullSet','conditions','ttl: full set; please remove this key',{key:'ttl'}], ['flagName','tcp_flags','unknown TCP flag "x"',{value:'x'}],
  ['flagConflict','tcp_flags','contradictory TCP flags: SYN',{value:'SYN'}],
]
for (const lang of ['zh-CN','ja-JP','en-US'] as const) {
  it.each(cases)('R8-2 ' + lang + ' %s renders exact translated text', (id, field, message, params = {}) => {
    i18n.global.locale.value = lang
    const expected = (messages[lang].ruleErrors as Record<string,string>)[id]!.replace(/\{(\w+)\}/g, (_, key) => params[key]!)
    const error = new ApiError(400, { code: 'invalid_rule', field, message })
    const w = mount(RuleError, { props: { error }, global: { plugins: [i18n] } })
    expect(w.text()).toBe(expected); expect(w.html()).not.toContain(message); w.unmount()
  })
}
it('R8-2 captured input is plain text, quoted correctly and truncated at 40 characters', () => {
  const value = '<script>"\\</script>' + 'a'.repeat(60), message = 'unknown TCP flag ' + JSON.stringify(value)
  const error = new ApiError(400, { code: 'invalid_rule', field: 'tcp_flags', message })
  const w = mount(RuleError, { props: { error }, global: { plugins: [i18n] } })
  expect(w.text()).toContain(value.slice(0,40) + '…'); expect(w.text()).not.toContain(value.slice(0,41) + '…')
  expect(w.find('script').exists()).toBe(false); expect(w.text()).not.toContain(message)
  expect([...w.element.querySelectorAll('*')].flatMap(e => [...e.attributes].map(a => a.value)).join(' ')).not.toContain(message)
  expect(errorText(new ApiError(400, { code: 'invalid_rule', field: 'conditions', message: 'rule rule_0123: ttl: reversed interval' }))).toBe('ttl 区间写反了，小的数在前')
  w.unmount()
})
it.each([
  [String.raw`unknown TCP flag "A\x01\n\"\\B"`, [65, 1, 10, 34, 92, 66]],
  [String.raw`unknown TCP flag "A\a\vB"`, [65, 7, 11, 66]],
  [String.raw`unknown TCP flag "A\u200b\x01B"`, [65, 0x200b, 1, 66]],
  [String.raw`unknown TCP flag "A\\X41\x01B"`, [65, 92, 88, 52, 49, 1, 66]],
  [String.raw`unknown TCP flag "\a\b\f\n\r\t\v\\\"\x41\u0042\U0001f600\101\z"`, [7, 8, 12, 10, 13, 9, 11, 92, 34, 65, 66, 0x1f600, 65, 92, 122]],
] as const)('R13-escapes decodes Go message %s with independent codepoint expectations', (message, points) => {
  const expected = String.fromCodePoint(...points)
  expect(ruleMessage(message, 'tcp_flags')!.value).toBe(expected)
  i18n.global.locale.value = 'zh-CN'
  const wrapper = mount(RuleError, { props: { error: new ApiError(400, { code: 'invalid_rule', field: 'tcp_flags', message }) }, global: { plugins: [i18n] } })
  expect(wrapper.text()).toBe(messages['zh-CN'].ruleErrors.flagName.replace('{value}', expected)); expect(wrapper.find('script').exists()).toBe(false); wrapper.unmount()
})
it('R8-2 R13-nonBMP truncates captured text at forty codepoints without splitting an emoji', () => {
  const prefix = [60, 83, 67, 82, 73, 80, 84, 62, 34, 92, 60, 47, 83, 67, 82, 73, 80, 84, 62]
  const value = String.fromCodePoint(...prefix) + '😀'.repeat(50), expected = String.fromCodePoint(...prefix, ...Array(21).fill(0x1f600), 0x2026)
  const message = 'unknown TCP flag ' + JSON.stringify(value)
  expect(ruleMessage(message, 'tcp_flags')!.value).toBe(expected)
  const wrapper = mount(RuleError, { props: { error: new ApiError(400, { code: 'invalid_rule', field: 'tcp_flags', message }) }, global: { plugins: [i18n] } })
  expect(wrapper.text()).toContain(expected); expect(wrapper.find('script').exists()).toBe(false); wrapper.unmount()
})
it('R13-hints address hints forbid combining IP and subnet without a same-side exception', () => {
  for (const lang of ['zh-CN', 'ja-JP', 'en-US'] as const) expect(messages[lang].ruleHints.address).not.toMatch(/on the same side|同じ側|同侧/)
  expect(messages['zh-CN'].ruleHints.address).toContain('单个 IP 与网段不能混用')
  expect(messages['ja-JP'].ruleHints.address).toContain('単一 IP とサブネットは併用できません')
  expect(messages['en-US'].ruleHints.address).toContain('A single IP and subnet cannot be combined.')
})
it.each([
  ['tcp_flags','flags require tcp','tcp_flags','tcp_flags 只能用于协议 tcp'],
  ['conditions','ttl: invalid interval "x"','ttl','ttl 的区间 x 写法不对，应为「小-大」'],
  ['conditions','icmp_type requires protocol icmp,icmpv6','icmp_type','icmp_type 只能用于协议 icmp,icmpv6'],
  ['tuple','rule field combination is not recognized','target','规则太宽：至少要填一个地址、端口或具体协议'],
  ['conditions','ttl: private unmatched backend wording','ttl','ttl写法不对 ' + messages['zh-CN'].ruleHints.ttl],
  ['items.dst_port','private unmatched decoding wording','dst_port','目的端口写法不对'],
])('R8-3 field %s message %s locates input and never exposes raw backend message', async (field,message,location,text) => {
  i18n.global.locale.value = 'zh-CN'
  hooks.request.mockResolvedValue({ results: [{ index: 0, error: { code: 'invalid_rule', field, message } }] })
  const w = mount(RuleDrawer, { global: { plugins: [i18n] } })
  await w.get('form').trigger('submit'); await flushPromises()
  const element = location === 'target' ? w.findAll('fieldset').find(f => f.get('legend').text() === '目标')! : w.get('[data-field="' + location + '"]')
  expect(element.get('.rule-error').text()).toBe(text); expect(w.findAll('.rule-error')).toHaveLength(1)
  expect(w.text()).not.toContain(message); expect([...w.element.querySelectorAll('*')].flatMap(e => [...e.attributes].map(a => a.value)).join(' ')).not.toContain(message)
  w.unmount()
})
