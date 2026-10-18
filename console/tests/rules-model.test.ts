import { it, expect, vi } from 'vitest'
import { ApiError } from '../src/api/client'
import { listState, ruleList, ruleForm, ruleBody, ruleRate, exportRules, serializeRule, exportDuration, ExportExpired, grouped } from '../src/rules'
import { trailingThrottle } from '../src/api/events'
import { integerAxis } from '../src/metrics'
import type { RuleDTO, RulePage, TopAll } from '../src/api/types'
const now = Date.parse('2026-10-16T00:00:00Z')
const rule = (n = 1, extra: Partial<RuleDTO> = {}): RuleDTO => ({ id: 'rule_' + n.toString(16).padStart(32, '0'), logical_id: n,
  src_ip: '', dst_ip: '192.0.2.1', src_cidr: '', dst_cidr: '', protocol: 'tcp', src_port: 0, dst_port: 443, ttl: '64', dscp: null,
  icmp_type: null, icmp_code: null, fragment: null, pkt_len: null, tcp_flags: '', match_anomaly: 0, action: 'rate_limit', rate_limit: 100,
  kind: 'exact', group_key: 'g', cond_key: '', enabled: true, comment: 'memo', created_at: '', updated_at: '', expires_at: null,
  created_by: 'user:admin', updated_by: 'user:admin', ...extra })
const page = (items: RuleDTO[] = [rule()], next_after: number | null = null): RulePage => ({ items, next_after, counts: { all: 250, drop: 100, rate_limit: 100, disabled: 50 } })
const deferred = <T>() => { let resolve!: (v: T) => void, reject!: (e: unknown) => void; const promise = new Promise<T>((a, b) => { resolve = a; reject = b }); return { promise, resolve, reject } }
const capture = () => ({ isCurrent: () => true })
it('C5-V2 pages use counts once and next_after for continuation', async () => {
  const s = listState(), fetch = vi.fn().mockResolvedValueOnce(page([rule()], 17)).mockResolvedValueOnce(page([rule(2)]))
  const m = ruleList(s, fetch, capture); await m.query({ q: '', state: '' }); expect(s.next).toBe(17); await m.more()
  expect(fetch.mock.calls.map(c => c[0])).toEqual(['/rules?limit=100&counts=1', '/rules?limit=100&after=17'])
  expect(s.rows.map(r => r.id)).toEqual([rule().id, rule(2).id]); expect(s.next).toBeNull()
  await m.more(); expect(fetch).toHaveBeenCalledTimes(2)
})
it('C5-V3 query and filter reset after two loaded pages', async () => {
  const s = listState(), fetch = vi.fn().mockResolvedValue(page([rule()], 17)), m = ruleList(s, fetch, capture)
  await m.query({ q: '', state: '' }); await m.more(); expect(s.rows).toHaveLength(2)
  await m.query({ q: '  192.0.2.2  ', state: 'drop' })
  expect(fetch.mock.lastCall?.[0]).toBe('/rules?limit=100&counts=1&q=192.0.2.2&state=drop'); expect(s.rows).toHaveLength(1)
})
it.each([false, true])('C5-V1 reversed replies discard stale success and error error=%s', async error => {
  const s = listState(), a = deferred<RulePage>(), b = deferred<RulePage>(), fetch = vi.fn().mockReturnValueOnce(a.promise).mockReturnValueOnce(b.promise)
  const m = ruleList(s, fetch, capture), first = m.query({ q: '192.0.2.1', state: '' }), second = m.query({ q: '192.0.2.2', state: '' })
  b.resolve(page([rule(2)])); await second; expect(s.rows[0]?.id).toBe(rule(2).id)
  if (error) a.reject(new ApiError(400, { code: 'bad_request', message: 'old', field: 'q' })); else a.resolve(page([rule()]))
  await first; expect(s.rows[0]?.id).toBe(rule(2).id); expect(s.error).toBeNull(); expect(s.applied.q).toBe('192.0.2.2')
})
it('C5 invalid search preserves rows counts cursor and applied query for more and export', async () => {
  const s = listState(), fetch = vi.fn().mockResolvedValueOnce(page([rule()], 17)).mockRejectedValueOnce(new ApiError(400, { code: 'bad_request', field: 'q', message: 'query' })).mockResolvedValue(page([rule(2)]))
  const m = ruleList(s, fetch, capture); await m.query({ q: '192.0.2.1', state: 'drop' }); const before = structuredClone(s)
  await m.query({ q: 'wrong', state: '' }); expect({ ...s, error: null }).toEqual(before)
  expect(s.error).toBeInstanceOf(ApiError); await m.more(); expect(fetch.mock.lastCall?.[0]).toContain('after=17&q=192.0.2.1&state=drop')
  await exportRules(s.applied, fetch, () => true, () => {}, () => now); expect(fetch.mock.lastCall?.[0]).toBe('/rules?limit=1000&q=192.0.2.1&state=drop')
})
it('C5-V5 refresh replaces atomically after more than 1000 loaded rows', async () => {
  const s = listState(); s.rows = Array.from({ length: 1105 }, (_, i) => rule(i + 1))
  expect(s.rows.length).toBeGreaterThan(1000)
  const a = deferred<RulePage>(), b = deferred<RulePage>(), fetch = vi.fn().mockReturnValueOnce(a.promise).mockReturnValueOnce(b.promise), m = ruleList(s, fetch, capture)
  const refreshing = m.refresh(), first = Array.from({ length: 1000 }, (_, i) => rule(i + 2001))
  a.resolve(page(first, 3000)); await Promise.resolve(); await Promise.resolve()
  expect(fetch).toHaveBeenCalledTimes(2); expect(fetch.mock.lastCall?.[0]).toBe('/rules?limit=1000&after=3000')
  expect(s.rows[0]?.logical_id).toBe(1)
  b.resolve(page(Array.from({ length: 105 }, (_, i) => rule(i + 3001))))
  await refreshing; expect(s.rows.map(r => r.logical_id)).toEqual(Array.from({ length: 1105 }, (_, i) => i + 2001))
})
it('C5 user query invalidates refresh and pending query defers trailing refresh and more', async () => {
  const s = listState(); s.rows = [rule()]; s.next = 9
  const old = deferred<RulePage>(), user = deferred<RulePage>(), fetch = vi.fn().mockReturnValueOnce(old.promise).mockReturnValueOnce(user.promise).mockResolvedValue(page([rule(7)]))
  const m = ruleList(s, fetch, capture), refresh = m.refresh(), query = m.query({ q: '192.0.2.7', state: 'disabled' })
  await m.refresh(); await m.more(); expect(fetch).toHaveBeenCalledTimes(2)
  old.resolve(page([rule(3)])); await refresh; expect(s.rows[0]?.logical_id).toBe(1)
  user.resolve(page([rule(7)])); await query; await Promise.resolve()
  expect(fetch).toHaveBeenCalledTimes(3); expect(fetch.mock.lastCall?.[0]).toContain('q=192.0.2.7&state=disabled')
  expect(s.rows.map(r => r.logical_id)).toEqual([7]); expect(s.applied.q).toBe('192.0.2.7')
})
it('C5 session and unmount discard in-flight list responses', async () => {
  for (const stop of [false, true]) {
    const s = listState(), a = deferred<RulePage>(); let current = true
    const m = ruleList(s, () => a.promise, () => ({ isCurrent: () => current })), pending = m.query({ q: '', state: '' })
    if (stop) m.stop(); else current = false
    a.resolve(page()); await pending; expect(s.rows).toEqual([])
  }
})
it('C5-V4 rules throttle has exactly one trailing request for three events', () => {
  vi.useFakeTimers(); vi.setSystemTime(now)
  const f = vi.fn(), trigger = trailingThrottle(f, 2000)
  trigger(); vi.advanceTimersByTime(100); trigger(); vi.advanceTimersByTime(100); trigger(); expect(f).toHaveBeenCalledTimes(1)
  vi.advanceTimersByTime(1799); expect(f).toHaveBeenCalledTimes(1); vi.advanceTimersByTime(1); expect(f).toHaveBeenCalledTimes(2)
  vi.advanceTimersByTime(5000); expect(f).toHaveBeenCalledTimes(2); trigger.cancel(); vi.useRealTimers()
})
it('C5-V14 absent rates stay unknown and present rates are paired', () => {
  const r = rule(), other = { rule_id: rule(2).id, target: '192.0.2.2', dropped_pps: 3, dropped_bytes_ps: 4, share: .1 }
  const top: TopAll = { rules: [other], targets: [], targets_total: 1, updated_at: '2026-10-16T00:00:00Z', incomplete: false }
  expect(top.rules[0]?.dropped_pps).toBeGreaterThan(0); expect(ruleRate(r, top)).toBeNull()
  top.rules.push({ ...other, rule_id: r.id }); expect(ruleRate(r, top)).toEqual([3, 32])
  expect(ruleRate({ ...r, enabled: false }, top)).toBeNull(); expect(ruleRate(r, { ...top, updated_at: null })).toBeNull()
})
it('R9-1 incomplete retains measured rates; disabled, absent and unknown remain dashes', () => {
  const r = rule(), top: TopAll = { rules: [{ rule_id: r.id, target: r.dst_ip, dropped_pps: 100, dropped_bytes_ps: 200, share: .1 }], targets: [], targets_total: 1, updated_at: '2026-10-16T00:00:00Z', incomplete: true }
  expect(r.enabled).toBe(true); expect(top.rules[0]?.dropped_pps).toBeGreaterThan(0); expect(top.updated_at).not.toBeNull(); expect(ruleRate(r, top)).toEqual([100, 1600])
  expect(ruleRate({ ...r, id: 'rule_' + 'e'.repeat(32) }, top)).toBeNull()
  expect(ruleRate({ ...r, enabled: false }, top)).toBeNull(); expect(ruleRate(r, { ...top, updated_at: null })).toBeNull()
})
it('C5-V9 edit sends exact changed keys and preserves trimmed snapshot comment', () => {
  const r = rule(1, { comment: '  original  ' }), initial = ruleForm(r), f = { ...initial, ttl: '128' }
  expect([r.dst_ip, r.protocol, r.dst_port, r.rate_limit].every(Boolean)).toBe(true)
  expect(ruleBody(f, initial, r)).toEqual({ ttl: '128' }); expect(ruleBody(initial, initial, r)).toEqual({})
})
it('C5-V10 edit string clearing is empty string', () => {
  const r = rule(), f = ruleForm(r); expect(r.ttl).toBe('64'); expect(ruleBody({ ...f, ttl: '' }, f, r)).toEqual({ ttl: '' })
})
it('C5-V25 edit clearing numeric ports sends zero', () => {
  const r = rule(), f = ruleForm(r); expect(r.dst_port).not.toBe(0); expect(ruleBody({ ...f, dst_port: '' }, f, r)).toEqual({ dst_port: 0 })
})
it('C5 edit address switch clears previous key and drop omits rate', () => {
  const r = rule(), f = ruleForm(r)
  expect(ruleBody({ ...f, dst_address: '192.0.2.0/24' }, f, r)).toEqual({ dst_ip: '', dst_cidr: '192.0.2.0/24' })
  expect(ruleBody({ ...f, action: 'drop' }, f, r)).toEqual({ action: 'drop' })
  expect(ruleBody({ ...f, dst_address: '', src_address: '198.51.100.7' }, f, r)).toEqual({ dst_ip: '', src_ip: '198.51.100.7' })
})
it('C5-V21 unchanged expiry omitted and permanent clears expiry', () => {
  const r = rule(1, { expires_at: new Date(now + 3600000).toISOString() }), f = ruleForm(r)
  expect(r.expires_at).not.toBeNull(); expect(ruleBody({ ...f, comment: 'changed' }, f, r)).toEqual({ comment: 'changed' })
  expect(ruleBody({ ...f, expires_mode: 'permanent' }, f, r)).toEqual({ expires_in: '' })
  expect(ruleBody({ ...f, expires_in: '2h' }, f, r)).toEqual({ expires_in: '2h' })
})
it.each(['53','abc','1.5','-1','9007199254740993','9'.repeat(400)])('C5-V29 numeric lexical body preserves unsafe values %s', value => {
  const f = { ...ruleForm(), dst_port: value, src_port: value, match_anomaly: value, action: 'rate_limit', rate_limit: value }
  const body = ruleBody(f), expected = value === '53' ? 53 : value
  for (const key of ['dst_port','src_port','match_anomaly','rate_limit']) expect(body[key]).toBe(expected)
  expect(JSON.stringify(body)).not.toContain('null')
})
it('C5-V11 export pages retain query and filter', async () => {
  const fetch = vi.fn().mockResolvedValueOnce(page([rule()], 17)).mockResolvedValueOnce(page([rule(2)]))
  const text = await exportRules({ q: '192.0.2.0/24', state: 'rate_limit' }, fetch, () => true, () => {}, () => now)
  expect(fetch.mock.calls.map(c => c[0])).toEqual(['/rules?limit=1000&q=192.0.2.0%2F24&state=rate_limit','/rules?limit=1000&after=17&q=192.0.2.0%2F24&state=rate_limit'])
  expect(text.split('\n')).toHaveLength(4); expect(text.split('\n')[0]).not.toContain('192.0.2.0/24')
})
it('C5-V12 V13 export exact format key order quotes escapes omissions and rounded expiry', () => {
  const r = rule(1, { comment: 'space "quote" \\ slash\nline\rreturn\ttab # =', enabled: false, match_anomaly: 4, expires_at: new Date(now + 3601000).toISOString() })
  expect(serializeRule(r, now)).toBe('dst_ip=192.0.2.1 dst_port=443 protocol=tcp ttl=64 match_anomaly=4 action=rate_limit rate_limit=100 enabled=false comment="space \\"quote\\" \\\\ slash\\nline\\rreturn\\ttab # =" expires_in=1h1m')
  const drop = serializeRule(rule(2, { action: 'drop', comment: '', ttl: null }), now)
  expect(drop).toBe('dst_ip=192.0.2.1 dst_port=443 protocol=tcp action=drop')
})
it.each([0,-1000])('C5-V27 expired export aborts remaining=%s', async remaining => {
  await expect(exportRules({ q: '', state: '' }, async () => page([rule(1, { expires_at: new Date(now + remaining).toISOString() })]), () => true, () => {}, () => now)).rejects.toBeInstanceOf(ExportExpired)
})
it('C5 expiry on later page fails; earlier page uses its receipt time', async () => {
  const r = rule(1, { expires_at: new Date(now + 1000).toISOString() })
  let clock = now
  const later = vi.fn().mockResolvedValueOnce(page([rule(2)], 2)).mockImplementationOnce(async () => { clock += 2000; return page([r]) })
  await expect(exportRules({ q: '', state: '' }, later, () => true, () => {}, () => clock)).rejects.toBeInstanceOf(ExportExpired)
  clock = now
  const earlier = vi.fn().mockResolvedValueOnce(page([r], 1)).mockImplementationOnce(async () => { clock += 2000; return page([rule(2)]) })
  const text = await exportRules({ q: '', state: '' }, earlier, () => true, () => {}, () => clock)
  expect(text.split('\n')[1]).toContain('expires_in=1m')
})
it('C5 export error and session expiry return no partial text', async () => {
  const fetch = vi.fn().mockResolvedValueOnce(page([rule()], 1)).mockRejectedValueOnce(new Error('network'))
  await expect(exportRules({ q: '', state: '' }, fetch, () => true, () => {}, () => now)).rejects.toThrow('network')
  await expect(exportRules({ q: '', state: '' }, async () => page(), () => false, () => {}, () => now)).rejects.toThrow()
})
it('C5-V31 duration upper bound is representable by Go int64 nanoseconds', () => {
  const seconds = 9223372036, at = new Date(now + seconds * 1000).toISOString()
  expect(BigInt(Math.ceil(seconds / 60) * 60) * 1000000000n).toBeGreaterThan(9223372036854775807n)
  const text = exportDuration(at, now); expect(text).toBe('2562047h47m16s')
  const sum = [...text.matchAll(/(\d+)([hms])/g)].reduce((n,m) => n + BigInt(m[1]!) * ({ h: 3600n, m: 60n, s: 1n }[m[2]!]!), 0n)
  expect(sum * 1000000000n).toBeLessThanOrEqual(9223372036854775807n)
})
it('C5-V33 clock skew clamps final whole seconds', () => {
  const at = new Date(now + 9223372036 * 1000).toISOString()
  expect(exportDuration(at, now - 60000)).toBe('2562047h47m16s')
})
// Independent minimal reader: no production tokenization or quote helpers.
function referenceParse(text: string) {
  const values: Record<string, string> = {}; let i = 0
  while (i < text.length) {
    while (text[i] === ' ') i++
    let key = ''; while (i < text.length && text[i] !== '=') key += text[i++]
    i++; let value = '', quoted = text[i] === '"'; if (quoted) i++
    while (i < text.length) {
      const c = text[i++]!
      if (quoted && c === '"' || !quoted && c === ' ') break
      if (quoted && c === '\\') { const e = text[i++]!; value += ({ n: '\n', r: '\r', t: '\t', '\\': '\\', '"': '"' } as Record<string,string>)[e] ?? e } else value += c
    }
    values[key] = value
  }
  return values
}
it('C5-V32 independent roundtrip covers twelve rules and all exported fields', () => {
  const variants: Partial<RuleDTO>[] = [{ ttl: '!0-31', dscp: '1,2' }, { tcp_flags: 'SYN,!ACK' }, { dst_ip: '2001:db8::7' },
    { dst_ip: '', dst_cidr: '203.0.113.0/24' }, { comment: 'white space' }, { comment: '"quoted"' }, { comment: 'back\\slash' },
    { comment: 'new\nline\r\ttab' }, { comment: '# = value' }, { match_anomaly: 4 }, { enabled: false, action: 'drop' },
    { src_ip: '198.51.100.8', rate_limit: 200, expires_at: new Date(now + 62000).toISOString(), pkt_len: '64,128' }]
  expect(variants).toHaveLength(12); expect(variants.some(r => r.match_anomaly)).toBe(true)
  const keys = 'src_ip dst_ip src_cidr dst_cidr src_port dst_port protocol ttl dscp icmp_type icmp_code fragment pkt_len tcp_flags match_anomaly action rate_limit enabled comment'.split(' ')
  for (const [i, variant] of variants.entries()) {
    const r = rule(i + 1, variant), parsed = referenceParse(serializeRule(r, now)), expected: Record<string,string> = {}
    for (const key of keys) {
      const value = r[key as keyof RuleDTO]
      if (key === 'enabled') { if (!value) expected[key] = 'false' }
      else if (key === 'rate_limit') { if (r.action === 'rate_limit') expected[key] = String(value) }
      else if (value !== '' && value !== null && value !== 0) expected[key] = String(value)
    }
    if (r.expires_at) expected.expires_in = '2m'
    expect(parsed).toEqual(expected)
  }
})
it('C5-V18 nice axis values and 1 2 5 steps', () => {
  for (const [raw, interval, max] of [[0,1,1],[6,2,6],[15,5,15],[1200000,1,2],[780000000*8,2,8]]) {
    const axis = integerAxis(raw!); expect(axis.interval).toBe(interval); expect(axis.max).toBe(max)
    expect([1,2,5]).toContain(axis.interval / 10 ** Math.floor(Math.log10(axis.interval))); expect(axis.interval).toBeGreaterThanOrEqual(1)
    expect(axis.max * axis.scale).toBeGreaterThanOrEqual(raw!)
  }
})
it('C5 loaded grouping only counts loaded rows', () => { expect(grouped([rule(),rule(2)]).get('g')).toEqual({ first: rule().id, count: 2 }) })
