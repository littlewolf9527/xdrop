// @vitest-environment node
import { beforeEach, afterEach, expect, it, vi } from 'vitest'
import type { ViteDevServer } from 'vite'
import { mockPlugin } from '../mock/server'
import { contracts } from '../src/api/contract'
import { isIP } from '../mock/ip'

type Handler = (req: unknown, res: unknown, next: () => void) => Promise<unknown>
type Result = { status: number; headers: Record<string, string>; chunks: string[]; end?: string; value: any; close(): void }
function backend(profile?: 'demo' | 'fixture') {
  let handler!: Handler, cookie = ''
  const plugin = profile ? mockPlugin({ profile }) : mockPlugin()
  if (typeof plugin.configureServer !== 'function') throw new Error('Missing middleware')
  plugin.configureServer.call({} as never, { middlewares: { use(fn: Handler) { handler = fn } }, httpServer: { once() {} } } as unknown as ViteDevServer)
  return async (path: string, method = 'GET', body?: unknown, authenticated = true, raw?: string): Promise<Result> => {
    const headers: Record<string, string> = {}, chunks: string[] = [], closeCallbacks: (() => void)[] = []
    let end: string | undefined
    const res = {
      statusCode: 200,
      setHeader(name: string, value: string) {
        headers[name.toLowerCase()] = value
        if (name.toLowerCase() === 'set-cookie') cookie = value.includes('Max-Age=0') ? '' : value.split(';')[0]!
      },
      writeHead(status: number, values: Record<string, string>) { this.statusCode = status; for (const [key, value] of Object.entries(values)) this.setHeader(key, value) },
      write(value: string) { chunks.push(value) },
      end(value?: string) { end = value },
      destroy() {},
      once(_event: string, fn: () => void) { closeCallbacks.push(fn) },
    }
    await handler({ url: path.startsWith('/__mock/') ? path : '/api/v1' + path, method, headers: { cookie: authenticated ? cookie : '' }, once() {}, async *[Symbol.asyncIterator]() { if (raw !== undefined) yield raw; else if (body !== undefined) yield JSON.stringify(body) } }, res, () => { res.statusCode = 404 })
    if (path.startsWith('/audit/export')) await vi.advanceTimersByTimeAsync(25)
    return { status: res.statusCode, headers, chunks, end, value: end && !chunks.length ? JSON.parse(end) : undefined, close() { closeCallbacks.forEach(fn => fn()) } }
  }
}
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-31T00:00:00Z')) })
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers() })
const login = (call: ReturnType<typeof backend>, username = 'admin', password = 'example-password-1') => call('/auth/login', 'POST', { username, password })
const sample = { dst_ip: '203.0.113.250', protocol: 'tcp', dst_port: 8443, action: 'drop' }
const ruleOne = 'rule_' + '1'.padStart(32, '0')

it('B R1 fixture whitelist preserves non-string IP input behavior', async () => {
  const call = backend(); await login(call)
  const numeric = await call('/whitelist', 'POST', { src_ip: 123 })
  expect(numeric.status).toBe(400)
  expect(numeric.value).toMatchObject({ code: 'invalid_rule', field: 'ip' })
  // Baseline Node isIP coerces the array; the existing whitelist create branch returns 201 without an error code.
  const array = await call('/whitelist', 'POST', { dst_ip: ['192.0.2.1'] })
  expect(array.status).toBe(201)
  expect(array.value.code).toBeUndefined()
})

it('B2 D1 nonempty login, no throttling, sorted surviving administrator fallback', async () => {
  for (const profile of ['fixture','demo'] as const) {
    const call = backend(profile), demo = profile === 'demo'
    for (let i = 0; i < 4; i++) expect((await login(call, 'visitor', 'demo')).status).toBe(demo ? 200 : i < 3 ? 401 : 429)
    expect((await login(call, '', 'demo')).status).toBe(401)
    expect((await login(call, 'empty-password', '')).status).toBe(401)
    await login(call)
    expect((await call('/users/operator/role', 'PUT', { role: 'admin' })).status).toBe(204)
    await login(call, 'operator')
    expect((await call('/users/admin', 'DELETE')).status).toBe(204)
    expect((await call('/auth/logout', 'POST')).status).toBe(204)
    const result = await login(call, 'unknown-user', 'demo')
    expect(result.status).toBe(demo ? 200 : 401)
    if (demo) {
      expect(result.value.username).toBe('operator')
      expect((await call('/auth/me')).value).toMatchObject({ name: 'operator', role: 'admin' })
      expect((await call('/credentials')).status).toBe(200)
      await call('/users', 'POST', { username: 'aaa', role: 'admin', password: 'example-password-1' })
      expect((await login(call, 'unknown-user', 'demo')).value.username).toBe('aaa')
    }
  }
})
it('B2 D2 password checks and session revocation remain, traps and throttling differ', async () => {
  for (const profile of ['fixture','demo'] as const) {
    const call = backend(profile), demo = profile === 'demo'
    await login(call)
    expect((await call('/auth/me/password', 'PUT', { current_password: 'demo', password: 'short' })).status).toBe(400)
    for (let i = 0; i < 4; i++) expect((await call('/auth/me/password', 'PUT', { current_password: '', password: 'example-password-2' })).status).toBe(!demo && i === 3 ? 429 : 401)
    const fresh = backend(profile)
    await login(fresh)
    const changed = await fresh('/auth/me/password', 'PUT', { current_password: 'demo', password: 'example-password-2' })
    expect(changed.status).toBe(demo ? 204 : 401)
    expect((await fresh('/auth/me')).status).toBe(demo ? 401 : 200)
    if (!demo) {
      expect((await fresh('/auth/me/password', 'PUT', { current_password: 'example-password-1', password: 'example-password-2' })).status).toBe(204)
      expect((await fresh('/auth/me')).status).toBe(401)
    }
  }
})
it('B2 D3 ttl, rule-one enable and first all-top traps only apply to fixture', async () => {
  for (const profile of ['fixture','demo'] as const) {
    const call = backend(profile), demo = profile === 'demo'; await login(call)
    expect((await call('/rules', 'POST', { ...sample, ttl: '1,2,3,4,5' })).status).toBe(demo ? 201 : 409)
    expect((await call('/rules/' + ruleOne + '/enabled', 'PUT', { enabled: true })).status).toBe(demo ? 200 : 409)
    expect((await call('/traffic/top?n=all')).value.updated_at).toBe(demo ? new Date().toISOString() : null)
    expect((await call('/traffic/top?n=all')).value.updated_at).toBe(new Date().toISOString())
  }
})
it('B2 D4 fixture endpoints require a session in the fixtures control and stay unavailable in demo', async () => {
  for (const profile of ['fixture','demo'] as const) {
    const call = backend(profile), demo = profile === 'demo'; await login(call)
    expect((await call('/__mock/fixtures', 'POST', {}, false)).status).toBe(demo ? 404 : 401)
    expect((await call('/__mock/unknown', 'GET', undefined, false)).status).toBe(demo ? 404 : 401)
    expect((await call('/__mock/fixtures', 'POST', undefined, true, '{')).status).toBe(demo ? 404 : 400)
    expect((await call('/__mock/fixtures', 'POST', { emptyTemplates: true })).status).toBe(demo ? 404 : 204)
    expect((await call('/templates')).value.length).toBe(demo ? 2 : 0)
    expect((await call('/__mock/revoke', 'POST')).status).toBe(demo ? 404 : 204)
    expect((await call('/auth/me')).status).toBe(demo ? 200 : 401)
  }
})
it('B2 D5 rule and whitelist counts reflect current memory only in demo', async () => {
  for (const profile of ['fixture','demo'] as const) {
    const call = backend(profile), demo = profile === 'demo'; await login(call)
    for (const stage of [0, 1, 2]) {
      if (stage === 1) {
        expect((await call('/rules', 'POST', sample)).status).toBe(201)
        expect((await call('/whitelist', 'POST', { src_ip: '203.0.113.250' })).status).toBe(201)
      }
      if (stage === 2) { await call('/rules/' + ruleOne, 'DELETE'); await call('/whitelist/wl_1', 'DELETE') }
      const rules = (await call('/rules?limit=1000')).value.items, whitelist = (await call('/whitelist')).value.items
      const enabled = rules.filter((row: { enabled: boolean }) => row.enabled === true).length
      expect((await call('/capacity')).value.rules).toEqual({ enabled: demo ? enabled : 1284, total: demo ? rules.length : 1300 })
      expect((await call('/system')).value.controller).toMatchObject({ rules_enabled: demo ? enabled : 1284, rules_total: demo ? rules.length : 1300, whitelist: demo ? whitelist.length : 37 })
    }
  }
})

it('G4 profile response differences are confined to the registered D1-D5 requests', async () => {
  // Explicit allowlist; subsequent read differences caused by writes are not silently allowed.
  const script: { path: string; method?: string; body?: unknown; authenticated?: boolean; raw?: string; difference?: string }[] = [
    { path: '/auth/login', method: 'POST', body: { username: 'admin', password: 'example-password-1' } },
    { path: '/__mock/fixtures', method: 'POST', body: {}, authenticated: false, difference: 'D4/R2 all fixture paths precede authentication' },
    { path: '/__mock/unknown', authenticated: false, difference: 'D4/R2 unknown fixture paths precede authentication' },
    { path: '/__mock/fixtures', method: 'POST', raw: '{', difference: 'D4/R2 fixture paths precede JSON parsing' },
    ...['/auth/me','/users','/credentials','/settings','/nodes','/templates','/whitelist','/rules?counts=1','/traffic/top','/traffic/history?range=15m','/traffic/history?range=7d','/audit?limit=1000','/auth/me/prefs','/events'].map(path => ({ path })),
    { path: '/capacity', difference: 'D5 current rule counts' },
    { path: '/system', difference: 'D5 current rule/whitelist counts' },
    { path: '/traffic/top?n=all', difference: 'D3 initial timestamp' },
    { path: '/traffic/top?n=all' },
    { path: '/rules', method: 'POST', body: { ...sample, ttl: '1,2,3,4,5' }, difference: 'D3 ttl trap' },
    { path: '/rules/' + ruleOne + '/enabled', method: 'PUT', body: { enabled: true }, difference: 'D3 enable trap' },
    { path: '/__mock/fixtures', method: 'POST', body: {}, difference: 'D4 fixture endpoint disabled' },
    { path: '/auth/logout', method: 'POST' },
    { path: '/auth/login', method: 'POST', body: { username: 'visitor', password: 'demo' }, difference: 'D1 arbitrary login' },
    { path: '/auth/login', method: 'POST', body: { username: 'admin', password: 'example-password-1' }, difference: 'D1 preceding login changes session serial' },
    { path: '/auth/me/password', method: 'PUT', body: { current_password: 'demo', password: 'example-password-2' }, difference: 'D2 old-password policy' },
    { path: '/auth/login', method: 'POST', body: { username: 'admin', password: 'example-password-1' }, difference: 'D1 preceding login changes session serial' },
    { path: '/__mock/revoke', method: 'POST', difference: 'D4 fixture endpoint disabled' },
  ]
  const fixture = backend(), demo = backend('demo'), differences: string[] = []
  for (const [index, item] of script.entries()) {
    const a = await fixture(item.path, item.method, item.body, item.authenticated, item.raw), b = await demo(item.path, item.method, item.body, item.authenticated, item.raw)
    const comparable = ({ status, headers, chunks, end }: Result) => ({ status, headers, chunks, end })
    if (JSON.stringify(comparable(a)) !== JSON.stringify(comparable(b))) {
      differences.push(index + ':' + item.path)
      expect(item.difference, item.path).toBeTruthy()
    }
    a.close(); b.close()
  }
  console.log('G4 unequal request set ' + JSON.stringify(differences))
})

const seedEndpoints = ['/rules?limit=1000','/whitelist','/nodes','/traffic/top','/traffic/top?n=all','/audit?limit=1000','/credentials']
function addresses(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(addresses)
  if (value && typeof value === 'object') return Object.values(value).flatMap(addresses)
  if (typeof value !== 'string') return []
  const candidates = [...value.matchAll(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:.%]+/g)].map(match => match[0])
  return candidates.filter(value => isIP(value) !== 0)
}
const documented = (ip: string) => /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]+$/.test(ip) || /^2001:db8:/i.test(ip) || ip === '127.0.0.1'
it('G5 all seed IP literals and URL hosts are documentation addresses', async () => {
  const call = backend('demo'); await login(call)
  const values = await Promise.all(seedEndpoints.map(async endpoint => (await call(endpoint)).value))
  const ips = [...new Set(values.flatMap(addresses))]
  expect(ips.length).toBeGreaterThan(200)
  expect(ips.filter(ip => !documented(ip))).toEqual([])
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) value.forEach(visit)
    else if (value && typeof value === 'object') Object.values(value).forEach(visit)
    else if (typeof value === 'string' && /^https?:\/\//.test(value)) expect(documented(new URL(value).hostname.replace(/^\[|\]$/g, ''))).toBe(true)
  }
  values.forEach(visit)
})
it('G5 positive control rejects a private address', () => {
  const control = [10, 1, 2, 3].join('.')
  expect(addresses({ ip: control }).every(documented)).toBe(false)
})
it('G2 isIP matches node:net on at least 200 inputs, including every seed address', async () => {
  const netModule = 'node:net'
  const net = await import(netModule) as { isIP(value: unknown): number }
  const call = backend('demo'); await login(call)
  const corpus = new Set<string>(['','192.0.2.1','192.00.2.1','256.0.2.1','192.0.2','192.0.2.1.2','192..2.1',' 192.0.2.1','192.0.2.1 ','192.0.2.1\n','::','::1','2001:db8:0:0:0:0:0:1','2001:db8::1','::ffff:192.0.2.1','2001:db8::192.0.2.1','::ffff:0192.0.2.1','2001:db8::1%eth0','2001:db8::1%','2001:db8::1%eth_0','2001:db8::1%eth.0-1:2','2001:db8::1/64','192.0.2.1/24','2001::db8::1','2001:db8:0:0:0:0:0:0:1','2001:db8::g','2001:db8::12345','2001:db8::1\n',':2001:db8::','2001:db8:','::192.0.2.1::'])
  for (let i = 0; i <= 260; i++) {
    corpus.add('192.0.2.' + i)
    corpus.add('192.0.2.' + String(i).padStart(3, '0'))
    corpus.add('2001:db8::' + i.toString(16))
  }
  for (const endpoint of seedEndpoints) for (const ip of addresses((await call(endpoint)).value)) corpus.add(ip)
  expect(corpus.size).toBeGreaterThanOrEqual(200)
  for (const input of corpus) expect(isIP(input), input).toBe(net.isIP(input))
  const nonStrings: unknown[] = [123, 0, null, undefined, true, {}, [], ['192.0.2.1'], ['::1'], [['192.0.2.1']], ['192.0.2.1', 'x']]
  for (const input of nonStrings) expect(isIP(input), JSON.stringify(input)).toBe(net.isIP(input))
  const symbol = Symbol('demo-isIP')
  expect(() => net.isIP(symbol)).toThrow(TypeError)
  expect(() => isIP(symbol)).toThrow(TypeError)
  console.log('G2 differential corpus=' + corpus.size)
  console.log('G2 non-string cases=' + nonStrings.length + '; Symbol throws TypeError in both implementations')
})

it('G6 19 backend GET occurrences are independently counted and covered', async () => {
  const fsModule = 'node:fs', cpModule = 'node:child_process'
  const { readFileSync } = await import(fsModule) as { readFileSync(path: URL, encoding: string): string }
  const { execFileSync } = await import(cpModule) as { execFileSync(bin: string, args: string[], options: { encoding: string }): string }
  const urls = ['api.go','accounts.go'].map(name => new URL('../../controller/core/api/' + name, import.meta.url))
  const paths = urls.flatMap(url => [...readFileSync(url, 'utf8').matchAll(/\{"GET", "(\/[^\"]*)"/g)].map(match => match[1]!))
  const counted = execFileSync('/usr/bin/grep', ['-o', '{"GET", "', ...urls.map(url => decodeURIComponent(url.pathname))], { encoding: 'utf8' }).trim().split('\n').length
  expect(counted).toBe(19); expect(paths).toHaveLength(counted)
  const exclusions: Record<string, string> = { '/health': 'public endpoint, console does not call it', '/rules/:id/delivery': 'console does not call delivery' }
  expect(Object.keys(exclusions)).toHaveLength(2)
  const source = decodeURIComponent(new URL('../src', import.meta.url).pathname)
  for (const needle of ["'/health'", 'delivery']) {
    try { execFileSync('/usr/bin/grep', ['-R', '--exclude-dir=docs', '-n', needle, source], { encoding: 'utf8' }); throw new Error('Unexpected console reference') }
    catch (error) { expect((error as { status: number }).status).toBe(1) }
  }
  expect(execFileSync('/usr/bin/grep', ['-R', '--exclude-dir=docs', '-o', "'/rules/'", source], { encoding: 'utf8' }).trim().split('\n').length).toBeGreaterThanOrEqual(1)
  const call = backend('demo'); await login(call)
  for (const path of paths) {
    if (exclusions[path]) continue
    const request = path.replace(':id', ruleOne).replace(':name', 'edge-01') + (path === '/audit/export' ? '?from=2026-10-17T00:00:00Z&to=2026-10-18T00:00:00Z&format=csv' : '')
    const result = await call(request)
    // Every covered route uses a logged-in session and valid parameters; no status exceptions are needed.
    expect(result.status, request).toBe(200)
    result.close()
  }
  console.log('G6 occurrences=' + counted + ' covered=' + (paths.length - Object.keys(exclusions).length) + ' exclusions=' + JSON.stringify(exclusions))
})

it('G7 each GET field contract uses full URLs, separate unauthenticated samples and event frames', async () => {
  const module = new URL('../scripts/contract-check.mjs', import.meta.url).href
  const { resolvePath } = await import(module) as { resolvePath(value: unknown, path: string, nullable?: boolean): string }
  const call = backend('demo'); await login(call)
  const firstID = (await call('/rules?limit=1')).value.items[0].id
  const stream = await call('/events'), frames: Record<string, unknown> = {}
  for (const chunk of stream.chunks) {
    const event = /^event: (.+)$/m.exec(chunk)?.[1], data = /^data: (.+)$/m.exec(chunk)?.[1]
    if (event && data) frames[event] = JSON.parse(data)
  }
  stream.close()
  // No environment-dependent query sample currently needs replacement.
  const querySamples: Record<string, string> = {}
  const cache = new Map<string, Result>(), counts: Record<string, number> = { hit: 0, missing: 0, uncovered: 0, writes: 0 }
  for (const entry of contracts) {
    if (!entry.endpoint.startsWith('GET ')) { counts.writes!++; continue }
    const authenticated = entry.status !== 401, query = querySamples[entry.query || ''] ?? entry.query
    let endpoint = entry.endpoint.slice(4).replace('{rule_id}', firstID)
    if (query) endpoint += (endpoint.includes('?') ? '&' : '?') + query
    const key = String(authenticated) + ':' + endpoint
    if (!cache.has(key)) cache.set(key, await call(endpoint.replace(/^\/api\/v1/, ''), 'GET', undefined, authenticated))
    const result = cache.get(key)!
    expect(result.status, key).toBe(entry.status ?? 200)
    result.close()
    const verdict = resolvePath(entry.event ? frames[entry.event] : result.value, entry.path, entry.nullable)
    counts[verdict] = (counts[verdict] || 0) + 1
    expect(verdict, entry.endpoint + ' ' + entry.path).toBe('hit')
  }
  console.log('G7 entries=' + contracts.length + ' verdicts=' + JSON.stringify(counts))
})
