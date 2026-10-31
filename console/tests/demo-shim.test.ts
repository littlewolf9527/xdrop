// @vitest-environment node
import { beforeEach, afterEach, expect, it, vi } from 'vitest'

const middleware = vi.hoisted(() => ({ streams: [] as { writes: number }[] }))
vi.mock('../mock/server', async importOriginal => {
  const actual = await importOriginal<typeof import('../mock/server')>()
  return { ...actual, mockPlugin(...args: Parameters<typeof actual.mockPlugin>) {
    const plugin = actual.mockPlugin(...args), configure = plugin.configureServer
    if (typeof configure !== 'function') throw new Error('Missing middleware')
    plugin.configureServer = function(server) {
      const use = server.middlewares.use.bind(server.middlewares)
      server.middlewares.use = ((handler: (req: any, res: any, next: any) => unknown) => use((req, res, next) => {
        if ((req as { url?: string }).url?.split('?')[0] === '/api/v1/events') {
          const trace = { writes: 0 }, write = res.write.bind(res)
          middleware.streams.push(trace)
          // Observe attempted middleware writes before shim.write can suppress them after cancellation.
          res.write = ((...values: Parameters<typeof res.write>) => { trace.writes++; return write(...values) }) as typeof res.write
        }
        return handler(req, res, next)
      })) as typeof server.middlewares.use
      return configure.call(this, server)
    }
    return plugin
  } }
})

let originalFetch: ReturnType<typeof vi.fn>
let links: { href: string; setAttribute(name: string, value: string): void }[]
let observe: () => void
beforeEach(async () => {
  vi.resetModules()
  middleware.streams.length = 0
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
  vi.setSystemTime(new Date('2026-10-31T00:00:00Z'))
  vi.stubEnv('BASE_URL', '/xdrop/')
  originalFetch = vi.fn(async () => new Response('static'))
  links = []
  vi.stubGlobal('window', globalThis)
  vi.stubGlobal('location', new URL('http://127.0.0.1/xdrop/'))
  vi.stubGlobal('fetch', originalFetch)
  vi.stubGlobal('EventSource', class { constructor(public url: string | URL) {} })
  vi.stubGlobal('document', { querySelectorAll: () => links.filter(link => link.href === '/third-party.txt') })
  vi.stubGlobal('MutationObserver', class {
    constructor(callback: () => void) { observe = callback }
    observe() {}
  })
  await import('../demo/shim')
})
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.unstubAllEnvs() })

const post = (path: string, body?: unknown) => fetch('/api/v1' + path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
const sample = { dst_ip: '203.0.113.250', protocol: 'tcp', dst_port: 8443, action: 'drop' }
const waitFor = (source: EventSource, name: string) => new Promise<MessageEvent>((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error('No first ' + name + ' frame')), 500)
  source.addEventListener(name, event => { clearTimeout(timeout); resolve(event as MessageEvent) }, { once: true })
})

it('B1① auto login precedes application requests', async () => {
  const result = await fetch('/api/v1/auth/me')
  expect(result.status).toBe(200)
  expect(await result.json()).toMatchObject({ name: 'admin', role: 'admin' })
  expect(originalFetch).not.toHaveBeenCalled()
})
it('B1② visitors can create and find a rule', async () => {
  const created = await post('/rules', sample)
  expect(created.status).toBe(201)
  expect(created.headers.has('set-cookie')).toBe(false)
  const page = await (await fetch('/api/v1/rules?q=' + sample.dst_ip)).json()
  expect(page.items.some((row: { dst_ip: string }) => row.dst_ip === sample.dst_ip)).toBe(true)
})
it('B1③ logout returns 204 and ends an open stream exactly once', async () => {
  const stream = new EventSource('/api/v1/events'), error = vi.fn()
  stream.onerror = error
  await waitFor(stream, 'rules')
  expect(stream.readyState).toBe(1)
  expect((await post('/auth/logout')).status).toBe(204)
  await vi.waitFor(() => { expect(stream.readyState).toBe(2); expect(error).toHaveBeenCalledTimes(1) })
  expect((await fetch('/api/v1/auth/me')).status).toBe(401)
  stream.close()
  expect(error).toHaveBeenCalledTimes(1)
})
it('B1④ any nonempty login restores the session', async () => {
  await post('/auth/logout')
  expect((await post('/auth/login', { username: 'visitor', password: 'demo' })).status).toBe(200)
  expect((await fetch('/api/v1/auth/me')).status).toBe(200)
})
it('B1⑤ audit export preserves complete UTF-8 data in multiple chunks', async () => {
  const query = 'from=2026-10-17T00:00:00Z&to=2026-10-18T00:00:00Z'
  const events = (await (await fetch('/api/v1/audit?' + query + '&limit=1000')).json()).items.reverse()
  const csv = (value: unknown) => {
    let text = value === null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value)
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text
    return /[",\r\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text
  }
  const expected = 'id,at,actor,source,action,target,before,after\n' + events.map((row: Record<string, unknown>) => ['id','at','actor','source','action','target','before','after'].map(key => csv(row[key])).join(',') + '\n').join('')
  const response = await fetch('/api/v1/audit/export?' + query + '&format=csv')
  expect(response.headers.get('content-disposition')).toContain('.csv')
  expect(response.headers.get('content-type')).toBe('text/csv; charset=utf-8')
  const reader = response.body!.getReader(), chunks: Uint8Array[] = []
  for (;;) { const chunk = await reader.read(); if (chunk.done) break; chunks.push(chunk.value) }
  expect(chunks.length).toBeGreaterThanOrEqual(2)
  expect(new TextDecoder().decode(new Uint8Array(chunks.flatMap(chunk => [...chunk])))).toBe(expected)
})
it('B1⑥ other fetches preserve their original inputs', async () => {
  const init = { headers: { 'X-Demo-Test': 'sample' } }
  await fetch('/xdrop/asset.txt', init)
  expect(originalFetch).toHaveBeenCalledWith('/xdrop/asset.txt', init)
  await fetch('https://example.invalid/api/v1/rules')
  expect(originalFetch).toHaveBeenLastCalledWith('https://example.invalid/api/v1/rules', undefined)
})
it('B1⑦ license fetch uses the Pages base', async () => {
  await fetch('/third-party.json')
  expect(String(originalFetch.mock.calls[0]![0])).toBe('http://127.0.0.1/xdrop/third-party.json')
})
it('B1⑧ deleting an existing rule returns a null-body 204', async () => {
  const created = await (await post('/rules', sample)).json()
  const response = await fetch('/api/v1/rules/' + created.id, { method: 'DELETE' })
  expect(response.status).toBe(204)
  expect(response.ok).toBe(true)
  expect(response.body).toBeNull()
  expect((await fetch('/api/v1/rules/' + created.id)).status).toBe(404)
})
it('B1⑨ Request input and init overrides reach the middleware', async () => {
  expect((await fetch(new Request(new URL('/api/v1/auth/me', location.href)))).status).toBe(200)
  const request = new Request(new URL('/api/v1/rules', location.href), { method: 'POST', body: JSON.stringify({ dst_ip: '203.0.113.249' }) })
  const created = await fetch(request, { body: JSON.stringify(sample), headers: { 'Content-Type': 'application/json' } })
  expect(created.status).toBe(201)
  expect((await created.json()).dst_ip).toBe(sample.dst_ip)
})
it('B1⑩ listeners registered synchronously receive the first frame asynchronously', async () => {
  const stream = new EventSource('/api/v1/events')
  expect(stream.readyState).toBe(0)
  const first = waitFor(stream, 'rules')
  expect(JSON.parse((await first).data).seq).toBe(42)
  stream.close()
  expect(stream.readyState).toBe(2)
})
it('B1 R5 active close unregisters the middleware stream before writes and ticks', async () => {
  const closed = new EventSource('/api/v1/events'), active = new EventSource('/api/v1/events')
  try {
    await Promise.all([waitFor(closed, 'rules'), waitFor(active, 'rules')])
    expect(middleware.streams).toHaveLength(2)
    const closedTrace = middleware.streams[0]!, activeTrace = middleware.streams[1]!
    expect(closedTrace.writes).toBeGreaterThanOrEqual(4)
    const closedBefore = closedTrace.writes, activeBefore = activeTrace.writes
    closed.close()
    expect(closed.readyState).toBe(2)
    expect((await post('/rules', sample)).status).toBe(201)
    expect(activeTrace.writes).toBeGreaterThan(activeBefore)
    expect(closedTrace.writes).toBe(closedBefore)
    const activeAfterWrite = activeTrace.writes
    await vi.advanceTimersByTimeAsync(5000)
    expect(activeTrace.writes).toBeGreaterThan(activeAfterWrite)
    expect(closedTrace.writes).toBe(closedBefore)
  } finally { closed.close(); active.close() }
})
it('B1 S8 license links follow added and changed anchors', () => {
  const link = { href: '/third-party.txt', setAttribute(_name: string, value: string) { this.href = value } }
  links.push(link); observe()
  expect(link.href).toBe('/xdrop/third-party.txt')
  link.href = '/third-party.txt'; observe()
  expect(link.href).toBe('/xdrop/third-party.txt')
})
it('G6 events have rules, nodes and traffic frames', async () => {
  const stream = new EventSource('/api/v1/events')
  const frames = await Promise.all(['rules','nodes','traffic'].map(name => waitFor(stream, name)))
  expect(frames.map(frame => frame.type)).toEqual(['rules','nodes','traffic'])
  for (const frame of frames) expect(JSON.parse(frame.data)).toBeTypeOf('object')
  const { contracts } = await import('../src/api/contract')
  const module = new URL('../scripts/contract-check.mjs', import.meta.url).href
  const { resolvePath } = await import(module) as { resolvePath(value: unknown, path: string, nullable?: boolean): string }
  const values = Object.fromEntries(frames.map(frame => [frame.type, JSON.parse(frame.data)]))
  for (const entry of contracts.filter(entry => entry.endpoint.startsWith('GET ') && entry.event)) {
    expect(resolvePath(values[entry.event!], entry.path, entry.nullable), 'G7 fake EventSource ' + entry.event + ' ' + entry.path).toBe('hit')
  }
  stream.close()
})
