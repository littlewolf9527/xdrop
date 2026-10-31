import { mockPlugin } from '../mock/server'
import type { ViteDevServer } from 'vite'

type Handler = (req: unknown, res: unknown, next: () => void) => unknown
let handler!: Handler
let cookie = ''
const plugin = mockPlugin({ profile: 'demo' })
const configure = plugin.configureServer
if (typeof configure !== 'function') throw new Error('Missing demo middleware')
configure.call({} as never, {
  middlewares: { use(fn: Handler) { handler = fn } },
  httpServer: { once() {} },
} as unknown as ViteDevServer)

function dispatch(request: Request): Promise<Response> {
  const url = new URL(request.url)
  return new Promise((resolve, reject) => {
    const headers = new Headers()
    let controller!: ReadableStreamDefaultController<Uint8Array>
    let sent = false, ended = false
    const closeCallbacks: (() => void)[] = []
    const closed = () => { for (const fn of closeCallbacks.splice(0)) fn() }
    const stream = new ReadableStream<Uint8Array>({
      start(value) { controller = value },
      cancel() { ended = true; closed() },
    })
    const send = () => {
      if (sent) return
      sent = true
      resolve(new Response([204, 205, 304].includes(res.statusCode) ? null : stream, { status: res.statusCode, headers }))
    }
    const encoder = new TextEncoder()
    const res = {
      statusCode: 200,
      setHeader(name: string, value: string) {
        if (name.toLowerCase() === 'set-cookie') {
          const session = /(?:^|;\s*)xdrop_session=([^;]*)/.exec(value)
          if (session) cookie = /(?:^|;\s*)Max-Age=0(?:;|$)/i.test(value) ? '' : 'xdrop_session=' + session[1]
        } else headers.set(name, value)
      },
      writeHead(status: number, values: Record<string, string>) {
        res.statusCode = status
        for (const [name, value] of Object.entries(values)) res.setHeader(name, value)
        send()
      },
      write(value: string) {
        if (ended) return
        send()
        controller.enqueue(encoder.encode(value))
      },
      end(value?: string) {
        if (ended) return
        send()
        if (value !== undefined) controller.enqueue(encoder.encode(value))
        ended = true
        controller.close()
        closed()
      },
      destroy() {
        if (ended) return
        send()
        ended = true
        controller.error(new Error('Demo response interrupted'))
        closed()
      },
      once(event: string, fn: () => void) { if (event === 'close') closeCallbacks.push(fn) },
    }
    const req = {
      url: url.pathname + url.search,
      method: request.method,
      headers: { ...Object.fromEntries(request.headers), cookie },
      once() {},
      async *[Symbol.asyncIterator]() {
        if (!request.body) return
        const reader = request.body.getReader(), decoder = new TextDecoder()
        try {
          for (;;) {
            const chunk = await reader.read()
            if (chunk.done) break
            yield decoder.decode(chunk.value, { stream: true })
          }
          const tail = decoder.decode()
          if (tail) yield tail
        } finally { reader.releaseLock() }
      },
    }
    const next = () => {
      res.statusCode = 404
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ code: 'not_found' }))
    }
    try {
      Promise.resolve(handler(req, res, next)).catch(error => {
        if (!sent) reject(error)
        res.destroy()
      })
    } catch (error) { reject(error); res.destroy() }
  })
}

const originalFetch = window.fetch.bind(window)
window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input), location.href)
  if (url.origin === location.origin && url.pathname.startsWith('/api/')) return dispatch(new Request(input instanceof Request ? input : url, init))
  if (url.pathname === '/third-party.json') {
    const rewritten = new URL(import.meta.env.BASE_URL + 'third-party.json', location.href)
    return originalFetch(input instanceof Request ? new Request(rewritten, new Request(input, init)) : rewritten, input instanceof Request ? undefined : init)
  }
  return originalFetch(input, init)
}

const OriginalEventSource = window.EventSource
class DemoEventSource extends EventTarget {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSED = 2
  readonly CONNECTING = 0
  readonly OPEN = 1
  readonly CLOSED = 2
  readyState = 0
  readonly url: string
  readonly withCredentials: boolean
  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  private reader?: ReadableStreamDefaultReader<Uint8Array>

  constructor(input: string | URL, init?: EventSourceInit) {
    super()
    const url = new URL(input, location.href)
    this.url = url.href
    this.withCredentials = init?.withCredentials ?? false
    if (url.pathname !== '/api/v1/events') return new OriginalEventSource(input, init) as unknown as DemoEventSource
    queueMicrotask(() => { void this.start() })
  }

  private fail() {
    if (this.readyState === 2) return
    this.readyState = 2
    const event = new Event('error')
    this.dispatchEvent(event)
    this.onerror?.(event)
  }

  private async start() {
    if (this.readyState === 2) return
    try {
      const response = await dispatch(new Request(this.url))
      if (response.body) this.reader = response.body.getReader()
      if (this.readyState === 2) { await this.reader?.cancel(); return }
      if (response.status !== 200 || !this.reader) { await this.reader?.cancel(); this.fail(); return }
      this.readyState = 1
      const opened = new Event('open')
      this.dispatchEvent(opened)
      this.onopen?.(opened)
      const decoder = new TextDecoder()
      let buffer = ''
      while (this.readyState !== 2) {
        const chunk = await this.reader.read()
        if (this.readyState === 2) return
        if (chunk.done) { this.fail(); return }
        buffer += decoder.decode(chunk.value, { stream: true }).replace(/\r/g, '')
        let split: number
        while ((split = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, split)
          buffer = buffer.slice(split + 2)
          const data: string[] = []
          let name = 'message'
          for (const line of frame.split('\n')) {
            if (line.startsWith('event:')) name = line.slice(6).replace(/^ /, '')
            if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''))
          }
          if (data.length && this.readyState !== 2) {
            const event = new MessageEvent(name, { data: data.join('\n'), origin: location.origin })
            this.dispatchEvent(event)
            if (name === 'message') this.onmessage?.(event)
          }
        }
      }
    } catch { this.fail() }
  }

  close() {
    if (this.readyState === 2) return
    this.readyState = 2
    void this.reader?.cancel()
  }
}
window.EventSource = DemoEventSource as unknown as typeof EventSource

function rewriteLicenses() {
  for (const link of document.querySelectorAll<HTMLAnchorElement>('a[href="/third-party.txt"]')) link.setAttribute('href', import.meta.env.BASE_URL + 'third-party.txt')
}
new MutationObserver(rewriteLicenses).observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['href'] })
rewriteLicenses()

await window.fetch('/api/v1/auth/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: 'demo' }),
})
