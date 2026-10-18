import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import type { Node } from '../src/api/types'
import { createRouter, createMemoryHistory, createWebHistory, type Router } from 'vue-router'
let app: typeof import('../src/state'), router: Router, account: string, calls: string[], streams: { closed: boolean }[]
let intercept: ((path: string, init?: RequestInit) => Promise<Response> | undefined) | undefined
const deferred = <T>() => {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => { resolve = r })
  return { promise, resolve }
}
const routes = ['/overview', '/nodes', '/settings', '/login'].map(path => ({ path, component: { template: '<div />' } }))
beforeEach(async () => {
  vi.resetModules(); vi.useFakeTimers(); localStorage.clear(); sessionStorage.clear(); account = 'A'; calls = []; streams = []; intercept = undefined
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener: vi.fn() }))
  vi.stubGlobal('EventSource', class {
    closed = false; readyState = 1; onerror = null
    constructor() { streams.push(this) }
    addEventListener() {} close() { this.closed = true }
  })
  vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
    const path = input.replace('/api/v1', ''); calls.push(path + ':' + (init?.method || 'GET'))
    const delayed = intercept?.(path, init); if (delayed) return delayed
    if (path === '/auth/me') return Response.json({ name: account, role: 'admin' })
    if (path === '/auth/me/prefs') return init?.method === 'PUT' ? new Response(null, { status: 204 }) : Response.json({})
    if (path === '/settings') return Response.json({ default_language: 'en-US' })
    if (path === '/capacity') return Response.json({ tightest: { name: 'cond', ratio: 0, exhausted: false }, dimensions: [] })
    return Response.json({})
  }))
  app = await import('../src/state'); router = createRouter({ history: createMemoryHistory(), routes })
  await router.push('/nodes'); await router.isReady(); await app.initialize(router)
})
afterEach(() => { app.expire(); vi.useRealTimers(); vi.unstubAllGlobals() })
it('V-r9a expired generation discards late identity and session continuations', async () => {
  const identity = deferred<Response>(); intercept = path => path === '/auth/me' ? identity.promise : undefined
  const first = app.refreshIdentity(); app.expire(); identity.resolve(Response.json({ name: 'A', role: 'admin' }))
  await first; expect(app.state.user).toBeNull()
  intercept = undefined; await app.session()
  const prefs = deferred<Response>(); intercept = path => path === '/auth/me/prefs' ? prefs.promise : undefined
  const second = app.session(); await flushPromises(); app.expire(); prefs.resolve(Response.json({ lang: 'ja-JP' }))
  await second; expect(app.state.user).toBeNull(); expect(streams.filter(s => !s.closed)).toHaveLength(0)
  expect(app.state.lang).not.toBe('ja-JP')
})
it('V-r9c initial unauthenticated deep link preserves full next path', async () => {
  app.expire(); vi.resetModules(); window.history.replaceState({}, '', '/nodes?focus=edge-01')
  intercept = path => path === '/auth/me' ? Promise.resolve(Response.json({ code: 'unauthenticated', message: '' }, { status: 401 }))
    : undefined
  app = await import('../src/state'); const deep = createRouter({ history: createWebHistory(), routes })
  await app.initialize(deep); await flushPromises()
  expect(deep.currentRoute.value.fullPath).toBe('/')
  deep.beforeEach(to => app.guard(to.path, to.fullPath))
  const { createApp } = await import('vue'); const host = document.createElement('div'); document.body.append(host)
  const mounted = createApp({ template: '<div />' }).use(deep).mount(host)
  await deep.isReady(); await flushPromises()
  expect(deep.currentRoute.value.query.next).toBe('/nodes?focus=edge-01')
  expect(deep.currentRoute.value.path).toBe('/login')
  mounted.$.appContext.app.unmount(); deep.options.history.destroy(); host.remove()
})
it('V-r9d queued preferences cannot read or write across account generations', async () => {
  const old = deferred<Response>(); const writes: string[] = []; const reads: string[] = []
  intercept = (path, init) => {
    if (path !== '/auth/me/prefs') return
    if (init?.method === 'PUT') { writes.push(account + ':' + init.body); return Promise.resolve(new Response(null, { status: 204 })) }
    reads.push(account); return old.promise
  }
  app.setLanguage('ja-JP'); app.setTheme('dark'); await flushPromises(); expect(reads).toEqual(['A'])
  app.expire(); account = 'B'; app.state.user = { name: 'B', role: 'admin' }
  old.resolve(Response.json({ future: 'A' })); await flushPromises()
  expect(writes).toEqual([]); expect(reads).toEqual(['A'])
})
it('V-r9e expire resolves login theme from browser storage', () => {
  localStorage.setItem('xd.theme', 'light'); app.state.theme = 'dark'; app.applyAppearance(); app.expire()
  expect(app.state.theme).toBe('light'); expect(document.documentElement.dataset.theme).toBe('light')
})
it('P2-4 authenticated initialization failure keeps session and reports operation failure', async () => {
  intercept = path => path === '/settings' ? Promise.resolve(Response.json({ code: 'unavailable', message: '' }, { status: 503 }))
    : undefined
  expect(await app.login('A', 'example-password-1')).toBe(false)
  expect(app.state.user?.name).toBe('A'); expect(app.state.error).toBe('operationFailed')
})
it('P2-5 settings identity network and server failures preserve current route', async () => {
  router.beforeEach(to => app.guard(to.path, to.fullPath))
  for (const server of [false, true]) {
    intercept = path => path === '/auth/me' ? server
      ? Promise.resolve(Response.json({ code: 'unavailable', message: '' }, { status: 503 }))
      : Promise.reject(new TypeError('offline')) : undefined
    await router.push('/settings'); expect(router.currentRoute.value.path).toBe('/nodes')
    expect(app.state.user?.name).toBe('A'); expect(app.state.error).toBe(server ? 'operationFailed' : 'unreachable')
  }
})

it.each(['after', 'during'])('V-r10a old 401 %s B login cannot expire B or invalidate login', async phase => {
  const old = deferred<Response>(), login = deferred<Response>()
  intercept = path => path.startsWith('/traffic/history') ? old.promise : undefined
  const pending = app.loadHistory(); app.expire(); await flushPromises(); account = 'B'
  intercept = path => path === '/auth/login' && phase === 'during' ? login.promise : undefined
  const next = app.login('B', 'example-password-1')
  if (phase === 'after') expect(await next).toBe(true)
  else { await flushPromises(); expect(app.state.user).toBeNull() }
  old.resolve(Response.json({ code: 'unauthenticated', message: '' }, { status: 401 })); await pending
  if (phase === 'during') { login.resolve(Response.json({})); expect(await next).toBe(true) }
  expect(app.state.user?.name).toBe('B'); expect(streams.filter(s => !s.closed)).toHaveLength(1)
  expect(app.state.error).toBe('')
})
it('V-r10a old 503 cannot report an error in the next account', async () => {
  const old = deferred<Response>()
  intercept = path => path.startsWith('/traffic/history') ? old.promise : undefined
  const pending = app.loadHistory(); app.expire(); await flushPromises(); account = 'B'; intercept = undefined
  expect(await app.login('B', 'example-password-1')).toBe(true)
  old.resolve(Response.json({ code: 'unavailable', message: '' }, { status: 503 })); await pending
  expect(app.state.error).toBe(''); expect(app.state.user?.name).toBe('B')
})
it('V-r10a demotion continuation cannot navigate after its generation expires', async () => {
  const identity = deferred<Response>()
  intercept = path => path.startsWith('/traffic/history')
    ? Promise.resolve(Response.json({ code: 'admin_required', message: '' }, { status: 403 }))
    : path === '/auth/me' ? identity.promise : undefined
  const pending = app.loadHistory(); await flushPromises()
  expect(calls.filter(path => path === '/auth/me:GET')).toHaveLength(2)
  app.expire(); await flushPromises(); account = 'B'; intercept = undefined
  expect(await app.login('B', 'example-password-1')).toBe(true); await router.push('/nodes')
  identity.resolve(Response.json({ name: 'A', role: 'operator' })); await pending
  expect(router.currentRoute.value.path).toBe('/nodes'); expect(app.state.user?.name).toBe('B')
  expect(app.state.error).toBe('')
})
it('V-r10b expire clears layout and errors without saving across accounts', async () => {
  app.state.layout = { order: ['rules', 'bps', 'ip', 'pps'], split: 3 }; app.state.error = 'operationFailed'
  app.saveLayout()
  const writes = calls.filter(path => path === '/auth/me/prefs:PUT').length
  app.expire(); await flushPromises()
  expect(app.state.layout).toEqual({ order: ['pps', 'ip', 'bps', 'rules'], split: 1.4 }); expect(app.state.error).toBe('')
  account = 'B'; intercept = path => path === '/settings'
    ? Promise.resolve(Response.json({ code: 'unavailable', message: '' }, { status: 503 })) : undefined
  expect(await app.login('B', 'example-password-1')).toBe(false)
  expect(app.state.user?.name).toBe('B'); expect(await app.guard('/overview', '/overview')).toBe(true)
  await router.push('/overview')
  const reads = calls.filter(path => path === '/auth/me/prefs:GET').length
  await vi.advanceTimersByTimeAsync(501); await flushPromises()
  expect(calls.filter(path => path === '/auth/me/prefs:GET')).toHaveLength(reads)
  expect(app.state.layout).toEqual({ order: ['pps', 'ip', 'bps', 'rules'], split: 1.4 })
  expect(calls.filter(path => path === '/auth/me/prefs:PUT')).toHaveLength(writes)
})
it('R2-S1 real login keeps only allowed browser keys and never stores the password', async () => {
  const password = 'example-password-storage'
  localStorage.setItem('xd.lang', 'zh-CN'); localStorage.setItem('xd.theme', 'light')
  const check = () => {
    for (const storage of [localStorage, sessionStorage]) {
      for (let index = 0; index < storage.length; index++) {
        const key = storage.key(index)!
        expect(['xd.lang', 'xd.theme']).toContain(key)
        expect(key).not.toContain(password); expect(storage.getItem(key)).not.toContain(password)
      }
    }
  }
  check(); expect(await app.login('A', password)).toBe(true); check()
  expect(calls).toContain('/auth/login:POST')
})

async function mountNodes() {
  const side = { state: 'normal', reason: '', confirmed_gen: 1, confirmable: true, rejected: [] }
  const nodes: Node[] = ['edge-01', 'edge-02'].map(name => ({ name, online: true, base_url: "http://192.0.2.1", key_unreadable: false, incompatible: false,
    rules: side, whitelist: side, health_at: '', health: { rules_synced: true, whitelist_synced: true }, stats: null, rates: null }))
  app.state.nodes = nodes
  const { default: NodeTable } = await import('../src/components/NodeTable.vue')
  const { i18n } = await import('../src/i18n')
  return mount(NodeTable, { props: { nodes, actions: true }, global: { plugins: [i18n] } })
}
it.each([503, 401])('V-r11a node action %s cannot write errors after its session expires', async status => {
  const old = deferred<Response>(); const path = '/nodes/edge-01/sync'
  intercept = name => name === path ? old.promise : undefined
  const wrapper = await mountNodes(); await wrapper.get('button.el-button').trigger('click')
  expect(calls.filter(name => name === path + ':POST')).toHaveLength(1)
  wrapper.unmount()
  if (status === 503) {
    app.expire(); await flushPromises(); account = 'B'; expect(await app.login('B', 'example-password-1')).toBe(true)
  }
  old.resolve(Response.json({ code: status === 401 ? 'unauthenticated' : 'unavailable', message: '' }, { status }))
  await flushPromises()
  expect(app.state.error).toBe('')
  if (status === 503) expect(app.state.user?.name).toBe('B')
  else expect(app.state.user).toBeNull()
})
it('V-r11b sync all stops before the next node when its session expires', async () => {
  const old = deferred<Response>(); intercept = path => path === '/nodes/edge-01/sync' ? old.promise : undefined
  const wrapper = await mountNodes(); const pending = wrapper.vm.all(); await flushPromises()
  expect(calls.filter(path => path === '/nodes/edge-01/sync:POST')).toHaveLength(1)
  app.expire(); wrapper.unmount(); await flushPromises(); account = 'B'
  expect(await app.login('B', 'example-password-1')).toBe(true)
  old.resolve(new Response(null, { status: 202 })); await pending; await flushPromises()
  expect(calls.filter(path => path === '/nodes/edge-02/sync:POST')).toHaveLength(0)
  expect(app.state.user?.name).toBe('B')
})
it('V-r11c old 403 arriving after B login cannot request B identity', async () => {
  const old = deferred<Response>(); intercept = path => path.startsWith('/traffic/history') ? old.promise : undefined
  const pending = app.loadHistory(); app.expire(); await flushPromises(); account = 'B'; intercept = undefined
  expect(await app.login('B', 'example-password-1')).toBe(true)
  const identities = calls.filter(path => path === '/auth/me:GET').length
  old.resolve(Response.json({ code: 'admin_required', message: '' }, { status: 403 })); await pending
  expect(calls.filter(path => path === '/auth/me:GET')).toHaveLength(identities)
  expect(app.state.user?.name).toBe('B'); expect(streams.filter(stream => !stream.closed)).toHaveLength(1)
})
it('V-r11d old logout completion cannot expire B', async () => {
  const old = deferred<Response>(); intercept = path => path === '/auth/logout' ? old.promise : undefined
  const pending = app.logout(); app.expire(); await flushPromises(); account = 'B'; intercept = undefined
  expect(await app.login('B', 'example-password-1')).toBe(true)
  old.resolve(new Response(null, { status: 204 })); await pending
  expect(app.state.user?.name).toBe('B'); expect(streams.filter(stream => !stream.closed)).toHaveLength(1)
})
it('V-r11e old settings guard error cannot redirect B to login', async () => {
  const old = deferred<Response>(); intercept = path => path === '/auth/me' ? old.promise : undefined
  const pending = app.guard('/settings', '/settings'); app.expire(); await flushPromises(); account = 'B'; intercept = undefined
  expect(await app.login('B', 'example-password-1')).toBe(true)
  old.resolve(Response.json({ code: 'unauthenticated', message: '' }, { status: 401 }))
  expect(await pending).toBe(false); expect(app.state.user?.name).toBe('B')
})

it('V-r12b current node failure reports the error and preserves its session', async () => {
  const user = app.state.user; const path = '/nodes/edge-01/sync'
  intercept = name => name === path ? Promise.resolve(Response.json({ code: 'unavailable', message: '' }, { status: 503 })) : undefined
  const wrapper = await mountNodes(); expect(app.state.error).toBe('')
  await wrapper.get('button.el-button').trigger('click'); await flushPromises()
  expect(calls.filter(name => name === path + ':POST')).toHaveLength(1)
  expect(app.state.error).toBe('operationFailed'); expect(app.state.user).toBe(user)
  expect(app.state.user?.name).toBe('A'); expect(streams.filter(stream => !stream.closed)).toHaveLength(1)
  wrapper.unmount()
})
it('V-r12a current sync all completes each node in order and preserves its session', async () => {
  const first = deferred<Response>(); const user = app.state.user
  intercept = path => path === '/nodes/edge-01/sync' ? first.promise : path === '/nodes/edge-02/sync'
    ? Promise.resolve(Response.json({ status: 'accepted' }, { status: 202 })) : undefined
  const wrapper = await mountNodes(); const pending = wrapper.vm.all(); await flushPromises()
  const posts = () => calls.filter(path => path.startsWith('/nodes/') && path.endsWith(':POST'))
  expect(posts()).toEqual(['/nodes/edge-01/sync:POST'])
  first.resolve(Response.json({ status: 'accepted' }, { status: 202 })); await pending; await flushPromises()
  expect(posts()).toEqual(['/nodes/edge-01/sync:POST', '/nodes/edge-02/sync:POST'])
  expect(wrapper.findAll('[role="status"]')).toHaveLength(2)
  expect(app.state.user).toBe(user); expect(app.state.user?.name).toBe('A')
  expect(streams.filter(stream => !stream.closed)).toHaveLength(1); expect(app.state.error).toBe('')
  wrapper.unmount()
})
