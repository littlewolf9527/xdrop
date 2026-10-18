import { it, expect, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { nextTick } from 'vue'
import { ElDropdown, ElDropdownItem } from 'element-plus'
import { createRouter, createMemoryHistory, RouterView } from 'vue-router'
it('R3-2 real expire blocks watches, pending throttles and search until login unmount', async () => {
  vi.useFakeTimers(); vi.resetModules(); localStorage.clear()
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener() {} }))
  vi.stubGlobal('EventSource', class { addEventListener() {} close() {} })
  const paths: string[] = [], page = { items: [], next_after: null, counts: { all: 0, drop: 0, rate_limit: 0, disabled: 0 } }
  vi.stubGlobal('fetch', vi.fn(async (input: string) => {
    paths.push(input)
    const data = input.endsWith('/auth/me') ? { name: 'admin', role: 'admin' } : input.endsWith('/settings') ? { default_language: 'zh-CN' } :
      input.includes('/rules?') ? page : input.includes('/traffic/top') ? { rules: [], targets: [], updated_at: null, incomplete: false } : {}
    return Response.json(data)
  }))
  const app = await import('../src/state'), { i18n } = await import('../src/i18n'), { default: Rules } = await import('../src/views/Rules.vue')
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/rules', component: Rules }, { path: '/login', component: { template: '<p>login</p>' } }] })
  let allowLogin!: () => void
  const navigation = new Promise<void>(resolve => { allowLogin = resolve })
  router.beforeEach(to => to.path === '/login' ? navigation : app.guard(to.path, to.fullPath))
  await app.initialize(router); await router.push('/rules'); await router.isReady()
  const w = mount(RouterView, { global: { plugins: [router, i18n] } })
  try {
    await flushPromises(); expect(app.state.user?.name).toBe('admin')
    expect(paths.some(p => p.includes('/rules?'))).toBe(true); expect(paths.some(p => p.includes('/traffic/top'))).toBe(true)
    app.state.rules = {}; app.state.top = { ...app.state.top }; await nextTick(); await flushPromises()
    await vi.advanceTimersByTimeAsync(100)
    app.state.rules = {}; app.state.top = { ...app.state.top }; await nextTick()
    await w.get('.search').setValue('192.0.2.1')
    const before = paths.length; app.expire(); expect(app.state.user).toBeNull()
    await nextTick(); await flushPromises(); expect(router.currentRoute.value.path).toBe('/rules')
    await vi.advanceTimersByTimeAsync(5000); await flushPromises()
    expect(paths.slice(before).filter(p => p.includes('/rules?') || p.includes('/traffic/top'))).toEqual([])
    allowLogin(); await flushPromises(); expect(router.currentRoute.value.path).toBe('/login')
    expect(paths.slice(before).filter(p => p.includes('/rules?') || p.includes('/traffic/top'))).toEqual([])
  } finally { allowLogin(); w.unmount(); app.expire(); vi.useRealTimers(); vi.unstubAllGlobals() }
})
it.each(['export', 'toggle', 'remove', 'submit', 'more'] as const)('R4-2 real expire blocks manual %s before route unmount', async action => {
  vi.useFakeTimers(); vi.resetModules(); localStorage.clear()
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener() {} }))
  vi.stubGlobal('EventSource', class { addEventListener() {} close() {} })
  const paths: string[] = [], row = { id: 'rule_' + '3'.repeat(32), logical_id: 3, dst_ip: '192.0.2.3', src_ip: '', src_cidr: '', dst_cidr: '',
    src_port: 0, dst_port: 443, protocol: 'tcp', ttl: null, dscp: null, pkt_len: null, icmp_type: null, icmp_code: null, fragment: null,
    tcp_flags: '', match_anomaly: 0, action: 'drop', rate_limit: 0, enabled: true, group_key: 'three', comment: '', expires_at: null, created_by: 'user:admin' }
  const page = { items: [row], next_after: 3, counts: { all: 4, drop: 4, rate_limit: 0, disabled: 0 } }
  vi.stubGlobal('fetch', vi.fn(async (input: string) => {
    paths.push(input)
    const data = input.endsWith('/auth/me') ? { name: 'admin', role: 'admin' } : input.endsWith('/settings') ? { default_language: 'zh-CN' } :
      input.includes('/rules?') ? { ...page, next_after: input.includes('after=') ? null : page.next_after } : input.includes('/traffic/top') ? { rules: [], targets: [], updated_at: null, incomplete: false } : {}
    return Response.json(data)
  }))
  const app = await import('../src/state'), { i18n } = await import('../src/i18n'), { default: Rules } = await import('../src/views/Rules.vue')
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/rules', component: Rules }, { path: '/login', component: { template: '<p>login</p>' } }] })
  let release!: () => void
  const pause = new Promise<void>(resolve => { release = resolve })
  router.beforeEach(to => to.path === '/login' ? pause : app.guard(to.path, to.fullPath))
  await app.initialize(router); await router.push('/rules'); await router.isReady()
  const w = mount(RouterView, { global: { plugins: [router, i18n] }, attachTo: document.body })
  const createURL = vi.fn(() => 'blob:fixture'), blob = vi.spyOn(globalThis, 'Blob')
  vi.stubGlobal('URL', class extends URL { static createObjectURL = createURL; static revokeObjectURL = vi.fn() })
  try {
    await flushPromises(); expect(app.state.user?.name).toBe('admin'); expect(w.findAll('[role=switch]')).toHaveLength(1)
    if (action === 'remove') {
      await w.get('.row-menu-trigger').trigger('click'); await vi.advanceTimersByTimeAsync(0); await flushPromises()
      await w.findComponent(ElDropdown).findAllComponents(ElDropdownItem)[1]!.get('[role=menuitem]').trigger('click')
    }
    if (action === 'submit') { await w.get('.page-head .primary').trigger('click'); await w.get('#dst_address').setValue('198.51.100.8') }
    const selectors = { export: '.page-head .btn:not(.primary)', toggle: '[role=switch]', remove: '.confirm .danger', submit: '#rule-form', more: '.load-more' }
    const button = w.get(selectors[action]); expect(button.attributes('disabled')).toBeUndefined()
    app.expire(); await nextTick(); await flushPromises()
    expect(app.state.user).toBeNull(); expect(router.currentRoute.value.path).toBe('/rules')
    const before = paths.length
    await button.trigger(action === 'submit' ? 'submit' : 'click'); await flushPromises()
    expect(paths.slice(before)).toEqual([]); expect(createURL).not.toHaveBeenCalled(); expect(blob).not.toHaveBeenCalled()
    release(); await flushPromises(); expect(router.currentRoute.value.path).toBe('/login')
    expect(paths.slice(before)).toEqual([])
    console.log('R4-2 expired manual entry', JSON.stringify({ action, requests: paths.slice(before), blobs: blob.mock.calls.length, urls: createURL.mock.calls.length }))
  } finally { release(); w.unmount(); app.expire(); blob.mockRestore(); vi.useRealTimers(); vi.unstubAllGlobals() }
})
