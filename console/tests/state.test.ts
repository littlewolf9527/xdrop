import {
  it, expect, vi, beforeEach, afterEach
} from 'vitest'
import {
  flushPromises
} from '@vue/test-utils'
import {
  createRouter, createMemoryHistory
} from 'vue-router'
let listeners: Record<string, (e: MessageEvent) => void>, calls: string[], role: string, pref: Record<string, unknown>
let app: typeof import('../src/state')
beforeEach(async () => {
  vi.resetModules();
  vi.useFakeTimers();
  localStorage.clear();
  listeners = {
  };
  calls = [];
  role = 'admin';
  pref = {
  }
  vi.stubGlobal('matchMedia', () => ({
    matches: false, addEventListener: vi.fn()
  }))
  vi.stubGlobal('EventSource', class {
    readyState = 1;
    onerror = null;
    addEventListener(k: string, fn: (e: MessageEvent) => void) {
      listeners[k] = fn
    } close() {
    }
  })
  vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
    const path = input.replace('/api/v1', '');
    calls.push(path)
    if (path === '/auth/me') return Response.json({
      name: 'admin', role
    })
    if (path === '/auth/me/prefs') {
      if (init?.method === 'PUT') {
        pref = JSON.parse(String(init.body));
        return new Response(null, {
          status: 204
        })
      };
      return Response.json(pref)
    }
    if (path === '/settings') return Response.json({
      default_language: 'en-US'
    })
    if (path === '/capacity') return Response.json({
      tightest: {
        name: 'cond', ratio: 0, exhausted: false
      }, dimensions: []
    })
    if (path.startsWith('/traffic/history')) return Response.json({
      step_s: 5, points: []
    })
    return Response.json({
    })

  }))
  app = await import('../src/state')
  const router = createRouter({
    history: createMemoryHistory(), routes: ['/overview', '/settings', '/login'].map(path => ({
      path, component: {
        template: '<div />'
      }
    }))
  })
  await router.push('/overview');
  await router.isReady();
  await app.initialize(router);
  await flushPromises()
})
afterEach(() => {
  app.expire();
  vi.useRealTimers();
  vi.unstubAllGlobals()
})
it('V19 zero-node rules events cause capacity reload with exactly one trailing fetch', async () => {
  expect(app.state.nodes).toEqual([])
  const initial = calls.filter(p => p === '/capacity').length
  for (const seq of [1, 2, 3]) listeners.rules!(new MessageEvent('message', {
    data: JSON.stringify({
      seq
    })
  }))
  await flushPromises();
  expect(calls.filter(p => p === '/capacity')).toHaveLength(initial)
  await vi.advanceTimersByTimeAsync(5000);
  await flushPromises();
  expect(calls.filter(p => p === '/capacity')).toHaveLength(initial + 1)
  await vi.advanceTimersByTimeAsync(5000);
  expect(calls.filter(p => p === '/capacity')).toHaveLength(initial + 1)
})
it('V15 operator direct settings route rejected', async () => {
  role = 'operator';
  expect(await app.guard('/settings', '/settings')).toBe('/overview');
  expect(app.canSettings.value).toBe(false)
})
it('V20 live downgrade re-fetches identity without injected 403', async () => {
  expect(app.state.user?.role).toBe('admin');
  const count = calls.filter(p => p === '/auth/me').length;
  role = 'operator';
  expect(await app.guard('/settings', '/settings')).toBe('/overview');
  expect(calls.filter(p => p === '/auth/me')).toHaveLength(count + 1);
  expect(app.canSettings.value).toBe(false)
})
it('403 refreshes role, removes settings and redirects overview', async () => {
  role = 'operator';
  const original = globalThis.fetch
  vi.stubGlobal('fetch', async (input: string, init?: RequestInit) => input.endsWith('/denied') ? Response.json({
    code: 'admin_required', message: 'denied'
  }, {
    status: 403
  }) : original(input, init))
  await expect(app.request('/denied')).rejects.toHaveProperty('status', 403);
  expect(app.canSettings.value).toBe(false);
  expect(await app.guard('/settings', '/settings')).toBe('/overview')
})
it('snapshots replace nodes and traffic; history respects event step', async () => {
  const emit = (type: string, value: unknown) => listeners[type]!(new MessageEvent('message', {
    data: JSON.stringify(value)
  }))
  emit('nodes', {
    nodes: [{
      name: 'first'
    }]
  });
  emit('nodes', {
    nodes: [{
      name: 'second'
    }]
  });
  expect(app.state.nodes.map(n => n.name)).toEqual(['second'])
  const traffic = {
    overview: {
      nodes_online: 0, nodes_total: 0, dropped_pps: 1, passed_pps: 2, dropped_bytes_ps: 3, passed_bytes_ps: 4
    }, top: {
      targets: [], rules: [], updated_at: null, targets_total: 8
    }
  }
  emit('traffic', traffic);
  await flushPromises();
  const before = calls.filter(p => p.startsWith('/traffic/history')).length
  emit('traffic', {
    ...traffic, top: {
      ...traffic.top, targets_total: 9
    }
  });
  await flushPromises();
  expect(app.state.top.targets_total).toBe(9);
  expect(calls.filter(p => p.startsWith('/traffic/history'))).toHaveLength(before)
  await vi.advanceTimersByTimeAsync(5000);
  emit('traffic', traffic);
  await flushPromises();
  expect(calls.filter(p => p.startsWith('/traffic/history'))).toHaveLength(before + 1)
})
it('layout pointer keyboard persistence, swap and restore defaults debounce 500ms', async () => {
  app.setSplit(99);
  expect(app.state.layout.split).toBe(3.5);
  app.setSplit(-9);
  expect(app.state.layout.split).toBe(.5)
  app.setSplit(app.state.layout.split + .1);
  expect(app.state.layout.split).toBe(.6)
  app.swapPanels(0, 1);
  expect(app.state.layout.order).toEqual(['ip', 'pps', 'bps', 'rules'])
  await vi.advanceTimersByTimeAsync(499);
  expect(calls.filter(p => p === '/auth/me/prefs')).toHaveLength(1)
  await vi.advanceTimersByTimeAsync(1);
  await flushPromises();
  expect(pref.overview).toEqual({
    order: ['ip', 'pps', 'bps', 'rules'], split: .6
  })
  app.restoreLayout();
  await vi.advanceTimersByTimeAsync(500);
  await flushPromises();
  expect(pref.overview).toEqual({
    order: ['pps', 'ip', 'bps', 'rules'], split: 1.4
  })
})
