import {
  describe, it, expect, vi, afterEach
} from 'vitest'
import {
  resolveLanguage, loginLanguage, resolveTheme, readLayout, clampSplit, mergePreferences, encodePreferences, createPreferencesWriter
} from '../src/preferences'
import {
  bits, metric, integerAxis, gapPoints, level, syncState, offlineNodes, heartbeat
} from '../src/metrics'
import {
  createClient, ApiError
} from '../src/api/client'
import {
  subscribe, trailingThrottle, type Stream
} from '../src/api/events'
import type {
  Node
} from '../src/api/types'
const side = () => ({
  state: 'normal', reason: '', confirmed_gen: 7, confirmable: true, rejected: []
})
const node = (): Node => ({
  name: 'edge', online: true, base_url: "http://192.0.2.1", key_unreadable: false, incompatible: false, rules: side(), whitelist: side(), health_at: '', health: {
    rules_synced: true, whitelist_synced: true
  }, rates: null, stats: null
})
afterEach(() => {
  vi.useRealTimers();
  localStorage.clear()
})
describe('preferences', () => {
  it('V4 language priority and unsupported login language', () => {
    for (const [browser, result] of [['zh-TW', 'zh-CN'], ['ja', 'ja-JP'], ['en-GB', 'en-US']]) expect(resolveLanguage(null, [
      browser!])).toBe(result)
    expect(resolveLanguage('ja-JP', ['en-US'], 'zh-CN')).toBe('ja-JP')
    expect(resolveLanguage(null, ['de-DE', 'fr'], 'ja-JP')).toBe('ja-JP')
    expect(resolveLanguage(null, ['de-DE', 'fr'], 'zh-CN')).toBe('zh-CN')
    expect(resolveLanguage(null, ['en-US'], 'ja-JP')).toBe('en-US')
    expect(localStorage.getItem('xd.lang')).toBeNull()
    expect(loginLanguage(['de-DE', 'fr'])).toBe('en-US')
    localStorage.setItem('xd.lang', 'ja-JP');
    expect(loginLanguage(['en-US'])).toBe('ja-JP')

  })
  it('theme priority and invalid values', () => {
    expect(resolveTheme('dark', 'light')).toBe('dark');
    expect(resolveTheme(null, 'light')).toBe('light');
    expect(resolveTheme('bad', 'bad')).toBe('auto')
  })
  it('V8 read modify write preserves unknown keys at both levels', async () => {
    const base = {
      future: {
        keep: 4
      }, overview: {
        future: 'keep', split: 2
      }, lang: 'ja-JP'
    }
    const put = vi.fn().mockResolvedValue(undefined), read = vi.fn().mockResolvedValue(base)
    await createPreferencesWriter(read, put)({
      overview: {
        split: 1.8
      }
    })
    expect(read).toHaveBeenCalledOnce()
    expect(JSON.parse(put.mock.calls[0]![0])).toEqual({
      ...base, v: 1, overview: {
        future: 'keep', split: 1.8
      }
    })
    expect(mergePreferences(base, {
      theme: 'dark'
    }).future).toEqual({
      keep: 4
    })

  })
  it('V14 UTF-8 rejects multibyte preferences above 8192 bytes', async () => {
    const prefs = {
      future: '中'.repeat(3000)
    }
    expect(JSON.stringify(prefs).length).toBeLessThanOrEqual(8192)
    expect(new TextEncoder().encode(JSON.stringify(prefs)).byteLength).toBeGreaterThan(8192)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {
    }), put = vi.fn()
    expect(encodePreferences(prefs)).toBeNull()
    await createPreferencesWriter(async () => prefs, put)({
      theme: 'dark'
    })
    expect(put).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled()
    expect(encodePreferences({
      future: 'a'.repeat(8179)
    })).not.toBeNull()
    expect(encodePreferences({
      future: 'a'.repeat(8192)
    })).toBeNull()

  })
  it('layout defaults, invalid order, read clamping, pointer and keyboard share interval', () => {
    expect(readLayout({
    })).toEqual({
      order: ['pps', 'ip', 'bps', 'rules'], split: 1.4
    })
    expect(readLayout({
      overview: {
        order: ['pps', 'pps', 'ip', 'rules'], split: 5
      }
    })).toEqual({
      order: ['pps', 'ip', 'bps', 'rules'], split: 3.5
    })
    expect(clampSplit(-1)).toBe(.5);
    expect(clampSplit(10)).toBe(3.5);
    expect(clampSplit(NaN)).toBe(1.4)
    expect(clampSplit(clampSplit(.5) - .1)).toBe(.5);
    expect(clampSplit(clampSplit(3.5) + .1)).toBe(3.5)

  })
})
describe('metrics', () => {
  it('V1 bytes to bits and decimal rate units', () => {
    expect(bits(125000)).toBe(1000000);
    expect(metric(bits(125000), 'bps')).toBe('1M bps');
    expect(metric(1000, 'pps')).toBe('1k pps');
    expect(metric(null)).toBe('—')
  })
  it('V3 missing buckets insert null-capable gaps anchored at first bucket', () => {
    const point = (t: number) => ({
      t, dropped_pps: 1, passed_pps: 2, dropped_bytes_ps: 3, passed_bytes_ps: 4
    })
    const input = {
      step_s: 5, points: [point(101), point(116)]
    }
    expect(input.points[1]!.t - input.points[0]!.t).toBeGreaterThan(input.step_s)
    expect(gapPoints(input)).toEqual([point(101), {
      t: 106, gap: true
    }, {
      t: 111, gap: true
    }, point(116)])

  })
  it('V9 integer ticks for maximum that would yield a 1.5 interval', () => {
    expect(6 / 4).toBe(1.5)
    for (const max of [0, 6, 15, 1500000, 6000000]) {
      const axis = integerAxis(max);
      expect(Number.isInteger(axis.interval)).toBe(true);
      expect(axis.max * axis.scale).toBeGreaterThanOrEqual(max)
    }

  })
  it('V5 capacity 70/90 thresholds and exhausted', () => {
    expect(level({
      ratio: .699, exhausted: false
    })).toBe('ok');
    expect(level({
      ratio: .75, exhausted: false
    })).toBe('warn');
    expect(level({
      ratio: .9, exhausted: false
    })).toBe('crit');
    expect(level({
      ratio: null, exhausted: true
    })).toBe('crit')
  })
  it('offline badge and empty heartbeat', () => {
    expect(offlineNodes([node(), {
      ...node(), online: false
    }])).toHaveLength(1);
    expect(heartbeat('', Date.now())).toBeNull();
    expect(heartbeat('0001-01-01T00:00:00Z', Date.now())).toBeNull();
    expect(heartbeat('2026-10-15T00:00:00Z', Date.parse('2026-10-15T00:00:07Z'))).toBe(7)
  })
  it.each([
    ['stopped', (n: Node) => {
      n.rules.state = '';
      n.whitelist.state = '';
      n.online = false
    }],
    ['offline', (n: Node) => {
      n.online = false
    }], ['incompatible', (n: Node) => {
      n.incompatible = true
    }],
    ['overloaded', (n: Node) => {
      n.rules.state = 'overloaded'
    }], ['failed', (n: Node) => {
      n.whitelist.state = 'failed'
    }],
    ['syncing', (n: Node) => {
      n.rules.state = 'pending'
    }], ['synced', (_n: Node) => {
    }],
  ])('V16 sync mapping %s', (state, change) => {
    const n = node();
    change(n);
    expect(syncState(n)).toBe(state)
  })
  it('V18 normal with nonempty rejected is failed', () => {
    const n = node();
    n.rules.rejected = [{
    }];
    expect(n.rules.state).toBe('normal');
    expect(n.health.rules_synced && n.health.whitelist_synced).toBe(true);
    expect(syncState(n)).toBe('failed')
  })
  it('V21 normal without confirmable is syncing', () => {
    const n = node();
    n.whitelist.confirmable = false;
    expect(n.rules.state).toBe('normal');
    expect(n.rules.rejected).toHaveLength(0);
    expect(syncState(n)).toBe('syncing')
  })
  it('sync priorities, false health, and unmatched states', () => {
    const n = node();
    n.online = false;
    n.incompatible = true;
    n.rules.state = 'overloaded';
    expect(syncState(n)).toBe('offline');
    n.online = true;
    expect(syncState(n)).toBe('incompatible');
    n.incompatible = false;
    n.whitelist.state = 'failed';
    expect(syncState(n)).toBe('overloaded');
    n.rules.state = 'normal';
    expect(syncState(n)).toBe('failed');
    n.whitelist.state = 'normal';
    n.health.rules_synced = false;
    expect(syncState(n)).toBe('syncing');
    n.health.rules_synced = true;
    n.rules.state = 'unknown';
    expect(syncState(n)).toBe('syncing')
  })
})
describe('client', () => {
  it('V6 expired session logs out, same-origin without Authorization', async () => {
    const expired = vi.fn(), transport = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: 'unauthenticated', message: 'no session'
    }), {
      status: 401
    }))
    await expect(createClient({
      expired, demoted: vi.fn()
    }, transport)('/nodes')).rejects.toBeInstanceOf(ApiError)
    expect(expired).toHaveBeenCalledOnce();
    expect(transport.mock.calls[0]![1].credentials).toBe('same-origin');
    expect(transport.mock.calls[0]![1].headers).not.toHaveProperty('Authorization')

  })
  it('V17 invalid credentials keeps an already authenticated state and route', async () => {
    const live = {
      user: 'admin', route: '/overview'
    }, expired = vi.fn(() => {
      live.user = '';
      live.route = '/login'
    })
    const transport = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: 'invalid_credentials', message: 'failed'
    }), {
      status: 401
    }))
    await expect(createClient({
      expired, demoted: vi.fn()
    }, transport)('/auth/me/password', {
      method: 'PUT', body: '{}'
    })).rejects.toBeInstanceOf(ApiError)
    expect(expired).not.toHaveBeenCalled();
    expect(live).toEqual({
      user: 'admin', route: '/overview'
    })

  })
  it('admin_required refreshes role', async () => {
    const demoted = vi.fn().mockResolvedValue(undefined);
    const transport = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: 'admin_required', message: 'denied'
    }), {
      status: 403
    }));
    await expect(createClient({
      expired: vi.fn(), demoted
    }, transport)('/settings')).rejects.toBeInstanceOf(ApiError);
    expect(demoted).toHaveBeenCalledOnce()
  })
})
describe('events', () => {
  const setup = () => {
    const listeners: Record<string, (e: MessageEvent) => void> = {
    };
    const stream: Stream = {
      readyState: 2, onerror: null, addEventListener: (k, f) => {
        listeners[k] = f
      }, close: vi.fn()
    };
    return {
      listeners, stream
    }
  }
  it('V7 CLOSED probes auth before reconnect and stops after 401', async () => {
    vi.useFakeTimers();
    const {
      stream
    } = setup(), me = vi.fn().mockResolvedValue(undefined), create = vi.fn(() => stream)
    const stop = subscribe({
      rules: vi.fn(), nodes: vi.fn(), traffic: vi.fn(), me
    }, create)
    await stream.onerror!();
    expect(me).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(2999);
    expect(create).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(create).toHaveBeenCalledTimes(2);
    stop()
    let cancel = () => {
    };
    const unauth = vi.fn(async () => {
      cancel();
      throw new ApiError(401, {
        code: 'unauthenticated', message: ''
      })
    })
    cancel = subscribe({
      rules: vi.fn(), nodes: vi.fn(), traffic: vi.fn(), me: unauth
    }, create)
    await stream.onerror!();
    await vi.advanceTimersByTimeAsync(3000);
    expect(create).toHaveBeenCalledTimes(3);
    expect(unauth).toHaveBeenCalledOnce()

  })
  it('three classes replace snapshots and CONNECTING does not create another stream', async () => {
    const {
      stream, listeners
    } = setup(), current: Record<string, unknown> = {
    }, me = vi.fn()
    const stop = subscribe({
      rules: v => {
        current.rules = v
      }, nodes: v => {
        current.nodes = v
      }, traffic: v => {
        current.traffic = v
      }, me
    }, () => stream)
    for (const name of ['rules', 'nodes', 'traffic']) {
      listeners[name]!(new MessageEvent('message', {
        data: '{"old":1}'
      }));
      listeners[name]!(new MessageEvent('message', {
        data: '{"new":2}'
      }));
      expect(current[name]).toEqual({
        new: 2
      })
    }
    stream.readyState = 0;
    await stream.onerror!();
    expect(me).not.toHaveBeenCalled();
    stop()

  })
  it('throttle guarantees exactly one trailing fetch per busy window', async () => {
    vi.useFakeTimers();
    const action = vi.fn(), trigger = trailingThrottle(action);
    trigger();
    await vi.advanceTimersByTimeAsync(1000);
    trigger();
    trigger();
    trigger();
    expect(action).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(4000);
    expect(action).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(5000);
    expect(action).toHaveBeenCalledTimes(2);
    trigger.cancel()
  })
})

it('V-r9b cancelled throttle can schedule a new trailing request', async () => {
  vi.useFakeTimers()
  const action = vi.fn(), trigger = trailingThrottle(action)
  trigger(); await vi.advanceTimersByTimeAsync(1000); trigger(); trigger.cancel(); trigger()
  await vi.advanceTimersByTimeAsync(9000)
  expect(action).toHaveBeenCalledTimes(2)
  trigger.cancel()
})
