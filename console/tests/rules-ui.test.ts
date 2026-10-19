import { conditionKeys, protocolOptions, conditionRanges } from '../src/rules'
import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { ElDropdown, ElDropdownItem, ElTooltip } from 'element-plus'
import NodeTable from '../src/components/NodeTable.vue'
import { i18n, messages } from '../src/i18n'
import type { RuleDTO, RulePage } from '../src/api/types'
import { ApiError } from '../src/api/client'
const hooks = vi.hoisted(() => ({ request: vi.fn(), current: true }))
vi.mock('../src/state', async () => ({ request: hooks.request, captureSession: () => ({ isCurrent: () => hooks.current }),
  state: (await import('vue')).reactive({ user: { name: 'admin', role: 'admin' }, rules: {}, top: {}, now: Date.parse('2026-10-16T00:00:00Z') }) }))
import { state } from '../src/state'
import Rules from '../src/views/Rules.vue'
import RuleDrawer from '../src/components/RuleDrawer.vue'
const r: RuleDTO = { id: 'rule_' + '1'.repeat(32), logical_id: 1, src_ip: '', dst_ip: '192.0.2.1', src_cidr: '', dst_cidr: '', protocol: 'tcp', src_port: 0, dst_port: 443, ttl: '64', dscp: null, icmp_type: null, icmp_code: null, fragment: null, pkt_len: null, tcp_flags: '', match_anomaly: 0, action: 'rate_limit', rate_limit: 100, kind: 'exact', group_key: 'same', cond_key: '', enabled: true, comment: 'memo', created_at: '', updated_at: '', expires_at: null, created_by: 'user:admin', updated_by: 'user:admin' }
const result = (items = [{ ...r }], next_after: number | null = null): RulePage => ({ items, next_after, counts: { all: items.length, drop: 0, rate_limit: items.length, disabled: 0 } })
const deferred = <T>() => { let resolve!: (v: T) => void, reject!: (e: unknown) => void; const promise = new Promise<T>((a,b) => { resolve=a; reject=b }); return {promise, resolve, reject} }
const wrappers: VueWrapper[] = []
function drawer(rule?: RuleDTO) { const w = mount(RuleDrawer, { props: { rule }, global: { plugins: [i18n] }, attachTo: document.body }); wrappers.push(w); return w }
async function rules() { const w = mount(Rules, { global: { plugins: [i18n] }, attachTo: document.body }); wrappers.push(w); await flushPromises(); return w }
async function menu(w: VueWrapper, item: number, row = 0) {
  await w.findAll('.row-menu-trigger')[row]!.trigger('click'); await flushPromises()
  if (vi.isFakeTimers()) await vi.advanceTimersByTimeAsync(0)
  const dropdown = w.findAllComponents(ElDropdown)[row]!
  await dropdown.findAllComponents(ElDropdownItem)[item]!.get('[role=menuitem]').trigger('click'); await nextTick()
}
beforeEach(() => {
  hooks.current = true; hooks.request.mockReset(); i18n.global.locale.value = 'zh-CN'
  hooks.request.mockImplementation(async (path: string) => path.startsWith('/traffic') ? { rules: [], targets: [], updated_at: null, incomplete: false, targets_total: 0 } : result())
})
afterEach(() => { wrappers.splice(0).forEach(w => w.unmount()); vi.useRealTimers(); vi.unstubAllGlobals() })
it('C5-V19 actual group marker is loaded count without denominator', async () => {
  hooks.request.mockImplementation(async (path: string) => path.startsWith('/traffic') ? { rules: [], updated_at: null } : result([{ ...r }, { ...r, id: 'rule_'+'2'.repeat(32), logical_id: 2 }]))
  const w = await rules(); expect(w.findAll('tr.in-grp')).toHaveLength(2); expect(w.get('.grp').text()).toBe('同组 2'); expect(w.text()).not.toContain('/ 4')
  expect(w.find('.load-more').exists()).toBe(false)
})
it('C5-V6 switch remains unchanged while busy and after 409; success uses returned enabled', async () => {
  const w = await rules(), reply = deferred<unknown>()
  hooks.request.mockReturnValueOnce(reply.promise)
  await w.get('[role=switch]').trigger('click'); expect(w.get('[role=switch]').attributes('aria-checked')).toBe('true')
  expect(w.get('[role=switch]').attributes('disabled')).toBeDefined()
  reply.reject(new ApiError(409, { code: 'condition_capacity', message: 'private backend text' })); await flushPromises()
  expect(w.get('[role=switch]').attributes('aria-checked')).toBe('true'); expect(w.get('tbody .rule-error').text()).toContain('同组条件位已满')
  hooks.request.mockResolvedValueOnce({ enabled: false }).mockResolvedValueOnce(result([{ ...r, enabled: false }])); await w.get('[role=switch]').trigger('click'); await flushPromises()
  expect(w.get('[role=switch]').attributes('aria-checked')).toBe('false')
})
it('C5-V7 menu deletion only confirms; cancel and search do not delete', async () => {
  vi.useFakeTimers(); const w = await rules()
  await menu(w, 1); expect(w.find('.confirm').exists()).toBe(true)
  expect(hooks.request.mock.calls.some(c => c[1]?.method === 'DELETE')).toBe(false)
  await w.get('.confirm .btn:not(.danger)').trigger('click'); expect(w.find('.confirm').exists()).toBe(false)
  await menu(w, 1); await w.get('.search').setValue('192.0.2.2'); await vi.advanceTimersByTimeAsync(300)
  expect(w.find('.confirm').exists()).toBe(false); expect(hooks.request.mock.calls.some(c => c[1]?.method === 'DELETE')).toBe(false)
  await menu(w, 1); await w.get('.confirm .danger').trigger('click'); await flushPromises()
  expect(hooks.request.mock.calls.filter(c => c[1]?.method === 'DELETE')).toHaveLength(1)
})
it('C5 drawer focus returns on close and Esc closes', async () => {
  const button = document.createElement('button'); document.body.append(button); button.focus()
  const w = drawer(); await nextTick(); expect(document.activeElement).toBe(w.get('#src_address').element)
  document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); expect(w.emitted('close')).toHaveLength(1)
  w.unmount(); wrappers.splice(wrappers.indexOf(w), 1); expect(document.activeElement).toBe(button); button.remove()
})
it.each([
  ['dst_port','invalid_rule','dst_port'], ['ip','invalid_rule','target'], ['tuple','invalid_rule','target'],
  ['conditions','invalid_rule','conditions'], ['', 'invalid_expires_in','expires_in'], ['', 'mapped_ipv6','target'],
  ['', 'address_family_mismatch','target'], ['protocol','invalid_rule','protocol'],
])('C5-V8 validate error stops POST and locates %s %s', async (field, code, expected) => {
  hooks.request.mockResolvedValue({ results: [{ index: 0, error: { code, message: 'backend secret', ...(field ? { field } : {}) } }] })
  const w = drawer(); await w.get('#dst_address').setValue('192.0.2.7'); await w.get('form').trigger('submit'); await flushPromises()
  expect(hooks.request).toHaveBeenCalledTimes(1); expect(hooks.request.mock.calls[0]?.[0]).toBe('/rules/batch?validate=1')
  if (['target','conditions'].includes(expected)) expect(w.findAll('fieldset').find(f => f.find('.rule-error').exists())?.get('legend').text()).toContain(expected === 'target' ? '目标' : '条件')
  else expect(w.find(`[data-field="${expected}"] .rule-error`).exists()).toBe(true)
  expect(w.text()).not.toContain('backend secret')
})
it('C5-V26 top-level items.dst_port decoding error locates destination port', async () => {
  hooks.request.mockRejectedValue(new ApiError(400, { code: 'bad_request', message: 'decode', field: 'items.dst_port' }))
  const w = drawer(); await w.get('#dst_port').setValue('abc'); await w.get('form').trigger('submit'); await flushPromises()
  expect(w.find('[data-field="dst_port"] .rule-error').exists()).toBe(true); expect(w.find('.drawer-error').exists()).toBe(false)
  expect(hooks.request).toHaveBeenCalledTimes(1)
})
it('C5-V23 validation and POST serialize exactly the same body including comment', async () => {
  hooks.request.mockResolvedValueOnce({ results: [{ index: 0, existing: false }] }).mockResolvedValueOnce({ id: r.id })
  const w = drawer(); await w.get('#dst_address').setValue('192.0.2.7'); await w.get('#comment').setValue('kept comment')
  await w.get('form').trigger('submit'); await flushPromises()
  expect(hooks.request.mock.calls.map(c => c[0])).toEqual(['/rules/batch?validate=1','/rules'])
  const pre = JSON.parse(hooks.request.mock.calls[0]?.[1].body).items[0], post = hooks.request.mock.calls[1]?.[1].body
  expect(pre.comment).toBe('kept comment'); expect(JSON.stringify(pre)).toBe(post); expect(w.emitted('saved')).toHaveLength(1)
})
it('C5 existing validation requires second click and editing it requires fresh validation', async () => {
  hooks.request.mockResolvedValue({ results: [{ index: 0, existing: true }] })
  const w = drawer(); await w.get('#comment').setValue('memo'); await w.get('form').trigger('submit'); await flushPromises()
  expect(hooks.request).toHaveBeenCalledTimes(1); expect(w.get('.rule-notice').text()).toContain('只可能延长期限'); expect(w.get('.drawer-foot button').text()).toBe('仍然提交')
  hooks.request.mockResolvedValueOnce({ id: r.id }); await w.get('form').trigger('submit'); await flushPromises()
  expect(hooks.request.mock.calls[1]?.[0]).toBe('/rules')
})
it('C5 editing existing confirmation body invalidates previous preflight', async () => {
  hooks.request.mockResolvedValue({ results: [{ index: 0, existing: true }] })
  const w = drawer(); await w.get('form').trigger('submit'); await flushPromises(); await w.get('#comment').setValue('changed')
  await w.get('form').trigger('submit'); await flushPromises(); expect(hooks.request.mock.calls.map(c => c[0])).toEqual(['/rules/batch?validate=1','/rules/batch?validate=1'])
})
it('C5 editor sends only changed fields and conflict View sets rule search', async () => {
  const w = await rules(); await menu(w, 0)
  const form = w.getComponent(RuleDrawer); expect(form.get('.drawer-foot button').attributes('disabled')).toBeDefined()
  const conflict = 'rule_'+'2'.repeat(32)
  hooks.request.mockImplementation(async (path: string, init?: RequestInit) => { if (init?.method === 'PATCH') throw new ApiError(409, { code: 'rule_conflict', message: 'conflict', rule_id: conflict } as never); return result() })
  await form.get('#comment').setValue('changed'); await form.get('form').trigger('submit'); await flushPromises()
  const patch = hooks.request.mock.calls.find(c => c[1]?.method === 'PATCH')!; expect(JSON.parse(patch[1].body)).toEqual({ comment: 'changed' })
  expect(form.find('.drawer-error').exists()).toBe(true); await form.get('.drawer-error button').trigger('click'); await flushPromises()
  expect((w.get('.search').element as HTMLInputElement).value).toBe(conflict); expect(w.findComponent(RuleDrawer).exists()).toBe(false)
})
it('C5 PATCH 404 is a top-level error and no new preflight occurs', async () => {
  hooks.request.mockRejectedValue(new ApiError(404, { code: 'not_found', message: 'hidden' }))
  const w = drawer(r); await w.get('#comment').setValue('changed'); await w.get('form').trigger('submit'); await flushPromises()
  expect(w.get('.drawer-error').text()).toContain('规则不存在'); expect(hooks.request.mock.calls[0]?.[1].method).toBe('PATCH')
})
it('C5 traffic five-second trailing request stops on unmount and discards pending response', async () => {
  vi.useFakeTimers(); const pending = deferred<unknown>(), w = await rules(), calls = () => hooks.request.mock.calls.filter(c => c[0] === '/traffic/top?n=all').length
  expect(calls()).toBe(1); state.top = { ...state.top }; await nextTick(); await vi.advanceTimersByTimeAsync(1000)
  state.top = { ...state.top }; await nextTick(); expect(calls()).toBe(1)
  hooks.request.mockImplementation((path: string) => path === '/traffic/top?n=all' ? pending.promise : Promise.resolve(result()))
  await vi.advanceTimersByTimeAsync(4000); expect(calls()).toBe(2)
  w.unmount(); wrappers.splice(wrappers.indexOf(w), 1)
  pending.resolve({ rules: [{ rule_id: r.id, dropped_pps: 100, dropped_bytes_ps: 200 }], updated_at: '2026-10-16T00:00:00Z', incomplete: false }); await flushPromises()
  state.top = { ...state.top }; await vi.advanceTimersByTimeAsync(10000); expect(calls()).toBe(2)
})
it('C5 expired export shows inline error and never downloads', async () => {
  const w = await rules(), download = vi.fn(); vi.stubGlobal('URL', class extends URL { static createObjectURL = download })
  hooks.request.mockResolvedValueOnce(result([{ ...r, expires_at: '2020-01-01T00:00:00Z' }]))
  await w.get('.page-head .btn:not(.primary)').trigger('click'); await flushPromises()
  expect(download).not.toHaveBeenCalled(); expect(w.get('p.error-text').text()).toContain('过一会儿再导出')
})
it('C5 stale drawer continuation cannot emit saved after session expires', async () => {
  const pending = deferred<unknown>(); hooks.request.mockReturnValue(pending.promise)
  const w = drawer(r); await w.get('#comment').setValue('changed'); await w.get('form').trigger('submit')
  hooks.current = false; pending.resolve(r); await flushPromises(); expect(w.emitted('saved')).toBeUndefined()
})
it('R3-1 queued push returns through the same two-second throttle', async () => {
  vi.useFakeTimers(); vi.setSystemTime(0)
  const first = deferred<RulePage>(), at: number[] = []
  hooks.request.mockImplementation((path: string) => {
    if (!path.startsWith('/rules?')) return Promise.resolve({ rules: [], updated_at: null })
    at.push(Date.now()); return at.length === 1 ? first.promise : Promise.resolve(result())
  })
  await rules(); state.rules = {}; await nextTick(); expect(at).toEqual([0])
  await vi.advanceTimersByTimeAsync(1900); first.resolve(result()); await flushPromises()
  expect(at).toEqual([0])
  await vi.advanceTimersByTimeAsync(100); state.rules = {}; await nextTick(); await flushPromises()
  expect(at.slice(1)).toEqual([2000])
  await vi.advanceTimersByTimeAsync(1999); expect(at.slice(1)).toEqual([2000])
  await vi.advanceTimersByTimeAsync(1); expect(at.slice(1)).toEqual([2000, 4000])
})
it('R3-3 PUT success invalidates a pre-write list reply and starts a fresh list', async () => {
  const w = await rules(), old = deferred<RulePage>(), fresh = deferred<RulePage>()
  let reads = 0
  hooks.request.mockImplementation((path: string, init?: RequestInit) => {
    if (init?.method === 'PUT') return Promise.resolve({ enabled: false })
    if (path.startsWith('/rules?')) return ++reads === 1 ? old.promise : fresh.promise
    return Promise.resolve({ rules: [], updated_at: null })
  })
  state.rules = {}; await nextTick(); expect(reads).toBe(1)
  await w.get('[role=switch]').trigger('click'); await flushPromises()
  expect(w.get('[role=switch]').attributes('aria-checked')).toBe('false'); expect(reads).toBe(2)
  old.resolve(result([{ ...r, enabled: true }])); await flushPromises()
  expect(w.get('[role=switch]').attributes('aria-checked')).toBe('false')
  fresh.resolve(result([{ ...r, enabled: false }])); await flushPromises()
  expect(w.get('[role=switch]').attributes('aria-checked')).toBe('false')
})
it('R3-4 switching the background editor replaces the snapshot before PATCH', async () => {
  const b = { ...r, id: 'rule_' + '2'.repeat(32), logical_id: 2, dst_ip: '198.51.100.2', comment: 'B snapshot', group_key: 'B' }
  hooks.request.mockImplementation(async (path: string) => path.startsWith('/traffic') ? { rules: [], updated_at: null } : result([{ ...r }, b]))
  const w = await rules(), editors = w.findAll('.row-menu-trigger')
  await menu(w, 0, 0); expect((w.get('#dst_address').element as HTMLInputElement).value).toBe(r.dst_ip)
  const aInput = w.get('#dst_address').element
  await menu(w, 0, 1)
  expect(w.get('#dst_address').element).not.toBe(aInput)
  expect((w.get('#dst_address').element as HTMLInputElement).value).toBe(b.dst_ip)
  expect((w.get('#comment').element as HTMLTextAreaElement).value).toBe('B snapshot')
  await w.get('#comment').setValue('B edited'); await w.get('#rule-form').trigger('submit'); await flushPromises()
  const writes = hooks.request.mock.calls.filter(c => c[1]?.method === 'PATCH')
  expect(writes).toHaveLength(1); expect(writes[0]![0]).toBe('/rules/' + b.id)
  expect(JSON.parse(writes[0]![1].body)).toEqual({ comment: 'B edited' })
})
it.each(['toggle', 'remove', 'saved'] as const)('R4-1 %s write reissues the pending query before stale completion', async action => {
  const w = await rules(), old = deferred<RulePage>(), fresh = deferred<RulePage>(), paths: string[] = []
  hooks.request.mockImplementation((path: string, init?: RequestInit) => {
    if (init?.method) return Promise.resolve(init.method === 'PUT' ? { enabled: false } : {})
    if (path.startsWith('/rules?')) { paths.push(path); return paths.length === 1 ? old.promise : fresh.promise }
    return Promise.resolve({ rules: [], updated_at: null })
  })
  await w.get('.search').setValue(' 198.51.100.9 ')
  await w.findAll('.chip')[2]!.trigger('click')
  expect(paths).toHaveLength(1)
  const pending = new URLSearchParams(paths[0]!.split('?')[1])
  expect(pending.get('q')).toBe('198.51.100.9'); expect(pending.get('state')).toBe('rate_limit')
  if (action === 'toggle') await w.get('[role=switch]').trigger('click')
  else if (action === 'remove') {
    await menu(w, 1); await w.get('.confirm .danger').trigger('click')
  } else {
    await menu(w, 0); await w.get('#comment').setValue('write complete')
    await w.get('#rule-form').trigger('submit')
  }
  await flushPromises(); expect(paths).toEqual([paths[0], paths[0]])
  if (action === 'toggle') expect(w.get('[role=switch]').attributes('aria-checked')).toBe('false')
  old.resolve(result([{ ...r, dst_ip: '203.0.113.99', enabled: true }]))
  await flushPromises(); expect(w.get('tbody').text()).not.toContain('203.0.113.99')
  if (action === 'toggle') expect(w.get('[role=switch]').attributes('aria-checked')).toBe('false')
  fresh.resolve(result(action === 'remove' ? [] : [{ ...r, enabled: action !== 'toggle', comment: 'write complete' }]))
  await flushPromises(); expect(w.findAll('tr[data-rule-id]')).toHaveLength(action === 'remove' ? 0 : 1)
  if (action === 'toggle') expect(w.get('[role=switch]').attributes('aria-checked')).toBe('false')
})
it('R4-3 drawer replacement preserves B trigger and balances keydown listeners', async () => {
  const b = { ...r, id: 'rule_' + '2'.repeat(32), dst_ip: '198.51.100.2', comment: 'B' }
  hooks.request.mockImplementation(async (path: string) => path.startsWith('/traffic') ? { rules: [], updated_at: null } : result([{ ...r }, b]))
  const w = await rules(), editors = w.findAll('.row-menu-trigger')
  const added = vi.spyOn(document, 'addEventListener'), removed = vi.spyOn(document, 'removeEventListener')
  const close = async () => { document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); await nextTick() }
  try {
    await menu(w, 0, 0); expect((w.get('#dst_address').element as HTMLInputElement).value).toBe(r.dst_ip)
    await menu(w, 0, 1); expect((w.get('#dst_address').element as HTMLInputElement).value).toBe(b.dst_ip)
    await close(); expect(document.activeElement).toBe(editors[1]!.element)
    await menu(w, 0, 0); await close(); expect(document.activeElement).toBe(editors[0]!.element)
    const adds = added.mock.calls.filter(c => c[0] === 'keydown'), removes = removed.mock.calls.filter(c => c[0] === 'keydown')
    expect(adds).toHaveLength(3); expect(removes.map(c => c[1])).toEqual(adds.map(c => c[1]))
  } finally { added.mockRestore(); removed.mockRestore() }
})
it('R5-1 twenty push signals preserve confirmation across throttle windows and delete once', async () => {
  vi.useFakeTimers(); vi.setSystemTime(0)
  const w = await rules(), reads: number[] = []
  hooks.request.mockImplementation(async (path: string) => {
    if (path.startsWith('/rules?')) reads.push(Date.now())
    return result()
  })
  state.rules = {}; await nextTick(); await flushPromises(); expect(reads).toEqual([0])
  await vi.advanceTimersByTimeAsync(1900)
  await menu(w, 1)
  for (let event = 0; event < 20; event++) {
    await vi.advanceTimersByTimeAsync(100); state.rules = {}; await nextTick(); await flushPromises()
    expect(w.findAll('.confirm')).toHaveLength(1); expect(w.get('.confirm strong').text()).toContain(r.dst_ip)
  }
  await vi.advanceTimersByTimeAsync(100); await flushPromises()
  expect(reads).toEqual([0, 2000, 4000]); expect(w.findAll('.confirm')).toHaveLength(1)
  const deletes = () => hooks.request.mock.calls.filter(c => c[1]?.method === 'DELETE')
  expect(deletes()).toHaveLength(0)
  await w.get('.confirm .danger').trigger('click'); await flushPromises()
  expect(deletes()).toHaveLength(1); expect(deletes()[0]![0]).toBe('/rules/' + r.id); expect(w.find('.confirm').exists()).toBe(false)
})
it('R5-2 disappearing rule clears confirmation even if its id reappears in a later push', async () => {
  vi.useFakeTimers(); vi.setSystemTime(0); const w = await rules()
  await menu(w, 1); expect(w.find('.confirm').exists()).toBe(true)
  hooks.request.mockResolvedValueOnce(result([])); state.rules = {}; await nextTick(); await flushPromises()
  expect(w.findAll('tr[data-rule-id]')).toHaveLength(0); expect(w.find('.confirm').exists()).toBe(false)
  await vi.advanceTimersByTimeAsync(2000); state.rules = {}; await nextTick(); await flushPromises()
  expect(w.findAll('tr[data-rule-id]')).toHaveLength(1); expect(w.find('.confirm').exists()).toBe(false)
  expect(hooks.request.mock.calls.filter(c => c[1]?.method === 'DELETE')).toHaveLength(0)
})
it.each(['search', 'more', 'filter'] as const)('R5-3 user %s closes confirmation immediately', async action => {
  vi.useFakeTimers()
  hooks.request.mockImplementation(async (path: string) => path.startsWith('/traffic') ? { rules: [], updated_at: null } : result([{ ...r }], 1))
  const w = await rules(), pending = deferred<RulePage>()
  await menu(w, 1); expect(w.find('.confirm').exists()).toBe(true)
  hooks.request.mockReturnValueOnce(pending.promise)
  if (action === 'search') { await w.get('.search').setValue('198.51.100.7'); await w.get('.search').trigger('keydown.enter') }
  else if (action === 'more') await w.get('.load-more').trigger('click')
  else await w.findAll('.chip')[1]!.trigger('click')
  expect(w.find('.confirm').exists()).toBe(false)
  pending.resolve(result([])); await flushPromises()
  expect(hooks.request.mock.calls.filter(c => c[1]?.method === 'DELETE')).toHaveLength(0)
})
it('R5-3 switching the delete target replaces its confirmation and cancel closes it', async () => {
  const b = { ...r, id: 'rule_' + '2'.repeat(32), dst_ip: '198.51.100.2' }
  hooks.request.mockImplementation(async (path: string) => path.startsWith('/traffic') ? { rules: [], updated_at: null } : result([{ ...r }, b]))
  const w = await rules()
  await menu(w, 1, 0); expect(w.get('.confirm strong').text()).toContain(r.dst_ip)
  await menu(w, 1, 1); expect(w.findAll('.confirm')).toHaveLength(1); expect(w.get('.confirm strong').text()).toContain(b.dst_ip)
  await w.get('.confirm .btn:not(.danger)').trigger('click'); expect(w.find('.confirm').exists()).toBe(false)
  expect(hooks.request.mock.calls.filter(c => c[1]?.method === 'DELETE')).toHaveLength(0)
})
it('R6-1 exact range placeholders and eleven per-field circular explanations without plain question marks', async () => {
  const w = drawer()
  await w.get('#action').setValue('rate_limit'); await w.get('input[value=duration]').setValue()
  const placeholders: Record<string, string> = { src_address: 'IP 或网段', dst_address: 'IP 或网段', src_port: '1–65535', dst_port: '1–65535', ttl: '0–255', dscp: '0–63', pkt_len: '0–65535', icmp_type: '0–255', icmp_code: '0–255', match_anomaly: '1–15', rate_limit: '1–4294967295', expires_in: '分钟，如 30' }
  for (const [field, value] of Object.entries(placeholders)) expect(w.get('#' + field).attributes('placeholder'), field).toBe(value)
  expect(w.get('#fragment').attributes('placeholder')).toBeUndefined(); expect(w.get('#tcp_flags').attributes('placeholder')).toBeUndefined()
  expect(w.text().match(/\?/g) || []).toHaveLength(0); expect(w.findAll('.rule-help svg')).toHaveLength(11)
  expect(w.findAll('.rule-help').every(el => el.attributes('aria-label')?.endsWith(' 说明'))).toBe(true)
  const tips = w.findAllComponents({ name: 'ElTooltip' }); expect(tips).toHaveLength(11)
  for (const tip of tips) { expect(tip.props('trigger')).toEqual(['hover', 'click']); expect(tip.props('content')).not.toBe('') }
  await w.get('.rule-help').trigger('mouseenter'); await new Promise(resolve => setTimeout(resolve, 30)); await flushPromises()
  expect(document.querySelector('[role=tooltip]')?.textContent).toContain('IPv4 或 IPv6 地址')
  expect(w.get('label[for=expires_in]').text()).toBe('时长（分钟）')
})
it('R6-2 minutes submit as duration strings and editor rounds up without changing untouched expiry', async () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-16T00:00:00Z'))
  hooks.request.mockResolvedValue({ results: [{ index: 0, error: { code: 'invalid_expires_in', message: 'duration' } }] })
  const w = drawer(); await w.get('input[value=duration]').setValue()
  for (const [input, expected] of [['30', '30m'], ['abc', 'abc']]) {
    await w.get('#expires_in').setValue(input); await w.get('form').trigger('submit'); await flushPromises()
    expect(JSON.parse(hooks.request.mock.calls.at(-1)?.[1].body).items[0].expires_in).toBe(expected)
  }
  const edit = drawer({ ...r, expires_at: new Date(Date.now() + 6763000).toISOString() })
  expect((edit.get('#expires_in').element as HTMLInputElement).value).toBe('113')
  expect(edit.get('button[type=submit]').attributes('disabled')).toBeDefined()
  hooks.request.mockResolvedValue(r); await edit.get('#comment').setValue('new memo'); await edit.get('form').trigger('submit'); await flushPromises()
  expect(JSON.parse(hooks.request.mock.calls.at(-1)?.[1].body)).toEqual({ comment: 'new memo' })
})
it('R6-3 status text switches by PUT with busy ellipsis and authoritative aria-checked', async () => {
  const w = await rules(), reply = deferred<unknown>(), button = () => w.get('[role=switch]')
  expect(button().text()).toBe('启用'); expect(button().attributes('title')).toBe('点击停用'); expect(button().attributes('aria-checked')).toBe('true')
  hooks.request.mockReturnValueOnce(reply.promise)
  await button().trigger('click')
  expect(hooks.request.mock.calls.at(-1)).toEqual(['/rules/' + r.id + '/enabled', { method: 'PUT', body: '{"enabled":false}' }])
  expect(button().text()).toBe('…'); expect(button().attributes('disabled')).toBeDefined(); expect(button().attributes('aria-checked')).toBe('true')
  hooks.request.mockResolvedValue(result([{ ...r, enabled: false }])); reply.resolve({ enabled: false }); await flushPromises()
  expect(button().text()).toBe('停用'); expect(button().attributes('title')).toBe('点击启用'); expect(button().attributes('aria-checked')).toBe('false')
})
it('R13-1 pushed rows cannot unlock a pending status write or its two menu actions', async () => {
  const pending = deferred<unknown>(); let reads = 0, enabled = true
  hooks.request.mockImplementation((path: string, options?: { method?: string }) => {
    if (options?.method === 'PUT') return pending.promise
    if (path.startsWith('/traffic')) return Promise.resolve({ rules: [], updated_at: null })
    return Promise.resolve(result([{ ...r, enabled, comment: 'pushed-' + ++reads }]))
  })
  const w = await rules(); await w.get('[role=switch]').trigger('click')
  expect(hooks.request.mock.calls.filter(call => call[1]?.method === 'PUT')).toHaveLength(1)
  state.rules = {}; await flushPromises()
  expect(reads).toBe(2); expect(w.get('tbody td').attributes('title')).toContain('pushed-2')
  const button = w.get('[role=switch]'); expect(button.attributes('disabled')).toBeDefined(); expect(button.text()).toBe('…'); expect(button.attributes('aria-checked')).toBe('true')
  await w.get('.row-menu-trigger').trigger('click'); await flushPromises()
  const items = w.findComponent(ElDropdown).findAllComponents(ElDropdownItem)
  expect(items.map(item => item.get('[role=menuitem]').attributes('aria-disabled'))).toEqual(['true', 'true'])
  const count = hooks.request.mock.calls.length; (button.element as HTMLButtonElement).click()
  for (const item of items) await item.get('[role=menuitem]').trigger('click')
  expect(hooks.request.mock.calls).toHaveLength(count); expect(w.find('.confirm').exists()).toBe(false); expect(w.findComponent(RuleDrawer).exists()).toBe(false)
  enabled = false; pending.resolve({ enabled: false }); await flushPromises()
  expect(w.get('[role=switch]').attributes('aria-checked')).toBe('false'); expect(w.get('[role=switch]').attributes('disabled')).toBeUndefined(); expect(w.get('[role=switch]').text()).toBe('停用')
})
it('R7-1 teleported rule menu has edit and delete; delete only confirms and busy disables both items', async () => {
  const w = await rules(), dropdown = w.findComponent(ElDropdown)
  await w.get('.row-menu-trigger').trigger('click'); await flushPromises()
  const items = dropdown.findAllComponents(ElDropdownItem)
  expect(items.map(i => i.text())).toEqual(['编辑', '删除'])
  expect(document.body.contains(items[0]!.get('[role=menuitem]').element)).toBe(true); expect(w.element.contains(items[0]!.get('[role=menuitem]').element)).toBe(false)
  await items[1]!.get('[role=menuitem]').trigger('click'); await nextTick()
  expect(w.find('.confirm').exists()).toBe(true); expect(hooks.request.mock.calls.filter(c => c[1]?.method === 'DELETE')).toHaveLength(0)
  const pending = deferred<unknown>(); hooks.request.mockReturnValueOnce(pending.promise)
  await w.get('[role=switch]').trigger('click'); await w.get('.row-menu-trigger').trigger('click'); await flushPromises()
  expect(dropdown.findAllComponents(ElDropdownItem).map(i => i.get('[role=menuitem]').attributes('aria-disabled'))).toEqual(['true', 'true'])
  await dropdown.findAllComponents(ElDropdownItem)[1]!.get('[role=menuitem]').trigger('click')
  expect(hooks.request.mock.calls.filter(c => c[1]?.method === 'DELETE')).toHaveLength(0)
  pending.resolve({ enabled: false }); await flushPromises()
})
it('R7-2 node floating menu keeps its exact reconcile label and operation; resync remains separate', async () => {
  const side = { state: 'normal', reason: '', confirmed_gen: 1, confirmable: true, rejected: [] }
  const node = { name: 'edge-01', online: true, base_url: "http://192.0.2.1", key_unreadable: false, incompatible: false, rules: side, whitelist: side, health_at: '', health: { rules_synced: true, whitelist_synced: true }, stats: null, rates: null }
  const w = mount(NodeTable, { props: { nodes: [node], actions: true }, global: { plugins: [i18n] }, attachTo: document.body }); wrappers.push(w)
  await w.get('.row-menu-trigger').trigger('click'); await flushPromises()
  const items = w.findComponent(ElDropdown).findAllComponents(ElDropdownItem)
  expect(items.map(i => i.text())).toEqual(['对账']); expect(document.body.contains(items[0]!.get('[role=menuitem]').element)).toBe(true); expect(w.element.contains(items[0]!.get('[role=menuitem]').element)).toBe(false)
  const pending = deferred<unknown>(); hooks.request.mockReturnValueOnce(pending.promise)
  await items[0]!.get('[role=menuitem]').trigger('click'); await flushPromises()
  expect(hooks.request.mock.calls).toEqual([['/nodes/edge-01/reconcile', { method: 'POST' }]])
  expect(items[0]!.get('[role=menuitem]').attributes('aria-disabled')).toBe('true'); expect(w.get('.el-button').attributes('disabled')).toBeDefined()
  pending.resolve({}); await flushPromises(); expect(w.get('[role=status]').text()).toBe('已提交')
  const other = mount(NodeTable, { props: { nodes: [node], actions: true }, global: { plugins: [i18n] }, attachTo: document.body }); wrappers.push(other)
  expect(other.get('.el-button').text()).toBe('重新同步'); await other.get('.el-button').trigger('click'); await flushPromises()
  expect(hooks.request.mock.calls.at(-1)).toEqual(['/nodes/edge-01/sync', { method: 'POST' }])
})

it.each(['zh-CN','ja-JP','en-US'] as const)('R9-2 %s rate tooltip only appends incomplete notice for partial samples', async lang => {
  i18n.global.locale.value = lang
  for (const incomplete of [false, true]) {
    hooks.request.mockImplementation(async (path: string) => path.startsWith('/traffic') ? { rules: [], targets: [], updated_at: '2026-10-16T00:00:00Z', incomplete } : result())
    const w = await rules(), tip = w.findAllComponents(ElTooltip).find(c => c.props('content')?.startsWith(messages[lang].rateHelp))!
    expect(tip.props('content')).toBe(messages[lang].rateHelp + (incomplete ? ' ' + messages[lang].rateIncomplete : ''))
    w.unmount(); wrappers.splice(wrappers.indexOf(w), 1)
  }
})

it('FE G1 rule drawer uses shared tables', () => {
  const setup = (drawer().vm.$ as any).setupState
  expect(setup.conditionKeys).toBe(conditionKeys); expect(setup.protocolOptions).toBe(protocolOptions); expect(setup.ranges).toBe(conditionRanges)
})
it('FE G1 rule protocol dropdown has the complete ordered options', () => {
  expect(drawer().findAll('#protocol option').map(o => (o.element as HTMLOptionElement).value)).toEqual(['all','tcp','udp','icmp','icmpv6','igmp','gre','esp'])
})
