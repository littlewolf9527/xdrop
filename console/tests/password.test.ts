import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { i18n } from '../src/i18n'
import { ApiError } from '../src/api/client'
import { passwordOpen } from '../src/password'
const hooks = vi.hoisted(() => ({ request: vi.fn(), generation: 0, expire: vi.fn() }))
vi.mock('../src/state', async () => ({ request: hooks.request, expire: hooks.expire, captureSession: () => { const g = hooks.generation; return { isCurrent: () => g === hooks.generation } }, state: (await import('vue')).reactive({ user: { name: 'admin' }, notice: '', error: '' }) }))
import PasswordDrawer from '../src/components/PasswordDrawer.vue'
import { state } from '../src/state'
const wrappers: VueWrapper[] = []
const defer = () => { let resolve!: (v?: any) => void, reject!: (e: any) => void; const promise = new Promise((a,b) => { resolve=a; reject=b }); return { resolve, reject, promise } }
const fail = (status: number, code: string, field?: string) => new ApiError(status, { code, message: 'private', ...(field ? { field } : {}) }, new Headers({ 'Retry-After': '60' }))
async function drawer() { const w=mount(PasswordDrawer,{attachTo:document.body,global:{plugins:[i18n]}}); wrappers.push(w); await flushPromises(); return w }
async function fill(w: VueWrapper, current='example-password-1', next='example-password-2', again=next) { await w.get('#own-current_password').setValue(current); await w.get('#own-password').setValue(next); await w.get('#own-confirmation').setValue(again) }
async function submit(w: VueWrapper) { await w.get('form').trigger('submit'); await flushPromises() }
beforeEach(() => { hooks.generation=0; hooks.request.mockReset(); hooks.expire.mockReset(); state.user={name:'admin'} as any; state.notice=''; state.error=''; passwordOpen.value=true; i18n.global.locale.value='zh-CN' })
afterEach(() => { wrappers.splice(0).forEach(w=>w.unmount()); passwordOpen.value=false })
it('G2 empty fields disable; V2 mismatched confirmation sends zero', async () => {
  const w=await drawer(); expect(w.get('[type=submit]').attributes('disabled')).toBeDefined(); expect(w.findAll('input').every(e=>(e.element as HTMLInputElement).value==='')).toBe(true)
  await fill(w,undefined,undefined,'example-password-3'); await submit(w)
  expect(w.get('[data-field=confirmation] [role=alert]').text()).toBe('两次输入的新密码不一样'); expect(hooks.request).not.toHaveBeenCalled()
})
it('G2 V6 passwords with identical surrounding spaces are transmitted verbatim', async () => {
  const w=await drawer(); const password=' example-password-2 '; await fill(w,password,password); await submit(w)
  expect(hooks.request).toHaveBeenCalledWith('/auth/me/password',{method:'PUT',body:JSON.stringify({current_password:password,password})})
})
it('G2 V6b distinct current and new password field names stay in place', async () => {
  const w=await drawer(); await fill(w); await submit(w)
  expect(JSON.parse(hooks.request.mock.calls[0][1].body)).toEqual({current_password:'example-password-1',password:'example-password-2'})
})
it('G2 V3 401 and 429 text match exactly without digits or mechanisms', async () => {
  const texts: string[]=[]
  for (const [status,code] of [[401,'invalid_credentials'],[429,'login_throttled']] as const) {
    hooks.request.mockRejectedValueOnce(fail(status,code)); const w=await drawer(); await fill(w); await submit(w)
    texts.push(w.get('[role=alert]').text()); expect(w.text()).not.toMatch(/\d|锁定|限流|稍后|重试|秒/)
  }
  expect(texts).toEqual(['当前密码不对','当前密码不对'])
})
it('G2 V4 invalid credentials keep identity drawer and all three fields', async () => {
  const user=state.user; hooks.request.mockRejectedValueOnce(fail(401,'invalid_credentials')); const w=await drawer(); await fill(w); await submit(w)
  expect(hooks.expire).not.toHaveBeenCalled(); expect(state.user).toBe(user); expect(passwordOpen.value).toBe(true)
  expect(w.findAll('input').map(e=>(e.element as HTMLInputElement).value)).toEqual(['example-password-1','example-password-2','example-password-2'])
})
it('G2 V5 wrong current password belongs only to current field', async () => {
  hooks.request.mockRejectedValueOnce(fail(401,'invalid_credentials')); const w=await drawer(); await fill(w); await submit(w)
  expect(w.get('[data-field=current_password] [role=alert]').text()).toBe('当前密码不对'); expect(w.find('[data-field=password] [role=alert]').exists()).toBe(false)
})
it.each([[400,'invalid_field','password','passwordLength'],[503,'unavailable',undefined,'operationFailed'],[400,'invalid_field','current_password','errors.invalid_field']] as const)('G2 error %s %s %s uses %s',async(status,code,field,key)=>{
  hooks.request.mockRejectedValueOnce(fail(status,code,field)); const w=await drawer(); await fill(w); await submit(w)
  expect(w.get(field==='password'?'[data-field=password] [role=alert]':'.drawer-error').text()).toBe(i18n.global.t(key))
  expect(w.text()).not.toMatch(/ruleErrors|ruleHints|private/)
})
it('G2 V22 stale session retains original mounted instance and pending busy state',async()=>{
  const pending=defer();hooks.request.mockReturnValue(pending.promise);const w=await drawer();await fill(w);await submit(w)
  const vm=w.vm;expect(w.get('[type=submit]').attributes('aria-busy')).toBe('true');hooks.generation++
  expect(w.exists()).toBe(true);expect(passwordOpen.value).toBe(true);expect(w.vm).toBe(vm)
  pending.reject(fail(400,'invalid_field','password'));await flushPromises()
  expect(w.vm).toBe(vm);expect(w.find('[role=alert]').exists()).toBe(false);expect(w.get('[type=submit]').attributes('aria-busy')).toBe('true')
  expect(state.notice).toBe('');expect(state.error).toBe('');expect(hooks.expire).not.toHaveBeenCalled()
})
it('G2 in-flight double submit sends once; unmounted reply writes nothing',async()=>{
  const pending=defer();hooks.request.mockReturnValue(pending.promise);const w=await drawer();await fill(w);await submit(w);await submit(w)
  expect(hooks.request).toHaveBeenCalledTimes(1);w.unmount();wrappers.splice(wrappers.indexOf(w),1);pending.resolve();await flushPromises()
  expect(state.notice).toBe('');expect(hooks.expire).not.toHaveBeenCalled()
})
