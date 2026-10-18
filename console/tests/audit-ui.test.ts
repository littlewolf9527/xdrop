import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { createRouter, createMemoryHistory, type Router } from 'vue-router'
import { i18n } from '../src/i18n'
import { ApiError } from '../src/api/client'
import { auditActions } from '../src/audit'
const hooks=vi.hoisted(()=>({request:vi.fn(),identity:vi.fn(),expired:vi.fn(),generation:0}))
vi.mock('../src/state',async()=>{
  const {reactive,computed}=await import('vue'),state=reactive({user:{name:'admin',role:'admin'} as any})
  return {state,request:hooks.request,canSettings:computed(()=>state.user?.role==='admin'),captureSession:()=>{const g=hooks.generation;return{isCurrent:()=>g===hooks.generation}},expire:()=>{hooks.expired();hooks.generation++;state.user=null},refreshIdentity:async()=>{const g=hooks.generation,user=await hooks.identity();if(g===hooks.generation)state.user=user}}
})
import Audit from '../src/views/Audit.vue'
import { state, expire } from '../src/state'
const wrappers:VueWrapper[]=[]
let router:Router,blobs:Blob[],downloads:string[],transport:ReturnType<typeof vi.fn>
const defer=()=>{let resolve!:(v:any)=>void,reject!:(e:any)=>void;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{resolve,reject,promise}}
const row=(id:number,action='auth.login')=>({id,at:'2026-10-17T00:00:05Z',actor:'user:admin',source:'192.0.2.30',action,target:'user:operator',before:null,after:{enabled:true}})
const page=(id:number,cursor='',action='auth.login')=>({items:[row(id,action)],next_cursor:cursor})
const err=(status=400,code='invalid_field')=>Response.json({code,field:'cursor',message:'private'},{status})
const more=(w:VueWrapper)=>w.findAll('button').find(b=>b.text()==='加载更多')
async function view(){const w=mount(Audit,{global:{plugins:[i18n,router]}});wrappers.push(w);await flushPromises();return w}
async function choose(w:VueWrapper,value:string){await w.get('select').setValue(value);await flushPromises()}
async function download(w:VueWrapper,index=0){await w.findAll('.audit-export')[index].trigger('click');await flushPromises()}
const blobText=(blob:Blob)=>new Promise<string>((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result as string);reader.onerror=reject;reader.readAsText(blob)})
beforeEach(async()=>{
  hooks.generation=0;hooks.request.mockReset().mockResolvedValue(page(1,'G0'));hooks.identity.mockReset().mockResolvedValue({name:'admin',role:'operator'});hooks.expired.mockReset();state.user={name:'admin',role:'admin'};i18n.global.locale.value='zh-CN';blobs=[];downloads=[]
  router=createRouter({history:createMemoryHistory(),routes:['/audit','/overview'].map(path=>({path,component:{template:'<div />'}}))});await router.push('/audit');await router.isReady()
  transport=vi.fn();vi.stubGlobal('fetch',transport);vi.stubGlobal('URL',Object.assign(class extends URL {},{createObjectURL:(blob:Blob)=>{blobs.push(blob);return'blob:fixture'},revokeObjectURL:vi.fn()}))
  vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(function(this:HTMLAnchorElement){downloads.push(this.download)})
})
afterEach(()=>{wrappers.splice(0).forEach(w=>w.unmount());vi.unstubAllGlobals()})
it('G3 V9 first page has no action; filter replaces rows without cursor and values equal closed set',async()=>{
  const w=await view();expect(hooks.request.mock.calls[0][0]).toBe('/audit?limit=100');expect(w.findAll('option').map(o=>o.attributes('value')).slice(1).sort()).toEqual([...auditActions].sort())
  hooks.request.mockResolvedValue(page(2,'','auth.login_failed'));await choose(w,'auth.login_failed')
  expect(hooks.request.mock.calls.at(-1)![0]).toBe('/audit?limit=100&action=auth.login_failed');expect(w.findAll('tbody tr')).toHaveLength(1);expect(w.get('tbody tr .crit').text()).toBe('登录失败')
  expect(w.get('tbody td').attributes('title')).toBe('2026-10-17T00:00:05Z');expect(w.findAll('tbody td')[1].attributes('title')).toBe('user:admin')
})
it('G3 V7a switch A nonempty cursor to B empty cursor never reuses A',async()=>{
  const w=await view();hooks.request.mockResolvedValue(page(2,'A'));await choose(w,'auth.login');expect(more(w)).toBeDefined()
  hooks.request.mockResolvedValue(page(3,'','user.password'));await choose(w,'user.password');expect(more(w)).toBeUndefined()
  expect(hooks.request.mock.calls.slice(2).every(c=>!c[0].includes('cursor=A'))).toBe(true)
})
it('G3 V7b pending new first page hides load-more immediately',async()=>{
  const w=await view();hooks.request.mockResolvedValue(page(2,'A'));await choose(w,'auth.login');const pending=defer();hooks.request.mockReturnValue(pending.promise)
  await choose(w,'user.password');expect(more(w)).toBeUndefined();expect(w.get('[role=status]').text()).toBe('加载中');expect(hooks.request).toHaveBeenCalledTimes(3)
  pending.resolve(page(3,'','user.password'));await flushPromises();expect(more(w)).toBeUndefined()
})
it('G3 V10 normal A pagination uses same action and appends then hides button',async()=>{
  const w=await view();hooks.request.mockResolvedValue(page(2,'A'));await choose(w,'auth.login');hooks.request.mockResolvedValue(page(3))
  await more(w)!.trigger('click');await flushPromises();expect(hooks.request.mock.calls.at(-1)![0]).toBe('/audit?limit=100&cursor=A&action=auth.login')
  expect(w.findAll('tbody tr')).toHaveLength(2);expect(more(w)).toBeUndefined()
})
it('G3 cursor 4 all G0 then filtered G1 uses G1 and never G0',async()=>{
  const w=await view();hooks.request.mockResolvedValue(page(2,'G1'));await choose(w,'auth.login');hooks.request.mockResolvedValue(page(3));await more(w)!.trigger('click');await flushPromises()
  expect(hooks.request.mock.calls.at(-1)![0]).toBe('/audit?limit=100&cursor=G1&action=auth.login');expect(hooks.request.mock.calls.at(-1)![0]).not.toContain('G0')
})
it('G3 V8a stale first-page sequence while session stays current',async()=>{
  const pending=defer();hooks.request.mockReturnValueOnce(pending.promise);const w=await view(),vm=w.vm;hooks.request.mockResolvedValue(page(2,'','user.password'));await choose(w,'user.password')
  pending.resolve(page(3,'old','rule.create'));await flushPromises();expect(hooks.generation).toBe(0);expect(w.vm).toBe(vm);expect(w.findAll('tbody tr')).toHaveLength(1);expect(w.get('tbody').text()).not.toContain('建规则');expect(w.findAll('tbody tr').map(r=>r.findAll('td')[2].text())).toEqual(['改密码']);expect(more(w)).toBeUndefined()
})
it('G3 V8b stale session with same sequence keeps original instance mounted',async()=>{
  const pending=defer();hooks.request.mockReturnValue(pending.promise);const w=await view(),vm=w.vm;hooks.generation++;expect(w.exists()).toBe(true)
  pending.resolve(page(3,'old','rule.create'));await flushPromises();expect(w.vm).toBe(vm);expect(hooks.request).toHaveBeenCalledTimes(1)
  expect(w.findAll('tbody tr')).toHaveLength(0);expect(more(w)).toBeUndefined();expect(w.get('[role=status]').text()).toBe('加载中')
})
it('G3 V25 pending append loses sequence after filter switch; double click sends one',async()=>{
  const w=await view(),pending=defer();hooks.request.mockReturnValue(pending.promise);await more(w)!.trigger('click');await more(w)!.trigger('click');expect(hooks.request).toHaveBeenCalledTimes(2)
  hooks.request.mockResolvedValue(page(2,'','user.password'));await choose(w,'user.password');pending.resolve(page(3,'old','rule.create'));await flushPromises()
  expect(hooks.generation).toBe(0);expect(w.findAll('tbody tr')).toHaveLength(1);expect(w.get('tbody').text()).not.toContain('建规则');expect(w.findAll('tbody tr').map(r=>r.findAll('td')[2].text())).toEqual(['改密码']);expect(more(w)).toBeUndefined()
})
it('G3 empty filtered-empty generic error unknown action and append error keeps rows',async()=>{
  hooks.request.mockResolvedValue({items:[],next_cursor:''});const w=await view();expect(w.text()).toContain('还没有审计记录');await choose(w,'auth.login');expect(w.text()).toContain('没有这个动作的记录')
  hooks.request.mockRejectedValue(new ApiError(400,{code:'invalid_field',field:'cursor',message:'private'}));await choose(w,'user.password');expect(w.get('[role=alert]').text()).toBe(i18n.global.t('errors.invalid_field'));expect(w.text()).not.toMatch(/ruleErrors|ruleHints|private/)
  hooks.request.mockResolvedValue(page(4,'next','future.action'));await choose(w,'');expect(w.get('tbody').text()).toContain('future.action')
  hooks.request.mockRejectedValue(new TypeError('offline'));await more(w)!.trigger('click');await flushPromises();expect(w.findAll('tbody tr')).toHaveLength(1);expect(w.get('.audit-more [role=alert]').text()).toBe(i18n.global.t('unreachable'))
})
it('G3 unmount discards pending first page',async()=>{
  const pending=defer();hooks.request.mockReturnValue(pending.promise);const w=await view(),vm=w.vm as any;w.unmount();wrappers.splice(wrappers.indexOf(w),1)
  pending.resolve(page(1,'stale'));await flushPromises();expect(vm.$.setupState.rows).toEqual([]);expect(vm.$.setupState.cursor).toBe('')
})
it('G4 V11 administrator buttons exist; operator DOM has none',async()=>{
  const w=await view();expect(w.findAll('.audit-export')).toHaveLength(2);state.user={name:'operator',role:'operator'};await flushPromises();expect(w.findAll('.audit-export')).toHaveLength(0)
})
it.each(['csv','json'] as const)('G4 V13 V14 complete %s saves exact Blob once and full-range URL',async format=>{
  const w=await view();await choose(w,'auth.login');const full=format==='csv'?'id,actor\n1,甲\n2,乙\n':'[{"id":1,"actor":"甲"},{"id":2,"actor":"乙"}]',bytes=new TextEncoder().encode(full)
  transport.mockResolvedValue(new Response(new ReadableStream({start(c){c.enqueue(bytes.slice(0,12));c.enqueue(bytes.slice(12));c.close()}})))
  await download(w,format==='csv'?0:1)
  expect(transport).toHaveBeenCalledWith('/api/v1/audit/export?from=1970-01-01T00:00:00Z&to=9999-12-31T23:59:59Z&format='+format+'&action=auth.login',{credentials:'same-origin'})
  expect(downloads).toHaveLength(1);expect(downloads[0]).toMatch(new RegExp('^xdrop-audit-\\d{8}-\\d{6}\\.'+format+'$'));expect(blobs).toHaveLength(1);expect(await blobText(blobs[0])).toBe(full)
})
it('G4 V12 pull delivers two chunks before third pull rejects; saves zero and shows interruption',async()=>{
  const w=await view();let pulls=0;const delivered:string[]=[]
  transport.mockResolvedValue(new Response(new ReadableStream({pull(c){pulls++;if(pulls===3)return Promise.reject(new Error('cut'));const text=pulls===1?'first,甲\n':'second,乙\n';delivered.push(text);c.enqueue(new TextEncoder().encode(text))}},{highWaterMark:0})))
  await download(w);expect(delivered).toEqual(['first,甲\n','second,乙\n']);expect(pulls).toBe(3);expect(downloads).toHaveLength(0);expect(blobs).toHaveLength(0)
  expect(w.get('[role=alert]').text()).toBe('下载中断，文件不完整，未保存');expect(transport.mock.calls[0][0]).not.toContain('&action=')
})
it.each([401,403])('G4 V23 late %s cannot expire or demote new session; same mounted page',async status=>{
  const w=await view(),vm=w.vm,pending=defer();transport.mockReturnValue(pending.promise);await download(w);hooks.generation++;state.user={name:'operator',role:'operator'}
  expect(w.exists()).toBe(true);pending.resolve(err(status,status===401?'unauthenticated':'admin_required'));await flushPromises()
  expect(w.vm).toBe(vm);expect(downloads).toHaveLength(0);expect(hooks.expired).not.toHaveBeenCalled();expect(hooks.identity).not.toHaveBeenCalled();expect(state.user?.name).toBe('operator');expect(router.currentRoute.value.path).toBe('/audit')
})
it('G4 demotion identity reply after session changes cannot mutate identity or navigate',async()=>{
  const w=await view(),pending=defer();hooks.identity.mockReturnValue(pending.promise);transport.mockResolvedValue(err(403,'admin_required'));await download(w);expect(hooks.identity).toHaveBeenCalledTimes(1)
  const vm=w.vm;hooks.generation++;state.user={name:'operator',role:'admin'};pending.resolve({name:'admin',role:'operator'});await flushPromises()
  expect(w.vm).toBe(vm);expect(state.user).toEqual({name:'operator',role:'admin'});expect(router.currentRoute.value.path).toBe('/audit');expect(downloads).toHaveLength(0)
})
it.each([400,401,403])('G4 current non-2xx %s applies client-equivalent rules',async status=>{
  const w=await view();transport.mockResolvedValue(err(status,status===401?'unauthenticated':status===403?'admin_required':'invalid_field'));await download(w);expect(downloads).toHaveLength(0)
  if(status===400)expect(w.get('[role=alert]').text()).toBe(i18n.global.t('errors.invalid_field'))
  if(status===401){expect(hooks.expired).toHaveBeenCalledTimes(1);expect(state.user).toBeNull()}
  if(status===403){expect(hooks.identity).toHaveBeenCalledTimes(1);expect(state.user?.role).toBe('operator');expect(router.currentRoute.value.path).toBe('/overview')}
})
it('G4 pending export disables both buttons; repeated request ignored; expire prevents save',async()=>{
  const w=await view(),pending=defer();transport.mockReturnValue(pending.promise);await download(w)
  expect(w.findAll('.audit-export').every(b=>b.attributes('disabled')!==undefined&&b.attributes('aria-busy')==='true')).toBe(true)
  await download(w,1);expect(transport).toHaveBeenCalledTimes(1);expire();pending.resolve(new Response('complete'));await flushPromises();expect(downloads).toHaveLength(0)
})
it('G4 saved Blob bytes equal UTF-8 fixture through FileReader array buffer',async()=>{
  const w=await view(),bytes=new TextEncoder().encode('[{"actor":"甲"}]\n');transport.mockResolvedValue(new Response(bytes));await download(w,1)
  expect(downloads).toHaveLength(1);const actual=await new Promise<ArrayBuffer>((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result as ArrayBuffer);reader.onerror=reject;reader.readAsArrayBuffer(blobs[0])})
  expect([...new Uint8Array(actual)]).toEqual([...bytes])
})
it('G3 refresh clears cursor during request then replaces current rows',async()=>{
  const w=await view(),pending=defer();hooks.request.mockReturnValue(pending.promise);await w.findAll('button').find(b=>b.text()==='刷新')!.trigger('click');await flushPromises()
  expect(more(w)).toBeUndefined();expect(hooks.request.mock.calls.at(-1)![0]).toBe('/audit?limit=100');pending.resolve(page(10,''));await flushPromises();expect(w.findAll('tbody tr')).toHaveLength(1);expect(more(w)).toBeUndefined()
})
it('G3 V26 switching from A to failed B clears previous rows and shows generic error',async()=>{
  const w=await view();hooks.request.mockResolvedValue(page(2,'A','auth.login'));await choose(w,'auth.login')
  expect(w.findAll('tbody tr')).toHaveLength(1);expect(w.findAll('tbody td')[2].text()).toBe('登录')
  hooks.request.mockRejectedValue(new ApiError(503,{code:'unavailable',message:'private'}));await choose(w,'user.password')
  expect(hooks.request.mock.calls.at(-1)![0]).toBe('/audit?limit=100&action=user.password')
  expect(w.findAll('tbody tr')).toHaveLength(0);expect(w.get('[role=alert]').text()).toBe('操作失败');expect(w.find('[role=status]').exists()).toBe(false)
})
it('G3 switching from A to pending B clears previous rows while loading',async()=>{
  const w=await view();hooks.request.mockResolvedValue(page(2,'A','auth.login'));await choose(w,'auth.login')
  expect(w.findAll('tbody tr')).toHaveLength(1);expect(w.findAll('tbody td')[2].text()).toBe('登录')
  const pending=defer();hooks.request.mockReturnValue(pending.promise);await choose(w,'user.password')
  expect(hooks.request.mock.calls.at(-1)![0]).toBe('/audit?limit=100&action=user.password')
  expect(w.findAll('tbody tr')).toHaveLength(0);expect(w.get('[role=status]').text()).toBe('加载中');expect(w.find('[role=alert]').exists()).toBe(false)
  pending.resolve(page(3,'','user.password'));await flushPromises();expect(w.findAll('tbody tr')).toHaveLength(1);expect(w.findAll('tbody td')[2].text()).toBe('改密码')
})
it('G3 R1-P2-1 HTML-like audit fields render as literal text and create no element',async()=>{
  const html='<b data-review-injected="yes">probe</b>'
  hooks.request.mockResolvedValue({items:[{id:9,at:'2026-10-17T00:00:05Z',actor:'user:'+html,source:html,action:html,target:html,before:null,after:null}],next_cursor:''})
  const w=await view(),cells=w.findAll('tbody td')
  expect(w.find('[data-review-injected]').exists()).toBe(false);expect(cells.slice(1).map(c=>c.text())).toEqual([html,html,html,html])
})
it.each([401,403])('G4 R1-P2-2 envelope %s arriving after session change cannot expire or demote; same mounted page',async status=>{
  const w=await view(),vm=w.vm,envelope=defer();transport.mockResolvedValue({ok:false,status,headers:new Headers(),body:null,json:()=>envelope.promise})
  await download(w);expect(transport).toHaveBeenCalledTimes(1);hooks.generation++;state.user={name:'operator',role:'operator'}
  envelope.resolve({code:status===401?'unauthenticated':'admin_required',message:''});await flushPromises()
  expect(w.vm).toBe(vm);expect(hooks.expired).not.toHaveBeenCalled();expect(hooks.identity).not.toHaveBeenCalled();expect(state.user?.name).toBe('operator');expect(router.currentRoute.value.path).toBe('/audit');expect(downloads).toHaveLength(0)
})
