import { protocolOptions } from '../src/rules'
import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { ElDropdown, ElDropdownItem } from 'element-plus'
import { i18n, messages } from '../src/i18n'
import { ApiError } from '../src/api/client'
import type { WhitelistDTO } from '../src/api/types'
const hooks=vi.hoisted(()=>({request:vi.fn(),generation:0}))
vi.mock('../src/state',async()=>({request:hooks.request,captureSession:()=>{const g=hooks.generation;return{isCurrent:()=>g===hooks.generation}},state:(await import('vue')).reactive({user:{name:'admin'},rules:{}})}))
import { state } from '../src/state'
import Whitelist from '../src/views/Whitelist.vue'
import WhitelistDrawer from '../src/components/WhitelistDrawer.vue'
const make=(id:string,more:Partial<WhitelistDTO>={}):WhitelistDTO=>({id,src_ip:'192.0.2.1',dst_ip:'',src_port:0,dst_port:0,protocol:'tcp',comment:'memo',created_at:'2026-10-16T00:00:00Z',created_by:'user:admin',...more})
const wrappers:VueWrapper[]=[]
const defer=()=>{let resolve!:(v:any)=>void;const promise=new Promise(a=>{resolve=a});return{resolve,promise}}
async function mountPage(){const w=mount(Whitelist,{global:{plugins:[i18n]},attachTo:document.body});wrappers.push(w);await flushPromises();return w}
async function mountDrawer(){const w=mount(WhitelistDrawer,{global:{plugins:[i18n]},attachTo:document.body});wrappers.push(w);await flushPromises();return w}
async function menu(w:VueWrapper,row=0){await w.findAll('.row-menu-trigger')[row]!.trigger('click');await flushPromises();await vi.advanceTimersByTimeAsync(0);await w.findAllComponents(ElDropdown)[row]!.findComponent(ElDropdownItem).get('[role=menuitem]').trigger('click');await flushPromises()}
beforeEach(()=>{vi.useFakeTimers();hooks.generation=0;hooks.request.mockReset();i18n.global.locale.value='zh-CN';(state as any).user={name:'admin'};hooks.request.mockResolvedValue({items:[make('A')],next_after:null})})
afterEach(()=>{wrappers.splice(0).forEach(w=>w.unmount());vi.useRealTimers()})
it('G6 V10 three-page traversal; V16a V16c V16d four exact port displays',async()=>{
  hooks.request.mockResolvedValueOnce({items:[make('A',{src_port:123})],next_after:'A'}).mockResolvedValueOnce({items:[make('B',{dst_port:179})],next_after:'B'}).mockResolvedValueOnce({items:[make('C',{src_port:123,dst_port:179}),make('D')],next_after:null})
  const w=await mountPage();expect(hooks.request.mock.calls.map(c=>c[0])).toEqual(['/whitelist?limit=1000','/whitelist?limit=1000&after=A','/whitelist?limit=1000&after=B'])
  expect(w.findAll('.whitelist-ports').map(c=>c.text())).toEqual(['源 123','目的 179','源 123 · 目的 179','—']);expect(w.text()).toContain('共 4 条');expect(w.text()).not.toContain('user:admin')
})
it('G6 V12 debounced search matches comment alone and address alone, case-insensitively',async()=>{
  hooks.request.mockResolvedValue({items:[make('A',{comment:'AlphaNeedle'}),make('B',{src_ip:'198.51.100.2',comment:'Else'})],next_after:null})
  const w=await mountPage();await w.get('.search').setValue('alphaneedle');await vi.advanceTimersByTimeAsync(299);expect(w.text()).toContain('共 2 条');await vi.advanceTimersByTimeAsync(1)
  expect(w.findAll('[data-whitelist-id]').map(c=>c.attributes('data-whitelist-id'))).toEqual(['A']);expect(w.text()).toContain('共 1 条')
  await w.get('.search').setValue('198.51.100.2');await vi.advanceTimersByTimeAsync(300);expect(w.findAll('[data-whitelist-id]').map(c=>c.attributes('data-whitelist-id'))).toEqual(['B'])
  await w.get('.search').setValue('missing');await vi.advanceTimersByTimeAsync(300);expect(w.text()).toContain('没有匹配的条目')
})
it('G6 V11 V23 confirms captured B ID after [A,B,C] becomes [B,C]',async()=>{
  hooks.request.mockResolvedValue({items:[make('A'),make('B'),make('C')],next_after:null});const w=await mountPage();await menu(w,1)
  expect(hooks.request.mock.calls.filter(c=>c[1]?.method==='DELETE')).toHaveLength(0);expect(w.get('.confirm').text()).toContain('删除这条白名单？')
  hooks.request.mockResolvedValue({items:[make('B'),make('C')],next_after:null});(state as any).rules={push:1};await flushPromises();await vi.advanceTimersByTimeAsync(5000);await flushPromises()
  expect(w.findAll('[data-whitelist-id]').map(r=>r.attributes('data-whitelist-id'))).toEqual(['B','C']);await w.get('.confirm .danger').trigger('click');await flushPromises()
  expect(hooks.request.mock.calls.filter(c=>c[1]?.method==='DELETE').map(c=>c[0])).toEqual(['/whitelist/B'])
})
it('G6 new closes and reloads; V13 existing stays with notice and explicit close',async()=>{
  const w=await mountPage();await w.get('.page-head button').trigger('click');hooks.request.mockResolvedValueOnce({...make('new'),existing:false});await w.get('form').trigger('submit');await flushPromises()
  expect(w.findComponent(WhitelistDrawer).exists()).toBe(false);expect(hooks.request.mock.calls.filter(c=>c[0].includes('limit'))).toHaveLength(2)
  await w.get('.page-head button').trigger('click');hooks.request.mockResolvedValueOnce({...make('A'),existing:true});await w.get('form').trigger('submit');await flushPromises()
  expect(w.findComponent(WhitelistDrawer).exists()).toBe(true);expect(w.get('.rule-notice').text()).toContain('已有相同的白名单条目（备注未改）')
  await w.get('.rule-notice button').trigger('click');expect(w.findComponent(WhitelistDrawer).exists()).toBe(false)
})
it('G6 V16b source and destination inputs enter distinct numeric fields',async()=>{
  hooks.request.mockResolvedValue({...make('new'),existing:false});const w=await mountDrawer();await w.get('#wl-src_ip').setValue('192.0.2.7');await w.get('#wl-dst_ip').setValue('198.51.100.9');await w.get('#wl-src_port').setValue('123');await w.get('#wl-dst_port').setValue('179');await w.get('#wl-comment').setValue(' note ')
  await w.get('form').trigger('submit');await flushPromises();expect(JSON.parse(hooks.request.mock.calls[0]![1].body)).toEqual({src_ip:'192.0.2.7',dst_ip:'198.51.100.9',src_port:123,dst_port:179,protocol:'all',comment:'note'})
})
it.each([
 ['invalid_rule','ip','invalid IP address','ip','请输入单个 IP 地址'],
 ['invalid_rule','port','port out of range','port','端口须为'],
 ['invalid_rule','tuple','rule field combination is not recognized','ip','请填写地址、端口或协议'],
 ['invalid_rule','protocol','unknown protocol','protocol','协议不支持'],
 ['invalid_rule','protocol','protocol does not support ports','protocol','此协议不能带端口'],
 ['mapped_ipv6','','mapped','','请用 IPv4 地址'],['address_family_mismatch','','family','','源和目的须为同一地址族'],['table_full','','full','','白名单容量已满'],
])('G6 dedicated error %s %s %s',async(code,field,message,location,text)=>{
  hooks.request.mockRejectedValue(new ApiError(400,{code,field,message}));const w=await mountDrawer();await w.get('form').trigger('submit');await flushPromises()
  expect(w.get(location?`[data-field="${location}"] .error-text`:'.drawer-error').text()).toContain(text)
  if(location)expect(w.find('.drawer-error').exists()).toBe(false)
})
it('G6 V24 external code with field uses generic text, never rule hints',async()=>{
  hooks.request.mockRejectedValue(new ApiError(400,{code:'bad_request',field:'comment',message:'private backend'}));const w=await mountDrawer();await w.get('form').trigger('submit');await flushPromises()
  expect(w.get('.drawer-error').text()).toBe(messages['zh-CN'].errors.bad_request);expect(w.text()).not.toContain('private backend');expect(w.text()).not.toContain(i18n.global.t('ruleErrors.fallback', { key: '备注' }))
})
it('G6 push refresh is trailing, leaves no polling, stale list/session replies discarded',async()=>{
  const w=await mountPage();expect(hooks.request).toHaveBeenCalledTimes(1)
  ;(state as any).rules={push:1};await flushPromises();expect(hooks.request).toHaveBeenCalledTimes(2)
  ;(state as any).rules={push:2};await flushPromises();await vi.advanceTimersByTimeAsync(4999);expect(hooks.request).toHaveBeenCalledTimes(2);await vi.advanceTimersByTimeAsync(1);expect(hooks.request).toHaveBeenCalledTimes(3)
  await vi.advanceTimersByTimeAsync(20000);expect(hooks.request).toHaveBeenCalledTimes(3)
  const old=defer();hooks.request.mockReturnValueOnce(old.promise);(state as any).rules={push:3};await flushPromises();hooks.generation++;old.resolve({items:[make('stale')],next_after:null});await flushPromises();expect(w.text()).not.toContain('stale')
  w.unmount();wrappers.splice(wrappers.indexOf(w),1);(state as any).rules={push:4};await vi.advanceTimersByTimeAsync(5000);expect(hooks.request).toHaveBeenCalledTimes(4)
})
it('G6 leaving during list request discards continuation; loading and empty states',async()=>{
  const pending=defer();hooks.request.mockReturnValue(pending.promise);const w=await mountPage();expect(w.text()).toContain('加载中');w.unmount();wrappers.splice(wrappers.indexOf(w),1);pending.resolve({items:[make('late')],next_after:'late'});await flushPromises();expect(hooks.request).toHaveBeenCalledTimes(1)
  hooks.request.mockResolvedValue({items:[],next_after:null});const empty=await mountPage();expect(empty.text()).toContain('还没有白名单')
})
it('r1 V27 whitelist comment and creator remain literal text without markup elements',async()=>{
  const comment='<img src=x onerror=alert(1)>',creator='<b>x</b>'
  hooks.request.mockResolvedValue({items:[make('markup',{comment,created_by:'user:'+creator})],next_after:null})
  const w=await mountPage(),cells=w.get('[data-whitelist-id="markup"]').findAll('td')
  expect(cells[4]!.element.textContent).toBe(comment);expect(cells[5]!.element.textContent).toBe(creator)
  expect(w.get('table').element.querySelector('img')).toBeNull();expect(w.get('table').element.querySelector('b')).toBeNull()
})

it('FE G1 whitelist drawer uses the shared protocol object', async () => {
  expect(((await mountDrawer()).vm.$ as any).setupState.protocolOptions).toBe(protocolOptions)
})
it('FE G2 collects all 60 pages until null', async () => {
  let page = 0
  hooks.request.mockImplementation(async () => { page++; return { items: [make(String(page))], next_after: page === 60 ? null : String(page) } })
  const w = await mountPage()
  expect(w.findAll('[data-whitelist-id]').map(row => row.attributes('data-whitelist-id'))).toEqual(Array.from({ length: 60 }, (_, i) => String(i + 1)))
  expect(hooks.request).toHaveBeenCalledTimes(60); expect(w.find('[role=alert]').exists()).toBe(false)
})
it('FE G2 repeated cursor stops within two requests and shows an error', async () => {
  let calls = 0
  hooks.request.mockImplementation(async () => ({ items: [make(String(++calls))], next_after: calls >= 4 ? null : 'same' }))
  const w = await mountPage()
  expect.soft(hooks.request.mock.calls.length).toBeLessThanOrEqual(2)
  expect(w.get('[role=alert]').text()).toBe(i18n.global.t('operationFailed')); expect(w.findAll('[data-whitelist-id]')).toHaveLength(0)
})
