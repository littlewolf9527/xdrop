import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { i18n } from '../src/i18n'
import { ApiError } from '../src/api/client'
const hooks=vi.hoisted(()=>({request:vi.fn(),generation:0}))
vi.mock('../src/state',async()=>({request:hooks.request,captureSession:()=>{const g=hooks.generation;return{isCurrent:()=>g===hooks.generation}},state:(await import('vue')).reactive({user:{name:'admin'},rules:{}})}))
import ImportDrawer from '../src/components/ImportDrawer.vue'
import { state } from '../src/state'
const wrappers:VueWrapper[]=[]
const defer=()=>{let resolve!:(v:any)=>void,reject!:(e:any)=>void;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{resolve,reject,promise}}
const ok=(items:any[])=>({epoch:'fixture',results:items.map((_,index)=>({index,existing:false,rule:{id:''}}))})
const calls=(write=false)=>hooks.request.mock.calls.filter(c=>c[0]===(write?'/rules/batch':'/rules/batch?validate=1'))
const body=(c:any)=>JSON.parse(c[1].body).items
function button(w:VueWrapper,text:string){return w.findAll('button').find(b=>b.text()===text)!}
async function drawer(){const w=mount(ImportDrawer,{global:{plugins:[i18n]},attachTo:document.body});wrappers.push(w);await flushPromises();return w}
async function check(w:VueWrapper,text:string){await w.get('#import-a').setValue(text);await button(w,'预检').trigger('click');await flushPromises()}
async function submit(w:VueWrapper,n:number){await button(w,`提交 ${n} 条`).trigger('click');await flushPromises()}
function line(w:VueWrapper,n:number){return w.get(`[data-line="${n}"]`)}
beforeEach(()=>{vi.useFakeTimers();hooks.generation=0;hooks.request.mockReset();i18n.global.locale.value='zh-CN';(state as any).user={name:'admin'};hooks.request.mockImplementation(async(path,init)=>path==='/templates'?[]:ok(body([path,init])))})
afterEach(()=>{wrappers.splice(0).forEach(w=>w.unmount());vi.useRealTimers()})
it('G3 no-template state; tabs retain input; C original expanded rows reach preview and receipt',async()=>{
  hooks.request.mockImplementation(async(path,init)=>path==='/templates'?[{id:'x',name:'T',body:'protocol=udp\naction=drop'}]:ok(body([path,init])))
  const w=await drawer();await w.get('#import-a').setValue('comment=kept');await button(w,'应急').trigger('click')
  await w.get('#import-targets').setValue('192.0.2.1');await button(w,'预检').trigger('click');await flushPromises()
  expect(w.text()).toContain('1 个目标 × 模板 2 行 = 2 条');expect(line(w,1).attributes('title')).toBe('dst_ip=192.0.2.1 protocol=udp')
  await submit(w,2);expect(line(w,1).attributes('title')).toBe('dst_ip=192.0.2.1 protocol=udp');expect(line(w,1).text()).toContain('已建')
  await button(w,'一行一条').trigger('click');expect((w.get('#import-a').element as HTMLTextAreaElement).value).toBe('comment=kept')
  await button(w,'应急').trigger('click');expect((w.get('#import-targets').element as HTMLTextAreaElement).value).toBe('192.0.2.1')
  hooks.request.mockResolvedValue([]);const empty=await drawer();await button(empty,'应急').trigger('click');expect(empty.text()).toContain('还没有模板')
})
it('G4 1201 rows sequential chunks; precheck batch refs map past blank/comment/lexical lines',async()=>{
  const second=defer();let n=0
  hooks.request.mockImplementation(async(path,init)=>{
    if(path==='/templates')return[]
    const items=body([path,init]);n++;if(n===2)return second.promise
    return ok(items)
  })
  const w=await drawer(),text=['','# comment','invalid=lex',...Array.from({length:1201},(_,i)=>'dst_port='+i)].join('\n')
  await check(w,text);expect(calls().map(c=>body(c).length)).toEqual([500,500]);expect(button(w,'提交 500 条').attributes('disabled')).toBeDefined()
  const result=ok(body(calls()[1]));(result.results[0] as any)={index:0,error:{code:'condition_capacity',message:'capacity',rule_ids:['batch:0']}}
  second.resolve(result);await flushPromises();expect(calls().map(c=>body(c).length)).toEqual([500,500,201])
  expect(line(w,504).text()).toContain('第 504 行');expect(line(w,3).text()).toContain('写法不对')
  expect(line(w,503).text()).toContain('新建');expect(line(w,505).text()).toContain('新建')
})
it('G4 V9c true submission batch zero maps to original line 502 after skipping 501',async()=>{
  let vn=0,wn=0
  hooks.request.mockImplementation(async(path,init)=>{
    if(path==='/templates')return[];const items=body([path,init]),result=ok(items)
    if(path.includes('validate')){vn++;if(vn===2)result.results[0]={index:0,existing:true,rule:{id:'stored'}}}
    else{wn++;if(wn===2)(result.results[0] as any)={index:0,error:{code:'condition_capacity',message:'capacity',rule_ids:['batch:0']}}}
    return result
  })
  const w=await drawer();await check(w,Array.from({length:502},(_,i)=>'dst_port='+i).join('\n'));await submit(w,501)
  expect(body(calls(true)[1])).toEqual([{dst_port:501}]);expect(line(w,501).text()).toContain('已存在，未提交')
  expect(line(w,502).text()).toContain('第 502 行');expect(line(w,502).text()).toContain('有错')
})
it('G4 V6 precheck whole-400 marks every row and disables submission',async()=>{
  hooks.request.mockImplementation(async path=>{if(path==='/templates')return[];throw new ApiError(400,{code:'bad_request',message:'decode'})})
  const w=await drawer();await check(w,'dst_port=1\ndst_port=2')
  expect(line(w,1).text()).toContain('这一片被拒');expect(line(w,2).text()).toContain('这一片被拒')
  expect(button(w,'提交 0 条').attributes('disabled')).toBeDefined();await button(w,'提交 0 条').trigger('click');expect(calls(true)).toHaveLength(0)
})
it('G4 V7 V20 network interruption makes current unknown and later unsent without request',async()=>{
  let wn=0
  hooks.request.mockImplementation(async(path,init)=>{if(path==='/templates')return[];const items=body([path,init]);if(!path.includes('validate')&&++wn===2)throw new TypeError('offline');return ok(items)})
  const w=await drawer();await check(w,Array.from({length:1201},(_,i)=>'dst_port='+i).join('\n'));await submit(w,1201)
  expect(calls(true).map(c=>body(c).length)).toEqual([500,500]);expect(line(w,500).text()).toContain('已建');expect(line(w,501).text()).toContain('结果未知');expect(line(w,1001).text()).toContain('未发送')
  await button(w,'只提交失败行').trigger('click');await flushPromises();const expected=Array.from({length:201},(_,i)=>'dst_port='+(i+1000)).join('\n')
  expect((w.get('#import-a').element as HTMLTextAreaElement).value).toBe(expected)
  expect(body(calls().at(-1))).toEqual(Array.from({length:201},(_,i)=>({dst_port:i+1000})))
  await submit(w,201);expect(body(calls(true).at(-1))).toEqual(Array.from({length:201},(_,i)=>({dst_port:i+1000})))
})
it('G4 V8 whole submission 400 continues next chunk; failed-only input validation and writes exclude successes',async()=>{
  let first=true,wn=0
  hooks.request.mockImplementation(async(path,init)=>{
    if(path==='/templates')return[];const items=body([path,init]),result=ok(items)
    if(!path.includes('validate')&&first){wn++;if(wn===1)throw new ApiError(400,{code:'bad_request',message:'decode'});(result.results[0] as any)={index:0,error:{code:'invalid_rule',message:'port out of range',field:'dst_port'}};first=false}
    return result
  })
  const w=await drawer();await check(w,Array.from({length:502},(_,i)=>'dst_port='+i).join('\n'));await submit(w,502)
  expect(calls(true)).toHaveLength(2);expect(line(w,1).text()).toContain('这一片被拒');expect(line(w,500).text()).toContain('这一片被拒');expect(line(w,501).text()).toContain('有错');expect(line(w,502).text()).toContain('已建')
  await button(w,'只提交失败行').trigger('click');await flushPromises()
  const expected=Array.from({length:501},(_,i)=>'dst_port='+i).join('\n');expect((w.get('#import-a').element as HTMLTextAreaElement).value).toBe(expected)
  expect(calls().slice(-2).flatMap(body)).toEqual(Array.from({length:501},(_,i)=>({dst_port:i})))
  await submit(w,501);expect(calls(true).slice(-2).flatMap(body)).toEqual(Array.from({length:501},(_,i)=>({dst_port:i})))
})
it('G5 V9 V9b skips stored permanent proposal and batch duplicate second; V22 racing existing receipt',async()=>{
  hooks.request.mockImplementation(async(path,init)=>{
    if(path==='/templates')return[];const items=body([path,init])
    if(path.includes('validate'))return{epoch:'fixture',results:[{index:0,existing:true,rule:{id:'stored'}},{index:1,existing:false,rule:{id:''}},{index:2,existing:true,rule:{id:''}},{index:3,existing:false,rule:{id:''}}]}
    return{epoch:'fixture',results:[{index:0,existing:false,rule:{id:'new'}},{index:1,existing:true,rule:{id:'raced'}}]}
  })
  const w=await drawer();await check(w,'dst_ip=192.0.2.1\ndst_ip=192.0.2.2\ndst_ip=192.0.2.2\ndst_ip=192.0.2.3')
  expect(line(w,1).text()).toContain('已存在，将跳过');expect(line(w,2).text()).toContain('新建');expect(line(w,3).text()).toContain('与本次导入前面的一行相同，将跳过')
  await submit(w,2);expect(body(calls(true)[0])).toEqual([{dst_ip:'192.0.2.2'},{dst_ip:'192.0.2.3'}])
  expect(line(w,1).text()).toContain('已存在，未提交');expect(line(w,3).text()).toContain('与前面的一行相同，未提交');expect(line(w,4).text()).toContain('已存在（期限按较晚者）')
})
it('G4 V14a stale sequence is discarded with current session',async()=>{
  const old=defer();let n=0;hooks.request.mockImplementation(async(path,init)=>path==='/templates'?[]:++n===1?old.promise:ok(body([path,init])))
  const w=await drawer();await check(w,'comment=old');await check(w,'comment=new');old.resolve({epoch:'fixture',results:[{index:0,existing:true,rule:{id:'stored'}}]});await flushPromises()
  expect(line(w,1).attributes('title')).toBe('comment=new');expect(line(w,1).text()).toContain('新建');expect(line(w,1).text()).not.toContain('已存在')
})
it('G4 V14b stale session is discarded with same sequence',async()=>{
  const reply=defer();hooks.request.mockImplementation(async path=>path==='/templates'?[]:reply.promise)
  const w=await drawer();await check(w,'comment=old');hooks.generation++;reply.resolve({epoch:'fixture',results:[{index:0,existing:true,rule:{id:'stored'}}]});await flushPromises()
  expect(line(w,1).text()).not.toContain('已存在');expect(button(w,'提交 0 条').attributes('disabled')).toBeDefined()
})
it('G4 V15 V21 precheck in-flight and edited input cannot submit; 600ms debounce',async()=>{
  const reply=defer();let n=0;hooks.request.mockImplementation(async(path,init)=>path==='/templates'?[]:++n===2?reply.promise:ok(body([path,init])))
  const w=await drawer();await check(w,'comment=first');expect(button(w,'提交 1 条').attributes('disabled')).toBeUndefined()
  await button(w,'预检').trigger('click');expect(button(w,'提交 0 条').attributes('disabled')).toBeDefined();await button(w,'提交 0 条').trigger('click');expect(calls(true)).toHaveLength(0)
  reply.resolve(ok([{comment:'first'}]));await flushPromises();await w.get('#import-a').setValue('comment=changed')
  expect(button(w,'提交 0 条').attributes('disabled')).toBeDefined();await button(w,'提交 0 条').trigger('click');expect(calls(true)).toHaveLength(0)
  await vi.advanceTimersByTimeAsync(599);expect(calls()).toHaveLength(2);await vi.advanceTimersByTimeAsync(1);await flushPromises();expect(body(calls()[2])).toEqual([{comment:'changed'}])
})
it('G4 close restores focus and drops in-flight work',async()=>{
  const trigger=document.createElement('button');document.body.append(trigger);trigger.focus();const reply=defer()
  hooks.request.mockImplementation(async path=>path==='/templates'?[]:reply.promise);const w=await drawer();await check(w,'comment=x')
  document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));expect(w.emitted('close')).toHaveLength(1);w.unmount();wrappers.splice(wrappers.indexOf(w),1);expect(document.activeElement).toBe(trigger)
  reply.resolve(ok([{}]));await nextTick();trigger.remove()
})

it('G4 reused RuleError real rule link returns to rule search',async()=>{
  const id='rule_'+'a'.repeat(32)
  hooks.request.mockImplementation(async path=>path==='/templates'?[]:{epoch:'fixture',results:[{index:0,error:{code:'rule_conflict',message:'conflict',rule_id:id}}]})
  const w=await drawer();await check(w,'dst_ip=192.0.2.1');await w.get('.text-btn').trigger('click')
  expect(w.emitted('search')).toEqual([[id]]);expect(w.emitted('close')).toHaveLength(1);expect(calls(true)).toHaveLength(0)
})
it('r1 V26 unsent precheck conflict retains original line reference after submission',async()=>{
  hooks.request.mockImplementation(async(path,init)=>{
    if(path==='/templates')return[]
    return path.includes('validate')?{epoch:'fixture',results:[{index:0,existing:false,rule:{id:''}},{index:1,error:{code:'rule_conflict',message:'conflict',rule_id:'batch:0'}}]}:ok(body([path,init]))
  })
  const w=await drawer();await check(w,'dst_ip=203.0.113.250 action=drop\ndst_ip=203.0.113.250 action=rate_limit rate_limit=123')
  expect(line(w,2).get('.rule-error').text()).toContain('第 1 行')
  await submit(w,1);expect(body(calls(true)[0])).toEqual([{dst_ip:'203.0.113.250',action:'drop'}])
  expect(line(w,1).text()).toContain('已建');expect(line(w,2).get('.rule-error').text()).toContain('第 1 行')
  expect(line(w,2).get('.rule-error').text()).not.toContain('本次提交的这一条')
})
it('r1 import preview renders raw markup as text without image elements',async()=>{
  hooks.request.mockImplementation(async path=>path==='/templates'?[]:{epoch:'fixture',results:[{index:0,error:{code:'invalid_rule',field:'tuple',message:'rule field combination is not recognized'}}]})
  const raw='comment="<img src=x>"',w=await drawer();await check(w,raw)
  expect(line(w,1).get('.import-raw').element.textContent).toBe(raw)
  expect(line(w,1).attributes('title')).toBe(raw);expect(w.get('table').element.querySelector('img')).toBeNull()
})
it('r1 V28 stale session during first submit stops the second chunk and receipt writes',async()=>{
  const reply=defer()
  hooks.request.mockImplementation(async(path,init)=>path==='/templates'?[]:path.includes('validate')?ok(body([path,init])):reply.promise)
  const w=await drawer();await check(w,Array.from({length:501},(_,i)=>'dst_port='+i).join('\n'))
  expect(calls().map(c=>body(c).length)).toEqual([500,1]);expect(button(w,'提交 501 条').attributes('disabled')).toBeUndefined()
  await submit(w,501);expect(calls(true)).toHaveLength(1);expect(body(calls(true)[0])).toHaveLength(500)
  hooks.generation++;reply.resolve(ok(body(calls(true)[0])));await flushPromises()
  expect(calls(true)).toHaveLength(1);expect(w.findAll('.import-status').some(s=>s.text()==='已建')).toBe(false)
})
