import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { nextTick } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { i18n, messages } from '../src/i18n'
import { ApiError, createClient } from '../src/api/client'
const hooks=vi.hoisted(()=>({request:vi.fn(),generation:0}))
vi.mock('../src/state',async()=>{const {reactive,computed}=await import('vue'),state=reactive({user:{name:'admin',role:'admin'} as any,nodes:[] as any[]});return{state,canSettings:computed(()=>state.user?.role==='admin'),request:hooks.request,captureSession:()=>{const g=hooks.generation;return{isCurrent:()=>g===hooks.generation}}}})
import { state } from '../src/state'
import { passwordOpen } from '../src/password'
import SettingsView from '../src/views/Settings.vue'
import NodesTab from '../src/components/settings/NodesTab.vue'
import UsersTab from '../src/components/settings/UsersTab.vue'
import KeysTab from '../src/components/settings/KeysTab.vue'
import SystemTab from '../src/components/settings/SystemTab.vue'
import TemplatesTab from '../src/components/settings/TemplatesTab.vue'
import ImportDrawer from '../src/components/ImportDrawer.vue'
const wrappers:VueWrapper[]=[]
const defer=()=>{let resolve!:(v:any)=>void,reject!:(e:any)=>void;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{resolve,reject,promise}}
const key='xdk_'+'0'.repeat(16)+'_'+'A'.repeat(43)
const issued=()=>({id:'issued',name:'fresh',key,created_at:'2026-10-17T00:00:00Z',retired:[]})
const user=(username='operator')=>({username,role:'operator',created_at:'2026-10-01T00:00:00Z',created_by:'user:admin',password_changed_at:'2026-10-16T00:00:00Z'})
const users=()=>[{...user('admin'),role:'admin'},user('Admin'),user()]
const credential=(id:string,name='xsight',patch:any={})=>({id,name,created_at:'2026-10-01T00:00:00Z',created_by:'user:admin',retire_at:null,revoked_at:null,revoked_by:null,active:true,...patch})
const credentials=()=>[credential('x1','xsight',{retire_at:'2026-10-18T00:00:00Z'}),credential('x2','xsight',{created_at:'2026-10-02T00:00:00Z'}),credential('x0','xsight',{active:false,revoked_at:'2026-10-04T00:00:00Z',created_at:'2026-10-03T00:00:00Z'}),credential('m','monitor'),credential('o1','old',{active:false}),credential('o2','old',{active:false}),credential('l','lone',{retire_at:'2026-10-18T00:00:00Z'})]
const system=()=>({session_hours:12,audit_retention_days:180,history_retention_days:30,reconcile_interval_minutes:15,default_language:'en-US'})
const template=(name='Template')=>({id:'template-id',name,body:'\n# comment\n protocol=udp \n\naction=drop',created_at:'2026-10-01T00:00:00Z',created_by:'user:admin',updated_at:'2026-10-16T00:00:00Z',updated_by:'user:operator'})
const node=(name='edge 01#a')=>({name,base_url:'http://192.0.2.1',key_unreadable:false,online:true,incompatible:false,rules:{state:'normal',reason:'',confirmed_gen:1,confirmable:true,rejected:[]},whitelist:{state:'normal',reason:'',confirmed_gen:1,confirmable:true,rejected:[]},health_at:'',health:{rules_synced:true,whitelist_synced:true},rates:null,stats:null})
const fixture=(path:string)=>({'/users':users(),'/credentials':credentials(),'/settings':system(),'/templates':[template()]}[path])
const component={users:UsersTab,keys:KeysTab,system:SystemTab,templates:TemplatesTab}
const endpoint={users:'/users',keys:'/credentials',system:'/settings',templates:'/templates'}
type Tab=keyof typeof component
const reads=(path:string)=>hooks.request.mock.calls.filter(c=>c[0]===path&&!c[1]?.method)
const writes=()=>hooks.request.mock.calls.filter(c=>c[1]?.method)
const body=(c:any)=>JSON.parse(c[1].body)
function button(w:any,text:string){const b=w.findAll('button').find((b:any)=>b.text()===text);expect(b,`button ${text}`).toBeDefined();return b!}
async function click(w:any,text:string){await button(w,text).trigger('click');await flushPromises()}
async function view(c:any){const w=mount(c,{global:{plugins:[i18n]},attachTo:document.body});wrappers.push(w);await flushPromises();return w}
async function fill(w:VueWrapper,values:Record<string,string>){for(const [name,value]of Object.entries(values))await w.get(`[name="${name}"]`).setValue(value)}
async function createKey(w:VueWrapper){await click(w,'发放 API 密钥');await fill(w,{name:'fresh'});await w.get('form').trigger('submit');await flushPromises()}
async function writeTab(w:VueWrapper,tab:Tab){
  if(tab==='users'){await click(w,'添加用户');await fill(w,{username:'new-user',password:'example-password-1',again:'example-password-1'})}
  if(tab==='templates'){await click(w,'新建模板');await fill(w,{name:'New',body:'protocol=udp'})}
  if(tab==='keys'){await click(w.get('[data-row="xsight"]'),'轮换');await click(w.get('.confirm'),'轮换');return}
  if(tab==='system')await w.get('#setting-audit_retention_days').setValue('365')
  await w.get('form').trigger('submit');await flushPromises()
}
beforeEach(()=>{hooks.generation=0;hooks.request.mockReset();hooks.request.mockImplementation(async(path,init)=>init?.method?path==='/credentials'?issued():path==='/settings'?system():undefined:fixture(path));state.user={name:'admin',role:'admin'};state.nodes=[node()];passwordOpen.value=false;i18n.global.locale.value='zh-CN';localStorage.clear();sessionStorage.clear()})
afterEach(()=>{wrappers.splice(0).forEach(w=>{if(w.exists())w.unmount()});vi.restoreAllMocks();document.body.innerHTML='';window.getSelection()?.removeAllRanges()})
it('G2 five tabs switch aria selection and unmount old content; default nodes on entry',async()=>{
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/settings',component:SettingsView},{path:'/overview',component:{template:'<div />'}}]});await router.push('/settings')
  const w=mount(SettingsView,{global:{plugins:[i18n,router]}});wrappers.push(w);expect(w.findAll('[role="tab"]')).toHaveLength(5)
  await click(w,'用户');expect(w.find('[data-tab="nodes"]').exists()).toBe(false);expect(button(w,'用户').attributes('aria-selected')).toBe('true')
  await click(w,'API 密钥');await createKey(w);expect(w.text()).toContain(key);await click(w,'系统');expect(w.text()).not.toContain(key)
  await click(w,'API 密钥');expect(w.text()).not.toContain(key);expect(w.find('[data-key-panel]').exists()).toBe(false)
})
it('G2 V29 resident demotion removes tab and management DOM on same instance without navigation',async()=>{
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/settings',component:SettingsView},{path:'/overview',component:{template:'<div />'}}]});await router.push('/settings')
  const replace=vi.spyOn(router,'replace').mockResolvedValue(undefined),w=mount(SettingsView,{global:{plugins:[router,i18n]}});wrappers.push(w);const instance=w.vm
  state.user={name:'admin',role:'operator'};await nextTick();expect(w.vm).toBe(instance);expect(router.currentRoute.value.path).toBe('/settings');expect(replace).toHaveBeenCalledWith('/overview')
  expect(w.find('[role="tablist"]').exists()).toBe(false);expect(w.findAll('button')).toHaveLength(0);expect(w.find('[data-tab]').exists()).toBe(false)
})
it('G2 resident demotion navigates with real router',async()=>{
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/settings',component:SettingsView},{path:'/overview',component:{template:'<div />'}}]});await router.push('/settings')
  const w=mount(SettingsView,{global:{plugins:[router,i18n]}});wrappers.push(w);state.user={name:'admin',role:'operator'};await flushPromises();expect(router.currentRoute.value.path).toBe('/overview')
})
it('G3 V24 SSE nodes appear without GET; empty URL and unreadable key disable empty edit',async()=>{
  state.nodes=[];const w=await view(NodesTab);state.nodes=[{...node(),base_url:'',key_unreadable:true}];await nextTick();expect(hooks.request).not.toHaveBeenCalled();expect(w.get('[data-row]').text()).toContain('—');expect(w.text()).toContain('无法读取')
  await click(w,'编辑');expect(button(w,'保存').attributes('disabled')).toBeDefined();await fill(w,{base_url:'http://192.0.2.2'});expect(button(w,'保存').attributes('disabled')).toBeDefined()
  await fill(w,{api_key:'example-node-key-1'});expect(button(w,'保存').attributes('disabled')).toBeUndefined()
})
it('G3 add fields preserve whitespace; empty fields block both buttons; success clears and closes',async()=>{
  const w=await view(NodesTab);await click(w,'添加节点')
  for(const values of [{name:'',base_url:'http://192.0.2.1',api_key:'example-node-key-1'},{name:' edge ',base_url:'',api_key:'example-node-key-1'},{name:' edge ',base_url:' http://192.0.2.1 ',api_key:''}]){
    await fill(w,values);expect(button(w,'保存').attributes('disabled')).toBeDefined();expect(button(w,'测试连接').attributes('disabled')).toBeDefined()
  }
  await fill(w,{name:' edge ',base_url:' http://192.0.2.1 ',api_key:' example-node-key-1 '});await w.get('form').trigger('submit');await flushPromises()
  expect(writes()).toHaveLength(1);expect(writes()[0]![0]).toBe('/nodes');expect(body(writes()[0])).toEqual({name:' edge ',base_url:' http://192.0.2.1 ',api_key:' example-node-key-1 '});expect(w.find('form').exists()).toBe(false)
  await click(w,'添加节点');for(const input of w.findAll('input'))expect((input.element as HTMLInputElement).value).toBe('')
})
it.each(['contract','V21 no name','V22 no api_key'])('G3 node address-only edit %s',async(kind)=>{
  const w=await view(NodesTab);await click(w,'编辑');expect(button(w,'保存').attributes('disabled')).toBeDefined();await fill(w,{base_url:'http://192.0.2.2'});await w.get('form').trigger('submit');await flushPromises();const sent=body(writes()[0])
  if(kind==='contract')expect(sent).toEqual({base_url:'http://192.0.2.2'})
  if(kind==='V21 no name')expect('name' in sent).toBe(false)
  if(kind==='V22 no api_key')expect('api_key' in sent).toBe(false)
})
it('G3 edit key only sends api_key',async()=>{const w=await view(NodesTab);await click(w,'编辑');await fill(w,{api_key:'example-node-key-1'});await w.get('form').trigger('submit');await flushPromises();expect(body(writes()[0])).toEqual({api_key:'example-node-key-1'})})
it('G3 test results three text indicators; message title only; one in flight',async()=>{
  const pending=defer();hooks.request.mockReturnValue(pending.promise);state.nodes=[node(),node('edge-02')];const w=await view(NodesTab);await click(w.get('[data-row="edge 01#a"]'),'测试')
  expect(button(w.get('[data-row="edge-02"]'),'测试').attributes('disabled')).toBeDefined();expect(hooks.request).toHaveBeenCalledTimes(1)
  pending.resolve({reachable:true,compatible:false,key_accepted:true,message:'fixture-detail'});await flushPromises();expect(w.get('[data-result]').text()).toContain('可达 ✓');expect(w.get('[data-result]').text()).toContain('兼容 ✗');expect(w.get('[data-result]').text()).toContain('密钥 ✓');expect(w.get('[data-result]').attributes('title')).toBe('fixture-detail');expect(w.text()).not.toContain('fixture-detail')
})
it('G3 add test sends only address and key and shows unreachable state',async()=>{
  hooks.request.mockResolvedValue({reachable:false,compatible:false,key_accepted:false,message:'offline'});const w=await view(NodesTab);await click(w,'添加节点');await fill(w,{name:'new',base_url:'http://192.0.2.1',api_key:'example-node-key-1'});await click(w,'测试连接');expect(writes()[0]![0]).toBe('/nodes/test');expect(body(writes()[0])).toEqual({base_url:'http://192.0.2.1',api_key:'example-node-key-1'});expect(w.get('[data-result]').text()).toContain('可达 ✗')
})
it('G3 V30 all named node paths encode edge 01#a; stop cancellation sends zero',async()=>{
  hooks.request.mockResolvedValue({reachable:true,compatible:true,key_accepted:true,message:''});const w=await view(NodesTab)
  await click(w,'停止管理');await click(w.get('.confirm'),'取消');expect(hooks.request).not.toHaveBeenCalled()
  await click(w,'停止管理');await click(w.get('.confirm'),'停止管理');await click(w,'编辑');await fill(w,{api_key:'example-node-key-1'});await w.get('form').trigger('submit');await flushPromises();await click(w,'测试')
  expect(writes().map(c=>[c[0],c[1].method])).toEqual([['/nodes/edge%2001%23a','DELETE'],['/nodes/edge%2001%23a','PATCH'],['/nodes/edge%2001%23a/test','POST']])
})
it('G2 V27n node late write retains original mounted form fields and busy state',async()=>{
  const pending=defer();hooks.request.mockReturnValue(pending.promise);const w=await view(NodesTab);await click(w,'添加节点');await fill(w,{name:'new',base_url:'http://192.0.2.2',api_key:'example-node-key-1'});await w.get('form').trigger('submit');const instance=w.vm
  hooks.generation++;expect(w.exists()).toBe(true);pending.resolve({name:'new',base_url:'http://192.0.2.2'});await flushPromises();expect(w.vm).toBe(instance);expect((w.get('[name="name"]').element as HTMLInputElement).value).toBe('new');expect(button(w,'保存').attributes('aria-busy')).toBe('true')
})
it('G4 V1 V3 own row only opens existing password drawer with no request',async()=>{
  const w=await view(UsersTab),row=w.get('[data-row="admin"]'),before=hooks.request.mock.calls.length
  expect(row.findAll('button').map(b=>b.text())).toEqual(['改密码']);expect(row.text()).not.toMatch(/删除|改角色|重置/)
  await click(row,'改密码');expect(passwordOpen.value).toBe(true);expect(hooks.request).toHaveBeenCalledTimes(before)
})
it('G4 V2 Admin is another user with all three actions',async()=>{const w=await view(UsersTab);expect(w.get('[data-row="Admin"]').findAll('button').map(b=>b.text())).toEqual(['改密码','改角色','删除'])})
it('G4 add 201 empty body closes and reloads through real client parser',async()=>{
  const transport=vi.fn(async(_path:any,init:any)=>init?.method==='POST'?new Response('',{status:201}):Response.json(users()))
  hooks.request.mockImplementation(createClient({expired:vi.fn(),demoted:vi.fn()},transport));const w=await view(UsersTab);await writeTab(w,'users')
  expect(w.find('form').exists()).toBe(false);expect(reads('/users')).toHaveLength(2);expect(body(writes()[0])).toEqual({username:'new-user',password:'example-password-1',role:'operator'})
})
it('G4 mismatched passwords send no request; reset original bytes and notice survives reload until next action',async()=>{
  const w=await view(UsersTab);await click(w.get('[data-row="operator"]'),'改密码');await fill(w,{password:'example-password-1',again:'example-password-2'});await w.get('form').trigger('submit');await flushPromises();expect(writes()).toHaveLength(0);expect(w.text()).toContain('两次输入的新密码不一样')
  await fill(w,{password:' example-password-2 ',again:' example-password-2 '});await w.get('form').trigger('submit');await flushPromises();expect(writes()[0]![0]).toBe('/users/operator/password');expect(writes()[0]![1].method).toBe('PUT');expect(body(writes()[0])).toEqual({password:' example-password-2 '});expect(w.text()).toContain('已重置，该用户需重新登录')
  await click(w,'刷新');expect(w.text()).not.toContain('已重置，该用户需重新登录')
})
it('G4 other role and deletion use exact contracts; only one confirmation',async()=>{
  const w=await view(UsersTab);await click(w.get('[data-row="operator"]'),'改角色');await click(w.get('[data-row="Admin"]'),'删除');expect(w.findAll('.confirm')).toHaveLength(1);await click(w.get('.confirm'),'取消');expect(writes()).toHaveLength(0)
  await click(w.get('[data-row="operator"]'),'改角色');await click(w.get('.confirm'),'改角色');expect(writes()[0]![0]).toBe('/users/operator/role');expect(writes()[0]![1].method).toBe('PUT');expect(body(writes()[0])).toEqual({role:'admin'})
  await click(w.get('[data-row="Admin"]'),'删除');await click(w.get('.confirm'),'删除');expect(writes()[1]![0]).toBe('/users/Admin');expect(writes()[1]![1].method).toBe('DELETE')
})
it('G5 V5 V6 group rows states and latest active timestamp',async()=>{
  const w=await view(KeysTab);expect(w.findAll('[data-row]').map(r=>r.attributes('data-row'))).toEqual(['lone','monitor','xsight'])
  expect(w.get('[data-row="lone"]').text()).toContain('即将失效');expect(w.get('[data-row="monitor"]').text()).toContain('正常');expect(w.get('[data-row="xsight"]').text()).toContain('轮换中');expect(w.get('[data-row="xsight"] td.num').attributes('title')).toBe('2026-10-02T00:00:00Z')
})
it('G5 V7 existing name blocks issuance',async()=>{
  const w=await view(KeysTab);await click(w,'发放 API 密钥');await fill(w,{name:'xsight'});await w.get('form').trigger('submit');await flushPromises();expect(writes()).toHaveLength(0);expect(w.text()).toContain('已有同名密钥；要换新密钥请用该行的『轮换』')
})
it('G5 fresh issuance and rotation use names; panel displays returned key',async()=>{
  const w=await view(KeysTab);await createKey(w);expect(body(writes()[0])).toEqual({name:'fresh'});expect(w.get('.keybox').text()).toBe(key)
  await click(w.get('[data-row="xsight"]'),'轮换');await click(w.get('.confirm:not([data-key-panel])'),'轮换');expect(body(writes()[1])).toEqual({name:'xsight'})
})
it.each(['contract','V8 two active only','V9 revoked excluded'])('G5 revoke %s',async(kind)=>{
  if(kind==='V8 two active only')hooks.request.mockImplementation(async(_p,init)=>init?.method?undefined:credentials().filter(c=>c.name==='xsight'&&c.active))
  const w=await view(KeysTab);await click(w.get('[data-row="xsight"]'),'吊销');await click(w.get('.confirm'),'吊销');const ids=writes().map(c=>c[0])
  if(kind!=='V9 revoked excluded')expect(ids).toEqual(['/credentials/x1','/credentials/x2'])
  if(kind==='V9 revoked excluded')expect(ids).not.toContain('/credentials/x0')
})
it('G5 V10 missing credential continues; later 503 stops and reloads remaining state',async()=>{
  let phase=0;hooks.request.mockImplementation(async(path,init)=>{if(!init?.method)return phase? [credential('x2'),credential('x3')]:[credential('x1'),credential('x2'),credential('x3')];phase++;throw new ApiError(path.endsWith('x1')?404:503,{code:path.endsWith('x1')?'credential_not_found':'unavailable',message:''})})
  const w=await view(KeysTab);await click(w.get('[data-row="xsight"]'),'吊销');await click(w.get('.confirm'),'吊销');expect(writes().map(c=>c[0])).toEqual(['/credentials/x1','/credentials/x2']);expect(reads('/credentials')).toHaveLength(2);expect(w.text()).toContain('操作失败');expect((w.vm as any).rows[0].active.map((c:any)=>c.id)).toEqual(['x2','x3'])
})
it.each(['pending','failed','post pending','latest failed'])('G5 V31 V31b issuance unavailable %s',async(mode)=>{
  const pending=defer();let count=0
  hooks.request.mockImplementation(async(path,init)=>{if(init?.method)return issued();count++;if((mode==='pending'&&count===1)||(mode==='post pending'&&count===2))return pending.promise;if(mode==='failed'||(mode==='latest failed'&&count===2))throw new TypeError('offline');return credentials()})
  const w=await view(KeysTab);if(mode==='post pending')await createKey(w);if(mode==='latest failed')await click(w,'刷新');await click(w,'发放 API 密钥');await fill(w,{name:'brand-new'});const before=writes().length
  expect(button(w,'发放').attributes('aria-busy')).toBe('false');expect(button(w,'发放').attributes('disabled')).toBeDefined();await w.get('form').trigger('submit');await flushPromises();expect(writes()).toHaveLength(before)
})
it('G5 V11 closing clears the only plaintext ref',async()=>{const w=await view(KeysTab);await createKey(w);await click(w,'我已保存');expect(w.text()).not.toContain(key);expect((w.vm as any).plaintext).toBe('');expect(w.find('[data-key-panel]').exists()).toBe(false)})
it('G5 V12 standalone key panel clears on null user while same instance stays mounted',async()=>{const w=await view(KeysTab);await createKey(w);const instance=w.vm;state.user=null;await nextTick();expect(w.vm).toBe(instance);expect(w.exists()).toBe(true);expect(w.text()).not.toContain(key);expect((w.vm as any).plaintext).toBe('')})
it('G5 V13 all storage keys values URL console and attributes exclude plaintext',async()=>{
  const spies=['log','info','warn','error','debug'].map(name=>vi.spyOn(console,name as 'log').mockImplementation(()=>{}));localStorage.setItem('xd.lang','zh-CN');sessionStorage.setItem('fixture','safe')
  const w=await view(KeysTab);await createKey(w)
  expect(w.find('[data-key-panel]').exists()).toBe(true);expect(w.get('.keybox').text()).toBe(key)
  for(const storage of [localStorage,sessionStorage])for(let i=0;i<storage.length;i++){const name=storage.key(i)!;expect(name).not.toContain(key);expect(storage.getItem(name)).not.toContain(key)}
  expect(location.href).not.toContain(key);for(const spy of spies)expect(JSON.stringify(spy.mock.calls)).not.toContain(key)
  for(const el of w.findAll('[title],[aria-label]'))expect(JSON.stringify(el.attributes())).not.toContain(key)
  for(const el of document.querySelectorAll('*'))for(const name of el.getAttributeNames())expect(el.getAttribute(name)).not.toContain(key)
})
it.each([false,true])('G5 clipboard rejection %s',async(reject)=>{
  const writeText=vi.fn(()=>reject?Promise.reject(new Error('denied')):Promise.resolve());Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText}})
  const w=await view(KeysTab);await createKey(w);await click(w,'复制');expect(writeText).toHaveBeenCalledWith(key)
  if(reject){expect(w.text()).toContain('请手动复制');expect(window.getSelection()?.toString()).toBe(key)}else expect(w.text()).not.toContain('请手动复制')
})
it('G6 V15 V16 five settings preserve custom value three languages defaults and four tooltips',async()=>{
  const w=await view(SystemTab);expect(w.findAll('select')).toHaveLength(5);expect((w.get('#setting-session_hours').element as HTMLSelectElement).value).toBe('12');expect(w.get('#setting-session_hours').text()).toContain('12 小时');expect(w.get('#setting-language').findAll('option')).toHaveLength(3);expect(w.text()).not.toContain('跟随浏览器');expect(w.findAll('.tip')).toHaveLength(4);expect(w.text()).toContain('24 小时（默认）');expect(button(w,'保存').attributes('disabled')).toBeDefined()
})
it('G6 V14 single changed key exact PUT; response refills form and saved clears on next change',async()=>{
  const refreshed={...system(),audit_retention_days:90};let changed=false;hooks.request.mockImplementation(async(_p,init)=>{if(init?.method){changed=true;return refreshed}return changed?refreshed:system()})
  const w=await view(SystemTab);await w.get('#setting-audit_retention_days').setValue('365');await w.get('form').trigger('submit');await flushPromises();expect(writes()[0]![1].method).toBe('PUT');expect(body(writes()[0])).toEqual({audit_retention_days:365});expect((w.get('#setting-audit_retention_days').element as HTMLSelectElement).value).toBe('90');expect(w.text()).toContain('已保存');await w.get('#setting-session_hours').setValue('24');expect(w.text()).not.toContain('已保存')
})
it('G6 field range error belongs to its row',async()=>{hooks.request.mockImplementation(async(_p,init)=>{if(init?.method)throw new ApiError(400,{code:'invalid_field',field:'audit_retention_days',message:''});return system()});const w=await view(SystemTab);await writeTab(w,'system');expect(w.get('[data-field="audit_retention_days"]').text()).toContain('超出允许范围');expect(w.get('[data-field="session_hours"]').text()).not.toContain('超出允许范围')})
it('G6 V37 automatic reload preserves edits made after successful save and submits only their delta',async()=>{
  const pending=defer(),saved={...system(),audit_retention_days:365};let readCount=0
  hooks.request.mockImplementation(async(_path,init)=>init?.method?saved:++readCount===1?system():pending.promise)
  const w=await view(SystemTab);await writeTab(w,'system');expect(writes()).toHaveLength(1);expect(reads('/settings')).toHaveLength(2)
  expect((w.get('#setting-audit_retention_days').element as HTMLSelectElement).value).toBe('365');expect((w.vm as any).writing).toBe(false);expect((w.vm as any).loading).toBe(true)
  await w.get('#setting-session_hours').setValue('72');pending.resolve({...saved});await flushPromises()
  expect((w.get('#setting-session_hours').element as HTMLSelectElement).value).toBe('72');expect(button(w,'保存').attributes('disabled')).toBeUndefined()
  await w.get('form').trigger('submit');await flushPromises();expect(writes()).toHaveLength(2);expect(writes()[1]![1].method).toBe('PUT');expect(body(writes()[1])).toEqual({session_hours:72})
})
it('G7 V17 template rename PUT retains entire nonempty body; count and time titles',async()=>{
  const w=await view(TemplatesTab);expect(w.get('[data-row] td.num').text()).toBe('2');expect(w.get('[data-row] td[title]').attributes('title')).toBe(template().updated_at);expect(w.get('[data-row] td[title] span').attributes('title')).toBe('user:operator')
  await click(w,'编辑');await fill(w,{name:' Renamed '});await w.get('form').trigger('submit');await flushPromises();expect(writes()[0]![0]).toBe('/templates/template-id');expect(writes()[0]![1].method).toBe('PUT');expect(body(writes()[0])).toEqual({name:' Renamed ',body:template().body})
})
it('G7 create and freshly mounted import C share template response',async()=>{
  let rows=[template()];hooks.request.mockImplementation(async(path,init)=>{if(path==='/templates'&&init?.method){rows.push({...template('Created'),id:'created-id',...JSON.parse(init.body)});return rows.at(-1)}return rows})
  const w=await view(TemplatesTab);await click(w,'新建模板');await fill(w,{name:'Created',body:' protocol=udp '});await w.get('form').trigger('submit');await flushPromises();expect(writes()[0]![1].method).toBe('POST');expect(body(writes()[0])).toEqual({name:'Created',body:' protocol=udp '});const drawer=await view(ImportDrawer);await click(drawer,'应急');expect(drawer.findAll('option').some(o=>o.text()==='Created')).toBe(true)
})
it('G7 lexical precheck original line number and target block save',async()=>{
  const w=await view(TemplatesTab);await click(w,'新建模板');await fill(w,{name:'New',body:'\n# ignored\n\ninvalid=bad'});expect(w.text()).toContain('第 4 行写法不对');expect(button(w,'保存').attributes('disabled')).toBeDefined();await w.get('form').trigger('submit');expect(writes()).toHaveLength(0)
  await fill(w,{body:'\n# ignored\ndst_ip=192.0.2.1'});expect(w.text()).toContain('第 3 行不要写目标地址，目标在导入时填');expect(button(w,'保存').attributes('disabled')).toBeDefined()
})
it('G7 V32 delete uses id different from name; cancellation sends zero',async()=>{const w=await view(TemplatesTab);await click(w,'删除');await click(w.get('.confirm'),'取消');expect(writes()).toHaveLength(0);await click(w,'删除');await click(w.get('.confirm'),'删除');expect(writes()[0]![0]).toBe('/templates/template-id');expect(writes()[0]![1].method).toBe('DELETE')})
for(const tab of Object.keys(component) as Tab[]){
  it(`G2 ${tab} V25 old sequence current session cannot replace newer write reload`,async()=>{
    const pending=defer();let count=0;const before=fixture(endpoint[tab]),after=tab==='system'?{...system(),audit_retention_days:90}:tab==='users'?[user('Newer')]:tab==='keys'?[credential('newer','Newer')]:[template('Newer')]
    hooks.request.mockImplementation(async(path,init)=>{if(init?.method)return tab==='system'?after:tab==='keys'?issued():undefined;count++;return count===2?pending.promise:count===1?before:after})
    const w=await view(component[tab]);await click(w,'刷新');await writeTab(w,tab);expect(reads(endpoint[tab])).toHaveLength(3);pending.resolve(before);await flushPromises();expect(hooks.generation).toBe(0)
    if(tab==='system')expect((w.get('#setting-audit_retention_days').element as HTMLSelectElement).value).toBe('90');else{expect(w.text()).toContain('Newer');expect(w.text()).not.toContain(tab==='users'?'operator':tab==='keys'?'xsight':'Template')}
  })
  it(`G2 ${tab} V26 old session current sequence discards read on same mounted instance`,async()=>{
    const pending=defer();const w=await view(component[tab]),instance=w.vm,prior=w.html();hooks.request.mockReturnValue(pending.promise);await click(w,'刷新');const requestCount=hooks.request.mock.calls.length
    hooks.generation++;pending.resolve(tab==='system'?{...system(),session_hours:72}:tab==='users'?[user('Late')]:tab==='keys'?[credential('late','Late')]:[template('Late')]);await flushPromises()
    expect(w.vm).toBe(instance);expect(w.exists()).toBe(true);expect(hooks.request).toHaveBeenCalledTimes(requestCount);expect((w.vm as any).loading).toBe(true);expect(w.text()).not.toContain('Late');expect(prior).not.toContain('Late')
    if(tab==='system')expect((w.get('#setting-session_hours').element as HTMLSelectElement).value).toBe('12')
  })
  it(`G2 ${tab} V27 stale write cannot reload or show success on same instance`,async()=>{
    const pending=defer();const w=await view(component[tab]),instance=w.vm;hooks.request.mockImplementation(async(path,init)=>init?.method?pending.promise:fixture(path));await writeTab(w,tab);const count=hooks.request.mock.calls.length
    hooks.generation++;pending.resolve(tab==='system'?system():tab==='keys'?issued():undefined);await flushPromises();expect(w.vm).toBe(instance);expect(w.exists()).toBe(true);expect(hooks.request).toHaveBeenCalledTimes(count);expect((w.vm as any).writing).toBe(true);expect(w.text()).not.toContain('已保存');expect(w.text()).not.toContain('已重置，该用户需重新登录');expect(w.text()).not.toContain(key)
  })
  it(`G2 ${tab} unmounted read and write retain held instance without reload`,async()=>{
    const pending=defer();const w=await view(component[tab]);hooks.request.mockReturnValue(pending.promise);await writeTab(w,tab);const held=w.vm as any,count=hooks.request.mock.calls.length;w.unmount();pending.resolve(tab==='system'?system():tab==='keys'?issued():undefined);await flushPromises();expect(hooks.request).toHaveBeenCalledTimes(count);expect(held.writing).toBe(true)
    hooks.request.mockImplementation(async path=>fixture(path));const second=await view(component[tab]),late=defer(),old=second.vm as any,oldRows=old.rows??old.data;hooks.request.mockReturnValue(late.promise);await click(second,'刷新');second.unmount();late.resolve([]);await flushPromises();expect(old.rows??old.data).toEqual(oldRows);expect(old.loading).toBe(true)
  })
  it(`G2 ${tab} failed refresh retains rows and renders generic field error`,async()=>{
    const w=await view(component[tab]);const text=w.text();hooks.request.mockRejectedValue(new ApiError(400,{code:'invalid_field',field:'conditions',message:''}));await click(w,'刷新');expect(w.text()).toContain('字段内容有误')
    const ruleTexts=Object.values(messages['zh-CN'].ruleErrors);for(const value of ruleTexts)if(typeof value==='string'&&!value.includes('{'))expect(w.text()).not.toContain(value)
    if(tab!=='system')expect(w.text()).toContain(tab==='users'?'operator':tab==='keys'?'xsight':'Template');else expect(w.findAll('select')).toHaveLength(5);expect(text).not.toContain('字段内容有误')
  })
}
it('G2 keys V36 stale session during first revoke stops second DELETE and retains mounted confirmation busy state',async()=>{
  const pending=defer();hooks.request.mockImplementation(async(_path,init)=>init?.method?pending.promise:[credential('x1'),credential('x2')])
  const w=await view(KeysTab),instance=w.vm;await click(w.get('[data-row="xsight"]'),'吊销');await click(w.get('.confirm'),'吊销')
  expect(writes().map(c=>[c[0],c[1].method])).toEqual([['/credentials/x1','DELETE']]);expect((w.vm as any).writing).toBe(true)
  const confirmation=w.get('.confirm').html(),requestCount=hooks.request.mock.calls.length,readCount=reads('/credentials').length
  hooks.generation++;pending.resolve(undefined);await flushPromises()
  expect(w.vm).toBe(instance);expect(w.exists()).toBe(true);expect(state.user?.role).toBe('admin')
  expect(writes().map(c=>[c[0],c[1].method])).toEqual([['/credentials/x1','DELETE']]);expect(hooks.request).toHaveBeenCalledTimes(requestCount);expect(reads('/credentials')).toHaveLength(readCount)
  expect(w.get('.confirm').html()).toBe(confirmation);expect((w.vm as any).confirmation).toBe('revoke');expect((w.vm as any).writing).toBe(true);expect(button(w.get('.confirm'),'吊销').attributes('aria-busy')).toBe('true')
})
it.each([
  ['users','invalid_field','username','用户名只能用字母、数字和 . _ -，最长 64 个'],['users','invalid_field','password','新密码长度不对'],
  ['users','user_exists','','用户已存在'],['users','last_user','','至少保留一名用户'],['users','last_admin','','至少保留一名管理员'],['users','user_not_found','','用户不存在'],
  ['templates','rule_conflict','','已有同名模板'],['templates','table_full','','模板已满（最多 100 个）'],['templates','not_found','','这个模板已被删除'],['templates','invalid_field','name','名称 1 到 64 个字'],['templates','invalid_field','body','内容太长（最多 64 KB）'],
])('G4 G7 inline error %s %s %s',async(tab,code,field,text)=>{
  hooks.request.mockImplementation(async(path,init)=>{if(init?.method)throw new ApiError(400,{code,field,message:'',...{table:'templates'}});return fixture(path)})
  const w=await view(component[tab as Tab]);await writeTab(w,tab as Tab);expect(w.get('[role="alert"]').text()).toContain(text!);if(code==='not_found')expect(reads('/templates')).toHaveLength(2)
})
it.each(['users','keys','system','templates'] as Tab[])('G2 %s in-flight duplicate submission sends one write',async(tab)=>{
  const w=await view(component[tab]),pending=defer();hooks.request.mockImplementation(async(path,init)=>init?.method?pending.promise:fixture(path));await writeTab(w,tab);const before=writes().length
  if(tab==='keys')await click(w.get('.confirm'),'轮换');else await w.get('form').trigger('submit');await flushPromises();expect(writes()).toHaveLength(before);expect(before).toBe(1)
})

it.each([['users', UsersTab], ['system', SystemTab], ['keys', KeysTab]] as const)('G5-G6 %s tooltip opens on its existing trigger',async(kind,c)=>{
  const w=await view(c),trigger=kind==='keys'?w.get('[data-row="xsight"] .pill'):w.get('.tip')
  await trigger.trigger('click');await flushPromises();await new Promise(resolve=>setTimeout(resolve,20));await flushPromises()
  const text=kind==='keys'?'旧密钥':kind==='users'?'管理员：节点、用户、API 密钥、系统设置。':'改短后，已登录的会话按新时长计算'
  expect(document.body.querySelector('[role="tooltip"]')?.textContent).toContain(text)
  if(kind==='system')expect(w.findAllComponents({name:'ElTooltip'}).map(tip=>tip.props('content'))).toEqual([messages['zh-CN'].settingsUI.sessionHelp,messages['zh-CN'].settingsUI.reconcileHelp,messages['zh-CN'].settingsUI.historyHelp,messages['zh-CN'].settingsUI.languageHelp])
})
