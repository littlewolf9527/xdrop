// @vitest-environment node
import { it, expect, beforeEach, afterEach } from 'vitest'
import { mockPlugin } from '../mock/server'
const httpModule='node:http',http=await import(httpModule)
let server:any,handler:any,base='',cookie=''
beforeEach(async()=>{
  server=http.createServer((req:any,res:any)=>handler(req,res,()=>{res.statusCode=404;res.end()}))
  ;(mockPlugin().configureServer as any)({httpServer:server,middlewares:{use:(h:any)=>{handler=h}}})
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));base='http://127.0.0.1:'+server.address().port;await login('admin')
})
afterEach(async()=>{server.closeAllConnections();await new Promise<void>(resolve=>server.close(resolve))})
async function api(path:string,body?:unknown,method=body?'POST':'GET'){const r=await fetch(base+(path.startsWith('/__mock')?'':'/api/v1')+path,{method,headers:{Cookie:cookie,'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});const text=await r.text();return{status:r.status,text,data:text?JSON.parse(text):undefined,headers:r.headers}}
async function login(username:string,password='example-password-1'){const r=await api('/auth/login',{username,password});if(r.status===200)cookie=r.headers.get('set-cookie')!.split(';')[0]!;return r}
it('G8 mock users byte validation ordering empty 201 resets roles deletions last user and admin',async()=>{
  expect((await api('/users',{username:'bad name',role:'bad',password:'short'})).data.field).toBe('username')
  expect((await api('/users',{username:'new',role:'bad',password:'short'})).data.field).toBe('role')
  expect((await api('/users',{username:'new',role:'operator',password:'中'.repeat(25)})).data.field).toBe('password')
  const created=await api('/users',{username:'new',role:'operator',password:'example-password-1'});expect(created.status).toBe(201);expect(created.text).toBe('')
  expect((await api('/users',{username:'new',role:'operator',password:'example-password-1'})).data.code).toBe('user_exists')
  const admin=cookie;await login('new');const old=cookie;cookie=admin
  expect((await api('/users/new/password',{password:'example-password-2'},'PUT')).status).toBe(204);cookie=old;expect((await api('/auth/me')).status).toBe(401);expect((await login('new','example-password-2')).status).toBe(200);cookie=admin
  expect((await api('/users/new/role',{role:'admin'},'PUT')).status).toBe(204);expect((await api('/users')).data.find((u:any)=>u.username==='new').role).toBe('admin')
  expect((await api('/users/new',undefined,'DELETE')).status).toBe(204);expect((await api('/users/new',undefined,'DELETE')).data.code).toBe('user_not_found')
  expect((await api('/users/admin/role',{role:'operator'},'PUT')).data.code).toBe('last_admin');expect((await api('/users/admin',undefined,'DELETE')).data.code).toBe('last_admin')
  await api('/users/operator',undefined,'DELETE');expect((await api('/users/admin',undefined,'DELETE')).data.code).toBe('last_user')
})
it('G8 mock credentials rotation deadline and idempotent revocation preserve active states',async()=>{
  const first=(await api('/credentials',{name:'fresh'})).data;const time=Date.now(),second=(await api('/credentials',{name:'fresh'})).data
  expect(second.name).toBe('fresh');expect(second.key).toBe('xdk_'+'0'.repeat(16)+'_'+'A'.repeat(43));expect(second.retired.map((r:any)=>r.id)).toEqual([first.id]);expect(Math.abs(Date.parse(second.retired[0].retire_at)-time-86400000)).toBeLessThan(1500)
  const all=(await api('/credentials')).data;expect(all.filter((r:any)=>r.name==='xsight'&&r.active)).toHaveLength(2);expect(all.filter((r:any)=>r.name==='old').every((r:any)=>!r.active)).toBe(true)
  expect((await api('/credentials/'+first.id,undefined,'DELETE')).status).toBe(204);expect((await api('/credentials/'+first.id,undefined,'DELETE')).status).toBe(204);expect((await api('/credentials/missing',undefined,'DELETE')).data.code).toBe('credential_not_found')
  expect((await api('/credentials',{name:'bad name'})).data.field).toBe('name')
})
it('G8 mock settings patch validates entire input and preserves null omitted fields',async()=>{
  const before=(await api('/settings')).data;expect((await api('/settings',{audit_retention_days:365,session_hours:0},'PUT')).data.field).toBe('session_hours');expect((await api('/settings')).data).toEqual(before)
  const changed=(await api('/settings',{session_hours:12,default_language:'ja-JP',audit_retention_days:null},'PUT')).data;expect(changed).toEqual({...before,session_hours:12,default_language:'ja-JP'})
  expect((await api('/settings',{default_language:'auto'},'PUT')).data.field).toBe('default_language');expect((await api('/settings',{unknown:1},'PUT')).data.code).toBe('bad_request')
})
it('G8 mock templates full replacement duplicate missing and capacity',async()=>{
  const created=await api('/templates',{name:' New ',body:'protocol=udp'});expect(created.status).toBe(201);expect(created.data.name).toBe(' New ')
  expect((await api('/templates',{name:' New ',body:''})).data.code).toBe('rule_conflict')
  const edited=await api('/templates/'+created.data.id,{name:'Renamed'},'PUT');expect(edited.data.body).toBe('');expect(edited.status).toBe(200)
  expect((await api('/templates/missing',{name:'Missing',body:''},'PUT')).data.code).toBe('not_found')
  expect((await api('/templates',{name:'',body:''})).data.field).toBe('name');expect((await api('/templates',{name:'Long',body:'a'.repeat(65537)})).data.field).toBe('body')
  for(let i=0;i<97;i++)expect((await api('/templates',{name:'T'+i,body:''})).status).toBe(201)
  expect((await api('/templates',{name:'Overflow',body:''})).data).toMatchObject({code:'table_full',table:'templates'})
  expect((await api('/templates/'+created.data.id,undefined,'DELETE')).status).toBe(204);expect((await api('/templates/'+created.data.id,undefined,'DELETE')).data.code).toBe('not_found')
})
it('G8 mock nodes writes encoded paths unreadable key and three switchable test states',async()=>{
  const n={name:'edge 01#a',base_url:'http://192.0.2.100',api_key:'example-node-key-1'},path='/nodes/'+encodeURIComponent(n.name)
  expect((await api('/__mock/fixtures',{legacyNode:true})).status).toBe(204)
  expect(await api('/nodes',n)).toMatchObject({status:400,data:{code:'invalid_field',message:K3}})
  expect((await api(path,{base_url:'http://192.0.2.101'},'PATCH')).data.base_url).toBe('http://192.0.2.101');expect((await api(path,{name:'renamed'},'PATCH')).data.field).toBe('name')
  expect((await api('/nodes/edge-04',{base_url:'http://192.0.2.102'},'PATCH')).data.message).toBe('node key unreadable; supply api_key')
  expect((await api('/nodes/edge-04/test',{},'POST')).data).toEqual({reachable:false,compatible:false,key_accepted:false,message:'node key unreadable'})
  for(const nodeTest of ['ok','incompatible','unreachable']){await api('/__mock/fixtures',{nodeTest});for(const target of ['/nodes/test',path+'/test']){const r=await api(target,{base_url:n.base_url,api_key:n.api_key});expect(r.data).toEqual(nodeTest==='ok'?{reachable:true,compatible:true,key_accepted:true,message:''}:nodeTest==='incompatible'?{reachable:true,compatible:false,key_accepted:true,message:''}:{reachable:false,compatible:false,key_accepted:false,message:'node unreachable'})}}
  expect((await api(path,undefined,'DELETE')).status).toBe(204);expect((await api(path,undefined,'DELETE')).data.code).toBe('node_not_found');expect((await api('/nodes')).data.nodes.some((row:any)=>row.name===n.name)).toBe(false)
})
it('G8 mock administrator permission precedes malformed payload for all five resources',async()=>{
  await login('operator')
  for(const path of ['/users','/credentials','/settings','/templates','/nodes']){const r=await fetch(base+'/api/v1'+path,{method:path==='/settings'?'PUT':'POST',headers:{Cookie:cookie},body:'{invalid'});expect(r.status).toBe(403);expect((await r.json()).code).toBe('admin_required')}
})
it.each(['PATCH','DELETE'])('G8 V33 mock node named test supports %s without entering anonymous test',async(method)=>{
  const node={name:'test',base_url:'http://192.0.2.10',api_key:'example-node-key-1'}
  expect((await api('/nodes',node)).status).toBe(201)
  expect((await api('/nodes/test/test',undefined,'POST')).data).toEqual({reachable:true,compatible:true,key_accepted:true,message:''})
  const result=await api('/nodes/test',method==='PATCH'?{base_url:'http://192.0.2.11'}:undefined,method)
  expect(result.status).toBe(method==='PATCH'?200:204)
  const stored=(await api('/nodes')).data.nodes.find((row:any)=>row.name==='test')
  if(method==='PATCH')expect(stored.base_url).toBe('http://192.0.2.11');else expect(stored).toBeUndefined()
  expect((await api('/nodes/test',{base_url:node.base_url,api_key:node.api_key})).data).toEqual({reachable:true,compatible:true,key_accepted:true,message:''})
})
it('G8 V34 mock node URL accepts uppercase HTTP while retaining URL exclusions',async()=>{
  expect((await api('/nodes',{name:'uppercase',base_url:'HTTP://192.0.2.10',api_key:'example-node-key-1'})).status).toBe(201)
  for(const base_url of ['HTTP://admin@192.0.2.10','HTTP://192.0.2.10?x=1','HTTP://192.0.2.10#part','HTTP://']){
    const result=await api('/nodes',{name:'invalid-url',base_url,api_key:'example-node-key-1'});expect(result.status).toBe(400);expect(result.data.message).toBe('invalid node URL')
  }
})

const K3 = "name must be 1..64 ASCII letters, digits, '.', '_' or '-', and not '.' or '..'"
it('FE G4 legal node duplicate retains conflict coverage', async () => {
  const node = { name: 'edge-dup', base_url: 'http://192.0.2.100', api_key: 'example-node-key-1' }
  expect((await api('/nodes', node)).status).toBe(201)
  expect(await api('/nodes', node)).toMatchObject({ status: 409, data: { code: 'rule_conflict', message: 'node already exists' } })
})
it.each(['.','..'])('FE G4 rejects user name %s', async username => {
  expect(await api('/users', { username, role: 'operator', password: 'example-password-1' })).toMatchObject({ status: 400, data: { code: 'invalid_field', field: 'username', message: 'invalid field' } })
})
it.each(['.','..'])('FE G4 rejects credential name %s', async name => {
  expect(await api('/credentials', { name })).toMatchObject({ status: 400, data: { code: 'invalid_field', field: 'name', message: 'invalid field' } })
})
it.each(['edge 01#a','.','..','节点','a'.repeat(65)])('FE G4 node creation rejects K3 name %s', async name => {
  expect(await api('/nodes', { name, base_url: 'http://192.0.2.100', api_key: 'example-node-key-1' })).toMatchObject({ status: 400, data: { code: 'invalid_field', message: K3 } })
})
it.each([['', 'name must not be empty'],['  ', 'name must not be empty'],['bad/name', "name must not contain '/'"]])('FE G4 node error priority %s', async (name, message) => {
  expect(await api('/nodes', { name })).toMatchObject({ status: 400, data: { code: 'invalid_field', message } })
})
