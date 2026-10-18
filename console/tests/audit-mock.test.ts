// @vitest-environment node
import { it, expect, beforeEach, afterEach } from 'vitest'
import { mockPlugin } from '../mock/server'
import { auditActions } from '../src/audit'
const httpModule='node:http',http=await import(httpModule)
let server:any,handler:any,base='',cookie=''
beforeEach(async()=>{
  server=http.createServer((req:any,res:any)=>handler(req,res,()=>{res.statusCode=404;res.end()}))
  ;(mockPlugin().configureServer as any)({httpServer:server,middlewares:{use:(h:any)=>{handler=h}}})
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));base='http://127.0.0.1:'+server.address().port;await login('admin')
})
afterEach(async()=>{server.closeAllConnections();await new Promise<void>(resolve=>server.close(resolve))})
async function api(path:string,body?:unknown,method=body?'POST':'GET'){return fetch(base+path,{method,headers:{Cookie:cookie,'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})})}
async function login(username:string){const r=await api('/api/v1/auth/login',{username,password:'example-password-1'});cookie=r.headers.get('set-cookie')!.split(';')[0]!;return r}
it('G6 mock 330 rows cover actions repeated seconds actor shapes nullable views and exact filter pagination',async()=>{
  const all=await(await api('/api/v1/audit?limit=1000')).json();expect(all.items.length).toBeGreaterThanOrEqual(300)
  expect([...new Set(all.items.map((r:any)=>r.action))].sort()).toEqual([...auditActions].sort());expect(all.items.filter((r:any)=>r.action==='auth.login').length).toBeGreaterThanOrEqual(150)
  expect(all.items.filter((r:any)=>r.action==='user.password').length).toBeLessThanOrEqual(100);expect(new Set(all.items.map((r:any)=>r.at)).size).toBeLessThan(all.items.length)
  for(const prefix of ['user:','cred:','system:',''])expect(all.items.some((r:any)=>prefix?r.actor.startsWith(prefix):r.actor==='')).toBe(true)
  const sample=await(await api('/api/v1/audit?limit=100')).json();for(const field of ['before','after']){expect(sample.items.some((r:any)=>r[field]!==null)).toBe(true);expect(sample.items.some((r:any)=>r[field]===null)).toBe(true)}
  const a=await(await api('/api/v1/audit?limit=100&action=auth.login')).json();expect(a.items).toHaveLength(100);expect(a.next_cursor).not.toBe('')
  const b=await(await api('/api/v1/audit?limit=100&cursor='+encodeURIComponent(a.next_cursor)+'&action=auth.login')).json();expect(b.items.length).toBeGreaterThan(0);expect(b.next_cursor).toBe('');expect([...a.items,...b.items].every(r=>r.action==='auth.login')).toBe(true)
  expect(new Set([...a.items,...b.items].map(r=>r.id)).size).toBe(a.items.length+b.items.length)
  expect((await(await api('/api/v1/audit?limit=100&action=user.password')).json()).next_cursor).toBe('');expect((await(await api('/api/v1/audit?action=unknown')).json()).items).toEqual([])
})
it('G6 mock stream full exports filter and permissions; cutoff switch rejects after data',async()=>{
  const query='/api/v1/audit/export?from=1970-01-01T00:00:00Z&to=9999-12-31T23:59:59Z&format='
  const full=await(await api(query+'json&action=auth.login')).json();expect(full.length).toBeGreaterThanOrEqual(150);expect(full.every((r:any)=>r.action==='auth.login')).toBe(true);expect(full[0].id).toBeLessThan(full.at(-1).id)
  const csv=await(await api(query+'csv&action=user.password')).text();expect(csv.startsWith('id,at,actor,source,action,target,before,after\n')).toBe(true)
  await api('/__mock/fixtures',{auditCut:true});const response=await api(query+'json');const reader=response.body!.getReader();let bytes=0,failed=false
  try{while(true){const chunk=await reader.read();if(chunk.done)break;bytes+=chunk.value.length}}catch{failed=true}
  expect(bytes).toBeGreaterThan(0);expect(failed).toBe(true);await login('operator');expect((await api(query+'json')).status).toBe(403)
})
it('G6 mock password byte validation precedes wrong current and throttle; 204 invalidates all user sessions without changing login fixture',async()=>{
  const own='/api/v1/auth/me/password',payload={current_password:'example-password-2',password:'example-password-2'}
  const wrong=await api(own,payload,'PUT');expect(wrong.status).toBe(401);expect((await wrong.json()).code).toBe('invalid_credentials')
  await api('/__mock/fixtures',{passwordThrottle:true});expect((await api(own,payload,'PUT')).status).toBe(429)
  for(const password of ['短短短','中'.repeat(25)]){const r=await api(own,{...payload,password},'PUT');expect(r.status).toBe(400);expect(await r.json()).toMatchObject({code:'invalid_field',field:'password'})}
  await api('/__mock/fixtures',{});const old=cookie;await login('admin');const second=cookie
  const ok=await api(own,{current_password:'example-password-1',password:'example-password-2'},'PUT');expect(ok.status).toBe(204);expect(ok.headers.get('set-cookie')).toContain('Max-Age=0')
  cookie=old;expect((await api('/api/v1/auth/me')).status).toBe(401);cookie=second;expect((await api('/api/v1/auth/me')).status).toBe(401);expect((await login('admin')).status).toBe(200)
})
