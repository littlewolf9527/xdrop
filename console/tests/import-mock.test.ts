// @vitest-environment node
import { it, expect, beforeEach, afterEach } from 'vitest'
import { mockPlugin } from '../mock/server'
import { applyResults, parseImport, sendable } from '../src/import'
const httpModule='node:http', http=await import(httpModule)
let server:any, handler:any, base='', cookie=''
beforeEach(async()=>{
  server=http.createServer((req:any,res:any)=>handler(req,res,()=>{res.statusCode=404;res.end()}))
  ;(mockPlugin().configureServer as any)({httpServer:server,middlewares:{use:(h:any)=>{handler=h}}})
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));base='http://127.0.0.1:'+server.address().port
  const r=await fetch(base+'/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password:'example-password-1'})});cookie=r.headers.get('set-cookie')!.split(';')[0]!
})
afterEach(async()=>{server.closeAllConnections();await new Promise<void>(resolve=>server.close(resolve))})
async function api(path:string,payload?:unknown,method=payload?'POST':'GET') {
  const r=await fetch(base+path,{method,headers:{Cookie:cookie,'Content-Type':'application/json'},...(payload?{body:JSON.stringify(payload)}:{})})
  return{status:r.status,data:r.status===204?undefined:await r.json()}
}
it('G5 mock stored expiry unchanged through skip; positive direct submit renews; dry batch duplicate has empty ID',async()=>{
  const created=await api('/api/v1/rules',{dst_ip:'203.0.113.250',expires_in:'1h',comment:'old'}), before=created.data.expires_at
  expect(before).not.toBeNull()
  const rows=parseImport('dst_ip=203.0.113.250\ndst_ip=203.0.113.251\ndst_ip=203.0.113.251\ndst_ip=203.0.113.252')
  const checked=await api('/api/v1/rules/batch?validate=1',{items:rows.map(r=>r.patch)})
  expect(checked.data.results.map((r:any)=>[r.existing,r.rule.id===''])).toEqual([[true,false],[false,true],[true,true],[false,true]])
  const selected=sendable(applyResults(rows,checked.data,'validate'))
  expect(selected.map(r=>r.patch)).toEqual([{dst_ip:'203.0.113.251'},{dst_ip:'203.0.113.252'}])
  await api('/api/v1/rules/batch',{items:selected.map(r=>r.patch)})
  expect((await api('/api/v1/rules/'+created.data.id)).data.expires_at).toBe(before)
  const renewed=await api('/api/v1/rules/batch',{items:[{dst_ip:'203.0.113.250',comment:'new',enabled:false}]})
  expect(renewed.data.results[0].existing).toBe(true);expect(renewed.data.results[0].rule.expires_at).toBeNull();expect(renewed.data.results[0].rule.comment).toBe('old');expect(renewed.data.results[0].rule.enabled).toBe(true)
})
it('G6 mock whitelist identity returns old row and comment; idempotent deletion; template array toggle',async()=>{
  const created=await api('/api/v1/whitelist',{src_ip:'2001:db8::1',src_port:123,dst_port:179,protocol:'tcp',comment:'first'})
  expect(created.status).toBe(201)
  const existing=await api('/api/v1/whitelist',{src_ip:'2001:0DB8:0:0:0:0:0:1',src_port:123,dst_port:179,protocol:'tcp',comment:'changed'})
  expect(existing.status).toBe(200);expect(existing.data.id).toBe(created.data.id);expect(existing.data.comment).toBe('first');expect(existing.data.existing).toBe(true)
  expect((await api('/api/v1/whitelist/'+created.data.id,undefined,'DELETE')).status).toBe(204);expect((await api('/api/v1/whitelist/'+created.data.id,undefined,'DELETE')).status).toBe(204)
  expect((await api('/api/v1/whitelist',{src_ip:'192.0.2.0/24'})).data.field).toBe('ip')
  expect((await api('/api/v1/templates')).data).toHaveLength(2);await api('/__mock/fixtures',{emptyTemplates:true});expect((await api('/api/v1/templates')).data).toEqual([])
})
it('G4 mock whole batch decoding rejection writes zero; request size and action conflict',async()=>{
  const before=(await api('/api/v1/rules?limit=1000')).data.items.length
  expect((await api('/api/v1/rules/batch',{items:[{dst_ip:'203.0.113.250'},{dst_port:'bad'}]})).status).toBe(400)
  expect((await api('/api/v1/rules?limit=1000')).data.items).toHaveLength(before)
  expect((await api('/api/v1/rules/batch',{items:[]})).data.code).toBe('batch_too_large')
  const r=await api('/api/v1/rules/batch?validate=1',{items:[{dst_ip:'203.0.113.250'},{dst_ip:'203.0.113.250',action:'rate_limit',rate_limit:123}]})
  expect(r.data.results[1].error.code).toBe('rule_conflict')
})
it.each([{src_ip:'203.0.113.250'},{src_cidr:'203.0.113.0/28'}])('r1 V29 source-only duplicate has empty destination %j',async item=>{
  const checked=await api('/api/v1/rules/batch?validate=1',{items:[item,item]})
  expect(checked.status).toBe(200)
  expect(checked.data.results.map((r:any)=>({existing:r.existing,id:r.rule.id,dst_ip:r.rule.dst_ip}))).toEqual([
    {existing:false,id:'',dst_ip:''},{existing:true,id:'',dst_ip:''},
  ])
})
it('r1 V30 dry conflict references original batch index while success IDs stay empty',async()=>{
  const checked=await api('/api/v1/rules/batch?validate=1',{items:[{dst_ip:'203.0.113.250',action:'drop'},{dst_ip:'203.0.113.250',action:'rate_limit',rate_limit:123},{dst_ip:'203.0.113.250',action:'drop'}]})
  expect(checked.status).toBe(200);expect(checked.data.results[0].rule.id).toBe('')
  expect(checked.data.results[1].error).toMatchObject({code:'rule_conflict',rule_id:'batch:0'})
  expect(checked.data.results[2]).toMatchObject({existing:true,rule:{id:''}})
  const created=await api('/api/v1/rules',{dst_ip:'203.0.113.251',action:'drop'})
  const stored=await api('/api/v1/rules/batch?validate=1',{items:[{dst_ip:'203.0.113.251',action:'rate_limit',rate_limit:123}]})
  expect(stored.data.results[0].error.rule_id).toBe(created.data.id)
})
it.each(['0:0:0:0:0:ffff:c000:201','::ffff:192.0.2.1'])('r1 V31 rejects mapped IPv6 after canonicalization %s',async src_ip=>{
  const result=await api('/api/v1/whitelist',{src_ip})
  expect(result.status).toBe(400);expect(result.data.code).toBe('mapped_ipv6')
})
it('r2 V32 accepts canonical non-mapped IPv6 with an ffff segment',async()=>{
  const result=await api('/api/v1/whitelist',{src_ip:'0:0:0:0:ffff:0:c000:201'})
  expect(result.status).toBe(201);expect(result.data.src_ip).toBe('::ffff:0:c000:201')
})
