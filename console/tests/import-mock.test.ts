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

it.each(['icmp','icmpv6','igmp','gre','esp'])('FE G4 protocol %s rejects ports', async protocol => {
  expect(await api('/api/v1/rules', { dst_ip: '192.0.2.250', protocol, dst_port: 53 })).toEqual({ status: 400, data: { code: 'invalid_rule', field: 'protocol', message: 'protocol does not support ports' } })
})
it.each(['bad::ip','2001:db8:::1','2001:db8::1%eth0'])('FE G4 invalid IP has the backend envelope %s', async dst_ip => {
  expect(await api('/api/v1/rules', { dst_ip })).toEqual({ status: 400, data: { code: 'invalid_rule', field: 'ip', message: 'invalid IP address' } })
})
it.each(['::ffff:192.0.2.1','0:0:0:0:0:ffff:c000:201'])('FE G4 mapped IPv6 rejects %s', async dst_ip => {
  expect(await api('/api/v1/rules', { dst_ip })).toEqual({ status: 400, data: { code: 'mapped_ipv6', message: 'IPv4-mapped IPv6 is not supported; use IPv4 192.0.2.1' } })
})
it('FE G4 mapped IPv6 prefix uses the backend message', async () => {
  expect(await api('/api/v1/rules', { dst_cidr: '::ffff:192.0.2.1/120' })).toEqual({ status: 400, data: { code: 'mapped_ipv6', message: 'IPv4-mapped IPv6 prefix is not supported; use IPv4 192.0.2.0/24' } })
})
it.each([['src_port',-1],['dst_port',65536]])('FE G4 port range %s is exact', async (field, value) => {
  expect(await api('/api/v1/rules', { dst_ip: '192.0.2.250', [field]: value })).toEqual({ status: 400, data: { code: 'invalid_rule', field, message: 'port out of range' } })
})
it.each([['ttl','64'],['dscp','1'],['pkt_len','64'],['icmp_type','1'],['icmp_code','1'],['fragment','first'],['tcp_flags','SYN'],['match_anomaly',2]])('FE G4 condition identity includes %s', async (field, value) => {
  const item = { dst_ip: '203.0.113.201', protocol: String(field).startsWith('icmp_') ? 'icmp' : 'tcp' }
  const first = await api('/api/v1/rules', item), second = await api('/api/v1/rules', { ...item, [field]: value })
  expect(first.status).toBe(201); expect(second.status).toBe(201); expect(second.data.id).not.toBe(first.data.id)
  const dry = await api('/api/v1/rules/batch?validate=1', { items: [item, { ...item, [field]: value }] })
  expect(dry.data.results.map((r:any) => r.rule.id)).toEqual([first.data.id, second.data.id])
})
it('FE G4 omitted match_anomaly and explicit zero share identity', async () => {
  const item = { dst_ip: '203.0.113.201', protocol: 'tcp' }, first = await api('/api/v1/rules', item)
  expect(await api('/api/v1/rules', { ...item, match_anomaly: 0 })).toMatchObject({ status: 200, data: { id: first.data.id, existing: true } })
  const dry = await api('/api/v1/rules/batch?validate=1', { items: [item, { ...item, match_anomaly: 0 }] })
  expect(dry.data.results.map((r:any) => r.rule.id)).toEqual([first.data.id, first.data.id])
})
async function queryFixture() {
  const items = [{ dst_ip: '203.0.113.201' }, { src_ip: '203.0.113.202' }, { dst_cidr: '203.0.113.192/28' }, { src_cidr: '203.0.113.192/27' }, { dst_cidr: '203.0.113.0/24' }, { dst_ip: '203.0.113.231' }]
  const ids: string[] = []
  for (const item of items) { const r = await api('/api/v1/rules', item); expect(r.status).toBe(201); ids.push(r.data.id) }
  return ids
}
const query = async (q: string) => api('/api/v1/rules?limit=1000&q=' + encodeURIComponent(q))
it('FE G4 ID query is exact', async () => {
  const ids = await queryFixture()
  expect((await query(ids[0]!)).data.items.map((r:any) => r.id)).toEqual([ids[0]])
  expect(await query(ids[0]!.slice(0,-1))).toEqual({ status: 400, data: { code: 'bad_request', field: 'q', message: 'invalid rule query' } })
  expect(await query('2001:db8::1%eth0')).toEqual({ status: 400, data: { code: 'bad_request', field: 'q', message: 'invalid rule query' } })
})
it('FE G4 IP query includes its covering networks', async () => {
  const ids = await queryFixture()
  expect((await query('203.0.113.201')).data.items.map((r:any) => r.id)).toEqual([ids[0],ids[2],ids[3],ids[4]])
})
it('FE G4 network query includes addresses and equal or narrower networks', async () => {
  const ids = await queryFixture()
  expect((await query('203.0.113.199/27')).data.items.map((r:any) => r.id)).toEqual(ids.slice(0,4))
})
it('FE G4 IPv6 query canonicalizes compressed addresses and network boundaries', async () => {
  const host = await api('/api/v1/rules', { dst_ip: '2001:db8:1::1' }), prefix = await api('/api/v1/rules', { src_cidr: '2001:db8:1::/64' })
  await api('/api/v1/rules', { dst_ip: '2001:db8:2::1' })
  for (const q of ['2001:0db8:1:0:0:0:0:1','2001:db8:1::/64']) expect((await query(q)).data.items.map((r:any) => r.id)).toEqual([host.data.id,prefix.data.id])
})
it('FE G4 synthetic condition capacity fixture maps to 409', async () => {
  expect(await api('/api/v1/rules', { dst_ip: '192.0.2.250', ttl: '1,2,3,4,5' })).toMatchObject({ status: 409, data: { code: 'condition_capacity' } })
})
