// @vitest-environment node
import { it, expect, vi } from 'vitest'
vi.hoisted(() => { (globalThis as unknown as { process: { env: Record<string,string> } }).process.env.TZ='Asia/Tokyo' })
import { auditTime, auditActor, auditActions, auditGroups, auditFilename } from '../src/audit'
import { messages } from '../src/i18n'
import { contracts } from '../src/api/contract'
it('G3 V19 Asia Tokyo prerequisite and local timestamp',()=>{
  const offset=new Date('2026-10-17T00:00:05Z').getTimezoneOffset();console.log('TZ prerequisite offset',offset)
  expect(offset).toBe(-540);expect(auditTime('2026-10-17T00:00:05Z')).toBe('10-17 09:00:05')
})
it.each([['user:a','a'],['cred:k','k'],['system:s','s'],['','—']])('G3 V20 actor %s becomes %s',(raw,value)=>expect(auditActor(raw)).toBe(value))
it('G3 exact 26 actions grouped and translated; G6 nullable audit contract',()=>{
  const expected='rule.create rule.claim rule.update rule.release rule.delete rule.expire whitelist.create whitelist.delete auth.login auth.login_failed auth.logout user.create user.delete user.password credential.issue credential.revoke settings.update node.sync node.reconcile user.role template.create template.update template.delete node.create node.update node.delete'.split(' ')
  expect([...auditActions].sort()).toEqual(expected.sort());expect(auditGroups.map(g=>g.length)).toEqual([6,2,3,4,2,1,5,3])
  for(const dict of Object.values(messages))for(const action of expected)expect((dict.auditActions as Record<string,Record<string,string>>)[action.split('.')[0]]?.[action.split('.')[1]]).toBeTruthy()
  expect(contracts.filter(e=>e.root==='auditPage').map(e=>[e.path,!!e.nullable])).toEqual(['id','at','actor','source','action','target','before','after'].map(k=>['items[].'+k,['before','after'].includes(k)]).concat([['next_cursor',false]]))
  expect(auditFilename('json')).toMatch(/^xdrop-audit-\d{8}-\d{6}\.json$/)
})
