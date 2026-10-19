import { it, expect, vi } from 'vitest'
vi.mock('../src/state', () => ({ captureSession: vi.fn(), request: vi.fn() }))
import { createClient, ApiError } from '../src/api/client'
import { settingsError, templateCheck, templateCount, settingsDelta, groupCredentials } from '../src/settings'
import { i18n } from '../src/i18n'
import { expandTargets } from '../src/import'
import type { CredentialDTO } from '../src/api/types'
const error = (code: string, field?: string, message = '', table?: string) => new ApiError(400, { code, field, message, ...(table ? { table } : {}) })
it.each([[201,'',undefined],[200,'{"ok":true}',{ok:true}],[204,null,undefined]] as const)('G2 client %s success body resolves correctly', async(status,body,expected) => {
  const request = createClient({ expired: vi.fn(), demoted: vi.fn() }, vi.fn(async() => new Response(body,{status})))
  expect(await request('/users')).toEqual(expected)
})
it('G2 nonempty non-JSON success rejects', async() => {
  const request = createClient({expired:vi.fn(),demoted:vi.fn()},vi.fn(async()=>new Response('not json',{status:200})))
  await expect(request('/users')).rejects.toThrow(SyntaxError)
})
it.each([
  ['name must not be empty','名称不能为空'],["name must not contain '/'",'名称不能含 /'],
  ['node fields required','请填写地址和节点密钥'],['base_url and api_key (1..4096 bytes) required','请填写地址和节点密钥'],
  ['api_key must contain 1..4096 bytes','节点密钥长度不对'],['node key unreadable; supply api_key','无法读取已存的节点密钥，请重新填写'],
  ['invalid node URL','地址不对：只支持 http:// 或 https:// 开头、不带账号和参数'],
  ["name must be 1..64 ASCII letters, digits, '.', '_' or '-', and not '.' or '..'",'名称须为 1–64 个 ASCII 字母、数字、.、_、-，且不能是 . 或 ..'],
])('G3 exact node message %s', (message, text) => {
  i18n.global.locale.value='zh-CN'
  for(const code of ['invalid_field','bad_request']) expect(i18n.global.t(settingsError('nodes',error(code,undefined,message)))).toBe(text)
})
it.each(['invalid node URL: x','x node fields required','unknown'])('G3 V23 near node message remains generic %s', message => {
  expect(settingsError('nodes',error('invalid_field',undefined,message))).toBe('errors.invalid_field')
})
it.each([
  ['nodes','rule_conflict',undefined,'settingsUI.nodeExists'],['nodes','node_not_found',undefined,'errors.node_not_found'],
  ['users','invalid_field','username','settingsUI.usernameInvalid'],['users','invalid_field','password','passwordLength'],['users','invalid_field','role','errors.invalid_field'],
  ...['user_exists','user_not_found','last_user','last_admin'].map(code=>['users',code,undefined,'errors.'+code]),
  ['keys','invalid_field','name','settingsUI.keyNameInvalid'],['keys','credential_not_found',undefined,'errors.credential_not_found'],
  ['templates','invalid_field','name','settingsUI.templateNameInvalid'],['templates','invalid_field','body','settingsUI.templateBodyLong'],
  ['templates','rule_conflict',undefined,'settingsUI.templateExists'],['templates','not_found',undefined,'settingsUI.templateGone'],
])('G3-G7 mapping %s %s %s', (kind,code,field,key) => expect(settingsError(kind as any,error(code!,field))).toBe(key))
it('G7 V20 template capacity has its own text',()=>{
  i18n.global.locale.value='zh-CN';const text=i18n.global.t(settingsError('templates',error('table_full',undefined,'','templates')))
  expect(text).toBe('模板已满（最多 100 个）');expect(text).not.toContain('容量已满')
})
it.each(['nodes','users','keys','system','templates'] as const)('G2 V28 rule-shaped field stays generic %s',kind=>{
  expect(settingsError(kind,error('invalid_field','conditions'))).toBe('errors.invalid_field')
  expect(settingsError(kind,new TypeError('offline'))).toBe('unreachable')
  expect(settingsError(kind,error('unavailable'))).toBe('operationFailed')
})
it('G7 V18 original textarea line number; target detection; V19 count equals import expansion',()=>{
  const body='\n# comment\n  protocol=udp  \n\ninvalid=bad\ndst_ip=192.0.2.1\ndst_cidr=2001:db8::/32'
  expect(templateCheck(body)).toEqual([{no:5,key:'templateLex'},{no:6,key:'templateTarget'},{no:7,key:'templateTarget'}])
  expect(templateCount(body)).toBe(4);expect(templateCount(body)).toBe(expandTargets('192.0.2.2',body).template)
})
it('G6 settingsDelta contains only changed keys',()=>{
  const before={session_hours:24,audit_retention_days:180,history_retention_days:30,reconcile_interval_minutes:15,default_language:'en-US' as const}
  expect(settingsDelta(before,{...before,audit_retention_days:365})).toEqual({audit_retention_days:365})
})
it('G5 group state uses server active regardless of local clock',()=>{
  const row={id:'fixture',name:'lone',created_at:'2026-10-01T00:00:00Z',created_by:'',retire_at:'2000-01-01T00:00:00Z',revoked_at:null,revoked_by:null,active:true} satisfies CredentialDTO
  expect(groupCredentials([row])[0]?.status).toBe('retiring')
})

it('FE G3 K3 maps to the new node name key', () => {
  expect(settingsError('nodes', error('invalid_field', undefined, "name must be 1..64 ASCII letters, digits, '.', '_' or '-', and not '.' or '..'"))).toBe('settingsUI.nodeNameInvalid')
})
