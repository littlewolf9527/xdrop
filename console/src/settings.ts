import { onBeforeUnmount, ref, shallowRef } from 'vue'
import { captureSession, request } from './state'
import { ApiError } from './api/client'
import type { CredentialDTO, Settings, WriteError } from './api/types'
import { genericKey } from './errors'
import { auditTime } from './audit'
import { parseImport, expandTargets } from './import'

export const settingTime = (value: string) => auditTime(value).slice(0, 11)
export const jsonWrite = (method: string, body?: unknown): RequestInit => ({ method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) })
export function useSettingsRequests<T>(path: string, initial: T, errorKey: (e: unknown) => string) {
  const data = shallowRef<T>(initial), loading = ref(false), loaded = ref(false), error = ref(''), writing = ref(false), actionError = ref('')
  let sequence = 0, alive = true
  onBeforeUnmount(() => { alive = false })
  async function load(after?: () => void) {
    const serial = ++sequence, session = captureSession()
    const current = () => alive && serial === sequence && session.isCurrent()
    loading.value = true; loaded.value = false; error.value = ''
    try {
      const value = await request<T>(path)
      if (!current()) return
      data.value = value; loaded.value = true; after?.()
    } catch (e) { if (current()) error.value = errorKey(e) }
    finally { if (current()) loading.value = false }
  }
  async function write<R>(task: (current: () => boolean) => Promise<R>, success: (value: R) => void, failure?: (e: unknown) => void) {
    if (writing.value) return
    const session = captureSession()
    const current = () => alive && session.isCurrent()
    writing.value = true; actionError.value = ''
    try {
      const value = await task(current)
      if (!current()) return
      success(value)
    } catch (e) { if (current()) { actionError.value = errorKey(e); failure?.(e) } }
    finally { if (current()) writing.value = false }
  }
  return { data, loading, loaded, error, writing, actionError, load, write }
}
const nodeMessages: Record<string, string> = {
  'name must not be empty': 'nodeNameEmpty',
  "name must not contain '/'": 'nodeNameSlash',
  "name must be 1..64 ASCII letters, digits, '.', '_' or '-', and not '.' or '..'": 'nodeNameInvalid',
  'node fields required': 'nodeFields',
  'base_url and api_key (1..4096 bytes) required': 'nodeFields',
  'api_key must contain 1..4096 bytes': 'nodeKeyLength',
  'node key unreadable; supply api_key': 'nodeKeyUnreadable',
  'invalid node URL': 'nodeURL',
}
export function settingsError(kind: 'nodes' | 'users' | 'keys' | 'system' | 'templates', e: unknown): string {
  if (e instanceof ApiError) {
    const { code, field, message, table } = e.envelope as WriteError
    if (kind === 'nodes') {
      if (['invalid_field', 'bad_request'].includes(code)) {
        const match = Object.keys(nodeMessages).find(sentence => message === sentence)
        if (match) return 'settingsUI.' + nodeMessages[match]
      }
      if (code === 'rule_conflict') return 'settingsUI.nodeExists'
    }
    if (kind === 'users') {
      if (code === 'invalid_field' && field === 'username') return 'settingsUI.usernameInvalid'
      if (code === 'invalid_field' && field === 'password') return 'passwordLength'
      if (['user_exists', 'user_not_found', 'last_user', 'last_admin'].includes(code)) return 'errors.' + code
    }
    if (kind === 'keys') {
      if (code === 'invalid_field' && field === 'name') return 'settingsUI.keyNameInvalid'
      if (code === 'credential_not_found') return 'errors.credential_not_found'
    }
    if (kind === 'templates') {
      if (code === 'invalid_field' && field === 'name') return 'settingsUI.templateNameInvalid'
      if (code === 'invalid_field' && field === 'body') return 'settingsUI.templateBodyLong'
      if (code === 'rule_conflict') return 'settingsUI.templateExists'
      if (code === 'table_full' && table === 'templates') return 'settingsUI.templateFull'
      if (code === 'not_found') return 'settingsUI.templateGone'
    }
  }
  return genericKey(e)
}
export function groupCredentials(rows: CredentialDTO[]) {
  const groups = new Map<string, CredentialDTO[]>()
  for (const row of rows) groups.set(row.name, [...(groups.get(row.name) || []), row])
  return [...groups].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).flatMap(([name, all]) => {
    const active = all.filter(row => row.active === true)
    if (!active.length) return []
    const retired = active.map(row => row.retire_at).filter((v): v is string => v !== null).sort()
    return [{ name, active, all, created_at: active.map(row => row.created_at).sort().at(-1)!, retire_at: retired[0] || '',
      status: active.length >= 2 ? 'rotating' : active[0]!.retire_at ? 'retiring' : 'normal' }]
  })
}
export function templateCheck(body: string) {
  return parseImport(body).flatMap(row => row.lex ? [{ no: row.no, key: 'templateLex' }] :
    row.patch && ('dst_ip' in row.patch || 'dst_cidr' in row.patch) ? [{ no: row.no, key: 'templateTarget' }] : [])
}
export const templateCount = (body: string) => expandTargets('', body).template
export function settingsDelta(before: Settings, after: Settings): Partial<Settings> {
  return Object.fromEntries(Object.keys(before).filter(key => before[key as keyof Settings] !== after[key as keyof Settings]).map(key => [key, after[key as keyof Settings]]))
}
