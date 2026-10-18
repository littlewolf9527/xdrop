import { ApiError } from './api/client'
import type { ErrorEnvelope } from './api/types'

export const auditGroups = [
  ['rule.create', 'rule.claim', 'rule.update', 'rule.release', 'rule.delete', 'rule.expire'],
  ['whitelist.create', 'whitelist.delete'],
  ['auth.login', 'auth.login_failed', 'auth.logout'],
  ['user.create', 'user.delete', 'user.password', 'user.role'],
  ['credential.issue', 'credential.revoke'],
  ['settings.update'],
  ['node.sync', 'node.reconcile', 'node.create', 'node.update', 'node.delete'],
  ['template.create', 'template.update', 'template.delete'],
] as const
export const auditActions: readonly string[] = auditGroups.flat()
export function auditActor(actor: string) { return actor.replace(/^(user|cred|system):/, '') || '—' }
const pad = (n: number) => String(n).padStart(2, '0')
export function auditTime(at: string) {
  const d = new Date(at)
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
export function auditFilename(format: 'csv' | 'json', d = new Date()) {
  return `xdrop-audit-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.${format}`
}
export class AuditInterrupted extends Error {}
export async function exportAudit(format: 'csv' | 'json', action: string, current: () => boolean, hooks: { expired: () => void; demoted: () => Promise<void> }) {
  const url = '/api/v1/audit/export?from=1970-01-01T00:00:00Z&to=9999-12-31T23:59:59Z&format=' + format + (action ? '&action=' + encodeURIComponent(action) : '')
  const response = await fetch(url, { credentials: 'same-origin' })
  if (!current()) { await response.body?.cancel().catch(() => {}); return }
  if (!response.ok) {
    const envelope = await response.json().catch(() => ({ code: 'network', message: 'Request failed' })) as ErrorEnvelope
    if (!current()) return
    if (response.status === 401 && envelope.code !== 'invalid_credentials') hooks.expired()
    if (response.status === 403 && envelope.code === 'admin_required') await hooks.demoted()
    if (!current()) return
    throw new ApiError(response.status, envelope, response.headers)
  }
  if (!response.body) throw new AuditInterrupted()
  const reader = response.body.getReader(), chunks: BlobPart[] = []
  try {
    while (true) {
      const chunk = await reader.read()
      if (!current()) { await reader.cancel().catch(() => {}); return }
      if (chunk.done) break
      chunks.push(new Uint8Array(chunk.value))
    }
  } catch { throw new AuditInterrupted() }
  finally { reader.releaseLock() }
  if (!current()) return
  const blob = new Blob(chunks, { type: format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json' })
  const href = URL.createObjectURL(blob), a = document.createElement('a')
  a.href = href; a.download = auditFilename(format); document.body.append(a)
  try { a.click() } finally { a.remove(); URL.revokeObjectURL(href) }
}
