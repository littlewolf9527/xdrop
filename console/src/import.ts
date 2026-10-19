import type { BatchResult, WriteError } from './api/types'
import { ApiError } from './api/client'
import { quote, numeric } from './rules'
export { numeric }
export const importKeys = ['src_ip', 'dst_ip', 'src_cidr', 'dst_cidr', 'src_port', 'dst_port', 'protocol', 'ttl', 'dscp', 'icmp_type', 'icmp_code', 'fragment', 'pkt_len', 'tcp_flags', 'match_anomaly', 'action', 'rate_limit', 'enabled', 'comment', 'expires_in'] as const
export type RulePatch = Record<string, string | number | boolean>
export type ImportStatus = 'pending' | 'lex' | 'new' | 'existing' | 'duplicate' | 'error' | 'rejected' | 'created' | 'renewed' | 'skipped' | 'duplicateSkipped' | 'unsent' | 'unknown'
export interface ImportLine { no: number; raw: string; patch?: RulePatch; lex?: { key: string; kind: 'invalid' | 'target' }; status: ImportStatus; error?: ApiError }
export function parseImport(text: string): ImportLine[] {
  return text.split('\n').flatMap<ImportLine>((raw, i) => {
    raw = raw.trim()
    if (!raw || raw.startsWith('#')) return []
    const row: ImportLine = { no: i + 1, raw, status: 'pending' }, patch: RulePatch = {}
    let at = 0, key = ''
    const bad = () => [{ ...row, status: 'lex' as const, lex: { key, kind: 'invalid' as const } }]
    while (at < raw.length) {
      while (/\s/.test(raw[at] || '') && at < raw.length) at++
      if (at === raw.length) break
      const start = at
      while (at < raw.length && !/\s/.test(raw[at]!) && raw[at] !== '=') at++
      key = raw.slice(start, at)
      if (raw[at] !== '=' || !importKeys.some(k => k === key) || Object.hasOwn(patch, key)) return bad()
      at++
      let value = ''
      if (raw[at] === '"') {
        at++; let closed = false
        while (at < raw.length) {
          const c = raw[at++]!
          if (c === '"') { closed = true; break }
          if (c !== '\\') { value += c; continue }
          const escape = raw[at++]!, escapes: Record<string, string> = { '\\': '\\', '"': '"', n: '\n', r: '\r', t: '\t' }
          if (!Object.hasOwn(escapes, escape)) return bad()
          value += escapes[escape]
        }
        if (!closed || (at < raw.length && !/\s/.test(raw[at]!))) return bad()
      } else {
        const start = at
        while (at < raw.length && !/\s/.test(raw[at]!)) at++
        value = raw.slice(start, at)
        if (value.includes('"')) return bad()
      }
      if (numeric.includes(key)) {
        if (!/^[0-9]+$/.test(value) || !Number.isSafeInteger(Number(value))) return bad()
        patch[key] = Number(value)
      } else if (key === 'enabled') {
        if (!['true', 'false'].includes(value)) return bad()
        patch[key] = value === 'true'
      } else patch[key] = value
    }
    return [{ ...row, patch }]
  })
}
export function expandTargets(text: string, body: string) {
  const targets = text.split('\n').map(s => s.trim()).filter(Boolean)
  const template = body.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#'))
  const rows = targets.flatMap(target => template.map(line => {
    const raw = (target.includes('/') ? 'dst_cidr' : 'dst_ip') + '=' + quote(target) + ' ' + line
    const parsed = parseImport(raw)[0]!
    const hasTarget = parseImport(line)[0]?.patch
    if (hasTarget && ('dst_ip' in hasTarget || 'dst_cidr' in hasTarget)) return { ...parsed, patch: undefined, status: 'lex' as const, lex: { key: 'dst_ip / dst_cidr', kind: 'target' as const } }
    return parsed
  })).map((row, i) => ({ ...row, no: i + 1 }))
  return { rows, targets: targets.length, template: template.length }
}
export function splitLines(rows: ImportLine[]): ImportLine[][] {
  const valid = rows.filter(r => r.patch), chunks: ImportLine[][] = []
  for (let i = 0; i < valid.length; i += 500) chunks.push(valid.slice(i, i + 500))
  return chunks
}
export function applyResults(sent: ImportLine[], result: BatchResult, phase: 'validate' | 'submit'): ImportLine[] {
  return sent.map((row, i) => {
    const item = result.results.find(r => r.index === i)
    if (!item) return { ...row, status: 'unknown' }
    if (item.error) return { ...row, status: 'error', error: new ApiError(400, item.error) }
    const status = phase === 'submit' ? item.existing ? 'renewed' : 'created' : item.existing ? item.rule?.id ? 'existing' : 'duplicate' : 'new'
    return { ...row, status }
  })
}
export const sendable = (rows: ImportLine[]) => rows.filter(r => r.status === 'new')
export const failedText = (rows: ImportLine[]) => rows.filter(r => ['error', 'rejected', 'unsent'].includes(r.status)).map(r => r.raw).join('\n')
export const receipt = (rows: ImportLine[]) => rows.map(r => ({ ...r, status: r.status === 'existing' ? 'skipped' as const : r.status === 'duplicate' ? 'duplicateSkipped' as const : r.status }))
export function rejectedRows(rows: ImportLine[], error: unknown): ImportLine[] {
  return rows.map(row => ({ ...row, status: 'rejected', error: error instanceof ApiError ? error : new ApiError(400, { code: 'bad_request', message: '' } as WriteError) }))
}
