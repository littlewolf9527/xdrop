import type { RuleDTO, RulePage, RuleCounts, TopAll } from './api/types'
import { ApiError } from './api/client'
export type RuleQuery = { q: string; state: '' | 'drop' | 'rate_limit' | 'disabled' }
export type FetchRules = (path: string) => Promise<RulePage>
export const conditionKeys = ['ttl', 'dscp', 'pkt_len', 'icmp_type', 'icmp_code', 'fragment', 'tcp_flags', 'match_anomaly'] as const
const numeric = ['src_port', 'dst_port', 'match_anomaly', 'rate_limit']
const fields = ['protocol', 'src_port', 'dst_port', ...conditionKeys, 'action', 'rate_limit', 'comment']
export function rulePath(query: RuleQuery, limit: number, after = 0, counts = false) {
  const p = new URLSearchParams({ limit: String(limit) })
  if (counts) p.set('counts', '1')
  if (after) p.set('after', String(after))
  if (query.q) p.set('q', query.q)
  if (query.state) p.set('state', query.state)
  return '/rules?' + p
}
export function listState() {
  return { rows: [] as RuleDTO[], counts: { all: 0, drop: 0, rate_limit: 0, disabled: 0 } as RuleCounts,
    next: null as number | null, applied: { q: '', state: '' } as RuleQuery, busy: false, error: null as unknown }
}
// The caller supplies its reactive state; every request owns both a list sequence and a session guard.
export function ruleList(s: ReturnType<typeof listState>, fetch: FetchRules, capture: () => { isCurrent(): boolean }, begin = () => {}, queuedRefresh?: () => void) {
  let sequence = 0, stopped = false, userPending = false, refreshPending = false
  let pendingQuery: RuleQuery = s.applied
  async function run(kind: 'query' | 'more' | 'refresh', query = s.applied) {
    if (stopped || (kind === 'more' && (userPending || s.busy || s.next === null))) return
    if (kind === 'refresh' && userPending) { refreshPending = true; return }
    const serial = ++sequence, session = capture(), current = () => !stopped && serial === sequence && session.isCurrent()
    if (kind === 'query') { userPending = true; pendingQuery = { ...query } }
    if (kind === 'query' || kind === 'more') begin()
    s.busy = true
    const applied = { q: query.q.trim(), state: query.state }, wanted = s.rows.length
    const limit = kind === 'refresh' ? Math.min(1000, Math.max(100, wanted)) : 100
    let after = kind === 'more' ? s.next! : 0, rows: RuleDTO[] = [], counts = s.counts, next: number | null = null
    try {
      do {
        const page = await fetch(rulePath(applied, limit, after, kind !== 'more' && rows.length === 0))
        if (!current()) return
        rows.push(...page.items); next = page.next_after
        if (page.counts) counts = page.counts
        if (kind !== 'refresh' || rows.length >= wanted || next === null) break
        after = next
      } while (true)
      if (!current()) return
      s.rows = kind === 'more' ? [...s.rows, ...rows] : rows
      s.counts = counts; s.next = next; s.applied = applied; s.error = null
    } catch (error) { if (current()) s.error = error }
    finally {
      if (current()) {
        s.busy = false
        if (kind === 'query') {
          userPending = false
          if (refreshPending) { refreshPending = false; if (queuedRefresh) queuedRefresh(); else void run('refresh') }
        }
      }
    }
  }
  return { query: (q: RuleQuery) => run('query', q), more: () => run('more'), refresh: () => run('refresh'),
    written: () => userPending ? run('query', pendingQuery) : run('refresh'),
    stop: () => { stopped = true; sequence++ } }
}
export function searchError(e: unknown) {
  return e instanceof ApiError && e.status === 400 && e.envelope.code === 'bad_request' && e.envelope.field === 'q'
}
export const target = (r: RuleDTO) => r.dst_ip || r.dst_cidr || r.src_ip || r.src_cidr
export const direction = (r: RuleDTO) => r.dst_ip || r.dst_cidr ? 'destination' : 'source'
export function grouped(rows: RuleDTO[]) {
  const groups = new Map<string, { first: string; count: number }>()
  for (const r of rows) { const g = groups.get(r.group_key); if (g) g.count++; else groups.set(r.group_key, { first: r.id, count: 1 }) }
  return groups
}
export function ruleRate(r: RuleDTO, top: TopAll | null): [number, number] | null {
  if (!r.enabled) return null
  if (!top || top.updated_at === null) return null
  const rate = top.rules.find(v => v.rule_id === r.id)
  return rate ? [rate.dropped_pps, rate.dropped_bytes_ps * 8] : null
}
export function remaining(r: RuleDTO, now: number) {
  if (!r.expires_at) return ''
  const minutes = Math.floor((Date.parse(r.expires_at) - now) / 60000)
  return minutes < 1 ? '< 1m' : `${Math.floor(minutes / 60)}h ${minutes % 60}m`
}
export type RuleForm = Record<string, string> & { enabled: string }
export function ruleForm(r?: RuleDTO): RuleForm {
  const f: RuleForm = { src_address: r?.src_ip || r?.src_cidr || '', dst_address: r?.dst_ip || r?.dst_cidr || '',
    expires_mode: r?.expires_at ? 'duration' : 'permanent',
    expires_in: r?.expires_at ? String(Math.max(1, Math.ceil((Date.parse(r.expires_at) - Date.now()) / 60000))) : '', enabled: String(r?.enabled ?? true) }
  for (const k of fields) { const v = r?.[k as keyof RuleDTO]; f[k] = v === null || v === undefined || v === 0 ? '' : String(v).trim() }
  f.protocol ||= 'all'; f.action ||= 'drop'
  return f
}
export function ruleBody(form: RuleForm, initial?: RuleForm, rule?: RuleDTO): Record<string, string | number | boolean> {
  const body: Record<string, string | number | boolean> = {}
  for (const side of ['src', 'dst']) {
    const text = form[side + '_address']!.trim(), old = initial?.[side + '_address']!.trim()
    if (initial && text === old) continue
    const key = side + (text.includes('/') ? '_cidr' : '_ip')
    if (text) body[key] = text
    if (rule) for (const suffix of ['_ip', '_cidr']) {
      const oldKey = (side + suffix) as keyof RuleDTO
      if (rule[oldKey] && (!text || oldKey !== key)) body[oldKey] = ''
    }
  }
  for (const k of fields) {
    const value = form[k]!.trim()
    if (k === 'rate_limit' && form.action === 'drop') continue
    if (initial && value === initial[k]!.trim()) continue
    if (!initial && !value) continue
    body[k] = numeric.includes(k) ? !value ? 0 : /^[0-9]+$/.test(value) && Number.isSafeInteger(Number(value)) ? Number(value) : value : value
  }
  if (!initial) body.enabled = form.enabled === 'true'
  if (!initial || form.expires_mode !== initial.expires_mode || form.expires_in.trim() !== initial.expires_in.trim()) {
    if (form.expires_mode === 'permanent') { if (initial) body.expires_in = '' }
    else if (form.expires_in.trim()) { const value = form.expires_in.trim(); body.expires_in = /^[0-9]+$/.test(value) ? value + 'm' : value }
    else if (initial) body.expires_in = ''
  }
  return body
}
export class ExportExpired extends Error {}
export function exportDuration(at: string, now: number) {
  const seconds = (Date.parse(at) - now) / 1000
  if (seconds <= 0) throw new ExportExpired()
  const minutes = Math.ceil(seconds / 60)
  const s = minutes * 60 > 9223372036.854775807 ? Math.min(9223372036, Math.floor(seconds)) : minutes * 60
  return (Math.floor(s / 3600) ? Math.floor(s / 3600) + 'h' : '') +
    (Math.floor(s % 3600 / 60) ? Math.floor(s % 3600 / 60) + 'm' : '') + (s % 60 ? s % 60 + 's' : '')
}
export function quote(value: string) {
  return /[\s"\\#]/.test(value) || value === '' ? '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t') + '"' : value
}
export function serializeRule(r: RuleDTO, now: number) {
  const values: Record<string, unknown> = { ...r, expires_in: r.expires_at ? exportDuration(r.expires_at, now) : '' }
  const keys = ['src_ip', 'dst_ip', 'src_cidr', 'dst_cidr', 'src_port', 'dst_port', 'protocol', 'ttl', 'dscp', 'icmp_type',
    'icmp_code', 'fragment', 'pkt_len', 'tcp_flags', 'match_anomaly', 'action', 'rate_limit', 'enabled', 'comment', 'expires_in']
  return keys.filter(k => k === 'protocol' || k === 'action' || k === 'enabled' ? k !== 'enabled' || !r.enabled :
    k === 'rate_limit' ? r.action === 'rate_limit' : values[k] !== '' && values[k] != null && values[k] !== 0)
    .map(k => k + '=' + quote(String(values[k]))).join(' ')
}
export function localISO(date: Date) {
  const offset = -date.getTimezoneOffset(), local = new Date(date.getTime() + offset * 60000).toISOString().slice(0, 19)
  return local + (offset >= 0 ? '+' : '-') + String(Math.floor(Math.abs(offset) / 60)).padStart(2, '0') + ':' + String(Math.abs(offset) % 60).padStart(2, '0')
}
export async function exportRules(query: RuleQuery, fetch: FetchRules, current: () => boolean, progress: (n: number) => void, now = () => Date.now()) {
  let after = 0, count = 0
  const lines = ['# xdrop rules ' + localISO(new Date(now()))]
  do {
    const page = await fetch(rulePath(query, 1000, after))
    if (!current()) throw new Error('Session ended')
    const received = now()
    lines.push(...page.items.map(r => serializeRule(r, received)))
    count += page.items.length; progress(count)
    if (page.next_after === null) break
    after = page.next_after
  } while (true)
  return lines.join('\n') + '\n'
}
