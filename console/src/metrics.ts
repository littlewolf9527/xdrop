import type {
  Node, Point, History, Tightest
} from './api/types'
export const bits = (bytes: number): number => bytes * 8
export function metric(value: number | null | undefined, unit = ''): string {
  if (value == null || !Number.isFinite(value)) return '—'
  const exponent = value === 0 ? 0 : Math.max(0, Math.min(4, Math.floor(Math.log10(Math.abs(value)) / 3)))
  const n = value / 1000 ** exponent
  return `${new Intl.NumberFormat('en-US', {
    maximumFractionDigits: Math.abs(n) < 10 && exponent > 0 ? 2 : 0
  }).format(n)}${['', 'k', 'M', 'G', 'T'][exponent]}${unit ? ' ' + unit : ''}`
}
export const percent = (v: number | null): string => v === null ? '—' : `${Math.round(v * 100)}%`
export const level = (v: Pick<Tightest, 'ratio' | 'exhausted'>): string => v.exhausted || (v.ratio ?? 0) >= .9 ? 'crit' : (v.ratio ?? 0) >=
  .7 ? 'warn' : 'ok'
export const offlineNodes = (nodes: Node[]): Node[] => nodes.filter(n => !n.online)
export function syncState(n: Node): string {
  const sides = [n.rules, n.whitelist]
  if (sides.every(s => s.state === '')) return 'stopped'
  if (!n.online) return 'offline'
  if (n.incompatible) return 'incompatible'
  if (sides.some(s => s.state === 'overloaded')) return 'overloaded'
  if (sides.some(s => s.state === 'failed' || (s.rejected?.length ?? 0) > 0)) return 'failed'
  if (sides.some(s => s.state === 'pending') || !n.health.rules_synced || !n.health.whitelist_synced) return 'syncing'
  if (sides.every(s => s.state === 'normal' && s.confirmable) && n.health.rules_synced && n.health.whitelist_synced) return 'synced'
  return 'syncing'
}
export function gapPoints(history: History): (Point | {
  t: number;
  gap: true
})[] {
  if (history.step_s <= 0) return []
  const result: (Point | {
    t: number;
    gap: true
  })[] = []
  for (const p of history.points) {
    const last = result.at(-1)
    if (last) for (let t = last.t + history.step_s;
      t < p.t;
      t += history.step_s) result.push({
        t, gap: true
      })
    result.push(p)

  }
  return result
}
export function integerAxis(max: number): {
  scale: number;
  interval: number;
  max: number;
  suffix: string
} {
  const exponent = max > 0 ? Math.max(0, Math.min(4, Math.floor(Math.log10(max) / 3))) : 0
  const scale = 1000 ** exponent
  const required = Math.max(1, max / scale / 4)
  const power = 10 ** Math.floor(Math.log10(required))
  const interval = [1, 2, 5, 10].find(n => n * power >= required)! * power
  return {
    scale, interval, max: Math.max(interval, Math.ceil(max / scale / interval) * interval), suffix: ['', 'k', 'M', 'G', 'T'][exponent]!
  }
}
export function heartbeat(at: string, now: number): number | null {
  const stamp = Date.parse(at)
  return !Number.isFinite(stamp) || stamp <= 0 ? null : Math.max(0, Math.floor((now - stamp) / 1000))
}
