import { auditActions } from '../src/audit'
import type { AuditEvent, RuleDTO, WriteError, WhitelistDTO, TemplateDTO, UserDTO, CredentialDTO, NodeTestDTO } from '../src/api/types'
import type {
  Plugin
} from 'vite'
interface Request extends AsyncIterable<Uint8Array> {
  url?: string;
  method?: string;
  headers: {
    cookie?: string
  };
  once(event: string, callback: () => void): void;

}
interface Response {
  statusCode: number;
  setHeader(name: string, value: string): void;
  write(value: string): void;
  end(value?: string): void;
  writeHead(status: number, headers: Record<string, string>): void;

}
const netModule = 'node:net'
const { isIP } = await import(netModule) as { isIP(value: string): number }
// Positive build-scan control: XDROP_MOCK_ONLY /__mock/revoke
export function mockPlugin(): Plugin {
  return {
    name: 'xdrop-development-mock', configureServer(server) {
      const prefs: Record<string, unknown> = {
      }, sessions = new Map<string, string>(), failures = new Map<string, number>()
      const streams = new Map<Response, string>()
      let serial = 0, ruleSeq = 42, nextRule = 240, topReads = 0
      const makeRule = (n: number, patch: Record<string, unknown> = {}): RuleDTO => ({
        id: 'rule_' + n.toString(16).padStart(32, '0'), logical_id: n, src_ip: '', src_cidr: '',
        dst_ip: '192.0.2.' + ((n - 1) % 240 + 1), dst_cidr: '', src_port: 0, dst_port: 0, protocol: 'all',
        ttl: null, dscp: null, pkt_len: null, icmp_type: null, icmp_code: null, fragment: null, tcp_flags: '', match_anomaly: 0,
        action: 'drop', rate_limit: 0, enabled: true, comment: '', kind: 'exact', group_key: 'group-' + n, cond_key: '',
        created_at: new Date().toISOString(), updated_at: new Date().toISOString(), expires_at: null,
        created_by: 'user:admin', updated_by: 'user:admin', ...patch,
      } as RuleDTO)
      const rules = Array.from({ length: 240 }, (_, i) => makeRule(i + 1, {
        ...(i % 7 === 0 ? { enabled: false } : {}), ...(i % 4 === 0 ? { action: 'rate_limit', rate_limit: 20000 } : {}),
        ...(i % 5 === 0 ? { protocol: 'udp', dst_port: 53, pkt_len: '64-512' } : {}),
        ...(i % 6 === 0 ? { src_ip: '198.51.100.7' } : {}),
        ...(i % 9 === 0 ? { dst_ip: '2001:db8::' + (i + 1).toString(16), src_ip: '' } : {}),
        ...(i % 11 === 0 ? { expires_at: new Date(Date.now() + 7200000).toISOString() } : {}),
        ...(i >= 1 && i <= 3 ? { dst_ip: '203.0.113.7', protocol: 'tcp', dst_port: 443, ttl: String(61 + i), group_key: 'shared-three' } : {}),
        ...(i === 7 ? { dst_ip: '', dst_cidr: '198.51.100.0/24', kind: 'cidr' } : {}),
      }))
      const validate = (b: Record<string, unknown>, prefix = ''): WriteError | undefined => {
        for (const key of ['src_port', 'dst_port', 'match_anomaly', 'rate_limit']) if (key in b && typeof b[key] !== 'number') return { code: 'bad_request', message: 'decode error', field: prefix + key }
        for (const key of ['src_port', 'dst_port']) if (Number(b[key]) > 65535) return { code: 'invalid_rule', message: 'invalid port', field: key }
        if (['icmp','icmpv6'].includes(String(b.protocol)) && (b.src_port || b.dst_port)) return { code: 'invalid_rule', message: 'protocol with port', field: 'protocol' }
        if (['src_ip','dst_ip'].some(k => b[k] && !/^[0-9a-fA-F:.]+$/.test(String(b[k])))) return { code: 'invalid_rule', message: 'address', field: 'ip' }
        if (b.expires_in && !/^(?:[0-9]+[hms])+$/.test(String(b.expires_in))) return { code: 'invalid_expires_in', message: 'duration' }
        if (b.ttl === '1,2,3,4,5') return { code: 'condition_capacity', message: 'capacity', rule_ids: [rules[1]!.id, 'batch:0'] }
      }
      const apply = (r: RuleDTO, b: Record<string, unknown>) => {
        const patch = { ...b }; delete patch.expires_in
        Object.assign(r, patch)
        if ('expires_in' in b) r.expires_at = b.expires_in ? new Date(Date.now() + [...String(b.expires_in).matchAll(/(\d+)([hms])/g)].reduce((n, m) => n + Number(m[1]) * ({ h: 3600, m: 60, s: 1 }[m[2]!] || 0), 0) * 1000).toISOString() : null
        if (r.action === 'drop') r.rate_limit = 0
        r.group_key = JSON.stringify([r.src_ip, r.dst_ip, r.src_cidr, r.dst_cidr, r.protocol, r.src_port, r.dst_port])
        return r
      }
      const identical = (b: Record<string, unknown>) => rules.find(r => ['src_ip','dst_ip','src_cidr','dst_cidr','protocol','src_port','dst_port','ttl'].every(k => String(r[k as keyof RuleDTO] ?? '') === String(b[k] ?? (k === 'protocol' ? 'all' : k.endsWith('port') ? 0 : ''))))
      const identity = (r: RuleDTO, b: Record<string, unknown>) => ['src_ip','dst_ip','src_cidr','dst_cidr','protocol','src_port','dst_port','ttl'].every(k => String(r[k as keyof RuleDTO] ?? '') === String(b[k] ?? (k === 'protocol' ? 'all' : k.endsWith('port') ? 0 : '')))
      const createRule = (item: Record<string, unknown>, pool: RuleDTO[], dry: boolean, refs = new Map<RuleDTO, number>(), index = 0) => {
        const error = validate(item, 'items.')
        if (error) return { error }
        const proposed = apply(makeRule(nextRule + 1, { dst_ip: '' }), item), old = pool.find(r => identity(r, item))
        if (old) {
          const ruleID = old.id || (refs.has(old) ? 'batch:' + refs.get(old) : '')
          if (old.action !== proposed.action || old.rate_limit !== proposed.rate_limit) return { error: { code: 'rule_conflict', message: 'conflict', ...(ruleID ? { rule_id: ruleID } : {}) } }
          if (old.expires_at && (!proposed.expires_at || proposed.expires_at > old.expires_at)) old.expires_at = proposed.expires_at
          return { existing: true, rule: { ...old }, ...(!dry ? { gen: 42 } : {}) }
        }
        if (dry) { proposed.id = ''; refs.set(proposed, index) }
        else { proposed.logical_id = ++nextRule; proposed.id = 'rule_' + nextRule.toString(16).padStart(32, '0') }
        pool.push(proposed)
        return { existing: false, rule: proposed, ...(!dry ? { gen: 42 } : {}) }
      }
      const whitelist: WhitelistDTO[] = [
        { id: 'wl_1', src_ip: '192.0.2.10', dst_ip: '', src_port: 123, dst_port: 0, protocol: 'udp', comment: 'NTP', created_at: '2026-10-02T06:20:00Z', created_by: 'user:admin' },
        { id: 'wl_2', src_ip: '', dst_ip: '198.51.100.1', src_port: 0, dst_port: 179, protocol: 'tcp', comment: 'BGP', created_at: '2026-09-28T01:03:00Z', created_by: 'user:admin' },
        { id: 'wl_3', src_ip: '203.0.113.5', dst_ip: '', src_port: 0, dst_port: 0, protocol: 'all', comment: '监控', created_at: '2026-10-11T14:41:00Z', created_by: 'user:admin' },
        { id: 'wl_4', src_ip: '192.0.2.20', dst_ip: '198.51.100.20', src_port: 123, dst_port: 179, protocol: 'tcp', comment: '双侧', created_at: '2026-10-12T14:41:00Z', created_by: 'user:admin' },
      ]
      const templates: TemplateDTO[] = ['UDP 反射丢弃', 'SYN 限速'].map((name, i) => ({ id: 'template_' + i, name, body: i ? 'protocol=tcp tcp_flags=SYN,!ACK action=rate_limit rate_limit=50000' : 'protocol=udp src_port=53 action=drop expires_in=6h\nprotocol=udp src_port=123 action=drop expires_in=6h', created_at: '2026-10-16T12:00:00Z', updated_at: '2026-10-16T12:00:00Z', created_by: 'user:admin', updated_by: 'user:admin' }))
      let emptyTemplates = false, rejectBatch = false
      let auditCut = false, passwordThrottle = false, auditEmpty = false, auditError = false
      const audit: AuditEvent[] = Array.from({ length: 330 }, (_, i) => {
        const action = i < 160 ? 'auth.login' : auditActions[(i - 160) % auditActions.length]!
        return { id: i + 1, at: new Date(Date.UTC(2026, 9, 17, 0, 0, Math.floor(i / 3))).toISOString().replace('.000Z', 'Z'),
          actor: action === 'auth.login_failed' ? '' : ['user:admin', 'cred:monitor', 'system:expiry'][i % 3]!, source: i % 5 ? '192.0.2.30' : '',
          action, target: action.startsWith('user.') || action.startsWith('auth.') ? 'user:operator' : action.split('.')[0] + ':' + (i + 1),
          before: i % 3 ? null : { enabled: false }, after: i % 4 ? { enabled: true } : null }
      })
      const auditTimeValid = (v: string) => /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString().replace('.000Z', 'Z') === v

      const side = (state = 'normal') => ({
        state, reason: '', since: new Date().toISOString(), confirmed_gen: 42, confirmable: state === 'normal', rejected: []
      })
      const seedSnapshot = () => {
        const now = new Date().toISOString()
        return {
          epoch: 'development', nodes: [
            {
              name: 'edge-01', online: true, incompatible: false, base_url: 'http://192.0.2.10', key_unreadable: false, overload: [],
                rules: side(), whitelist: side(), health_at: now, health: {
                status: 'ok', rules_synced: true, whitelist_synced: true
              }, stats_at: now, stats: {
                system: {
                  cpu_percent: 24, mem_percent: 38
                }
              }, rates: {
                dropped_packets: 830400, passed_packets: 220000, dropped_bytes: 534600000, passed_bytes: 172500000
              }
            },
            {
              name: 'edge-02', online: true, incompatible: false, base_url: 'http://192.0.2.11', key_unreadable: false, overload: [],
                rules: side('pending'), whitelist: side(), health_at: now, health: {
                status: 'ok', rules_synced: false, whitelist_synced: true
              }, stats_at: now, stats: {
                system: {
                  cpu_percent: 74, mem_percent: 63
                }
              }, rates: {
                dropped_packets: 369600, passed_packets: 100000, dropped_bytes: 245400000, passed_bytes: 77500000
              }
            },
            {
              name: 'edge-03', online: false, incompatible: false, base_url: 'http://192.0.2.12', key_unreadable: false, overload: [],
                rules: side('failed'), whitelist: side('failed'), health_at: new Date(Date.now() - 240000).toISOString(), health: {
                status: '', rules_synced: false, whitelist_synced: false
              }, stats_at: '', stats: null, rates: null
            },
            {
              name: 'edge-04', online: false, incompatible: false, base_url: 'http://192.0.2.13', key_unreadable: true, overload: null, rules: {
                ...side(''), confirmed_gen: 0, rejected: null
              }, whitelist: {
                ...side(''), confirmed_gen: 0, rejected: null
              }, health_at: '', health: {
                status: '', rules_synced: false, whitelist_synced: false
              }, stats_at: '', stats: null, rates: null
            },
          ]
        }

      }
      const managedNodes = seedSnapshot().nodes
      const snapshot = () => ({ epoch: 'development', nodes: managedNodes })
      const validName = /^[A-Za-z0-9._-]{1,64}$/
      const users: UserDTO[] = ['admin','operator'].map(name => ({ username: name, role: name as 'admin' | 'operator', created_at: '2026-10-01T00:00:00Z', created_by: name === 'admin' ? '' : 'user:admin', password_changed_at: '2026-10-16T12:00:00Z' }))
      const passwords = new Map(users.map(row => [row.username, 'example-password-1']))
      const credentials: CredentialDTO[] = ['xsight','xsight','monitor','old','old','lone'].map((name,i) => ({ id: 'fixture-' + i, name, created_at: '2026-10-0' + (i+1) + 'T00:00:00Z', created_by: 'user:admin', retire_at: i === 0 || i === 5 ? new Date(Date.now()+86400000).toISOString() : null, revoked_at: name === 'old' ? '2026-10-07T00:00:00Z' : null, revoked_by: name === 'old' ? 'user:admin' : null, active: name !== 'old' }))
      const active = (c: CredentialDTO) => c.revoked_at === null && (c.retire_at === null || Date.now() < Date.parse(c.retire_at))
      let nodeTestResult: NodeTestDTO = { reachable: true, compatible: true, key_accepted: true, message: '' }
      const keys = ['blacklist', 'cidr_blacklist', 'cond', 'cidr_cond', 'whitelist', 'sv4_cidr_trie', 'dv4_cidr_trie', 'sv6_cidr_trie',
        'dv6_cidr_trie', 'logical_state']
      const capacity = () => {
        const dimensions = keys.map((name, index) => {
          const limit = name === 'cond' ? 4000 : 50000, used = [1102, 182, 2840, 96, 37, 11, 171, 8, 4, 1284][index]!;
          return {
            name, used, limit, admission_limit: limit, limit_source: index % 2 ? 'edge-01' : 'edge-02', free: limit - used, ratio: used /
              limit, exhausted: false
          }
        })
        const {
          name, limit_source, free, ratio, exhausted
        } = dimensions[2]!
        return {
          dimensions, tightest: {
            name, limit_source, free, ratio, exhausted
          }, candidates: {
            limit: 4, full_keys: 0, near_keys: 0
          }, rules: {
            enabled: 1284, total: 1300
          }, overloaded_nodes: []
        }

      }
      const targets = ['198.51.100.7', '203.0.113.24', '192.0.2.80', '2001:db8::8', '198.51.100.48']
      const top = () => ({
        targets_total: 8, updated_at: new Date().toISOString(), incomplete: true, total_dropped_pps: 1200000, total_dropped_bytes_ps: 780000000,
        targets: targets.map((target, i) => ({
          target, dropped_pps: [830400, 190200, 99600, 49200, 30600][i], dropped_bytes_ps: [534600000, 123600000, 69000000, 31000000,
            21800000][i], share: [.692, .1585, .083, .041, .0255][i], rules: i + 1
        })),
        rules: targets.map((target, i) => ({
          rule_id: 'rule_development_' + i, target, dropped_pps: [512300, 288100, 172600, 68800, 41400][i], dropped_bytes_ps: [461250000,
            140000000, 90250000, 49500000, 30875000][i], share: [512300, 288100, 172600, 68800, 41400][i]! / 1200000, nodes: 2
        })),

      })
      const overview = () => ({
        dropped_pps: 1200000, passed_pps: 320000, dropped_bytes_ps: 780000000, passed_bytes_ps: 250000000, nodes_online: 2, nodes_total: 4
      })
      const settings = {
        session_hours: 24, audit_retention_days: 180, reconcile_interval_minutes: 15, default_language: 'en-US', history_retention_days: 30
      }
      const frame = (res: Response) => {
        for (const [name, payload] of [['rules', {
          seq: ruleSeq, gen: 42
        }], ['nodes', {
          ...snapshot(), reconcile: {
          }
        }], ['traffic', {
          overview: overview(), top: top()
        }]]) res.write(`event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`)
      }
      const timer = setInterval(() => {
        for (const res of streams.keys()) frame(res)
      }, 5000)
      server.httpServer?.once('close', () => clearInterval(timer))
      server.middlewares.use(async (incoming, res, next) => {
        const req = incoming as unknown as Request
        const url = new URL(req.url || '/', 'http://127.0.0.1'), path = url.pathname.replace(/^\/api\/v1/, '')
        if (!url.pathname.startsWith('/api/') && !url.pathname.startsWith('/__mock/')) return next()
        const reply = (status: number, value?: unknown) => {
          res.statusCode = status;
          res.setHeader('Content-Type', 'application/json');
          res.end(value === undefined ? '' : JSON.stringify(value))
        }
        const token = req.headers.cookie?.split(';').map(s => s.trim()).find(s => s.startsWith('xdrop_session='))?.split('=')[1] ?? ''
        const user = sessions.get(token)
        const currentUser = users.find(row => row.username === user)
        const adminRoute = (path === '/credentials' || path.startsWith('/credentials/')) ||
          (req.method !== 'GET' && (/^\/(users|templates)(\/|$)/.test(path) || path === '/settings' || /^\/nodes(?:\/[^/]+)?(?:\/test)?$/.test(path)))
        if (adminRoute && !user) return reply(401, { code: 'unauthenticated', message: 'unauthenticated' })
        if (adminRoute && currentUser?.role !== 'admin') return reply(403, { code: 'admin_required', message: 'administrator required' })
        let body: Record<string, unknown> = {
        }
        if (['POST', 'PUT', 'PATCH'].includes(req.method || '')) {
          let raw = '';
          for await (const chunk of req) raw += String(chunk);
          try {
            body = raw ? JSON.parse(raw) : {
            }
          } catch {
            return reply(400, {
              code: 'bad_request', message: 'bad request'
            })
          }
        }
        if (path === '/auth/login') {
          const name = String(body.username), attempts = failures.get(name) || 0
          if (attempts >= 3) {
            res.setHeader('Retry-After', '60');
            return reply(429, {
              code: 'login_throttled', message: 'login failed'
            })
          }
          if (!passwords.has(name) || body.password !== passwords.get(name)) {
            failures.set(name, attempts + 1);
            return reply(401, {
              code: 'invalid_credentials', message: 'invalid credentials'
            })
          }
          failures.delete(name);
          const id = 'development-' + ++serial;
          sessions.set(id, name)
          res.setHeader('Set-Cookie', `xdrop_session=${id}; Path=/api/v1; HttpOnly; SameSite=Strict`)
          return reply(200, {
            username: name, expires_at: new Date(Date.now() + 86400000).toISOString()
          })

        }
        if (url.pathname === '/__mock/revoke') {
          for (const r of streams.keys()) r.end();
          streams.clear();
          sessions.clear();
          return reply(204)
        }
        if (!user) return reply(401, {
          code: 'unauthenticated', message: 'unauthenticated'
        })
        if (path === '/auth/me') return reply(200, {
          kind: 'user', name: user, role: currentUser?.role
        })
        if (path === '/auth/logout') {
          sessions.delete(token);
          for (const [r, id] of streams) if (id === token) {
            r.end();
            streams.delete(r)
          };
          return reply(204)
        }

        if (path === '/auth/me/password' && req.method === 'PUT') {
          if (Object.keys(body).some(k => !['current_password','password'].includes(k)) || ['current_password','password'].some(k => k in body && typeof body[k] !== 'string')) return reply(400, { code: 'bad_request', message: 'bad request' })
          const size = new TextEncoder().encode(String(body.password || '')).length
          if (size < 10 || size > 72) return reply(400, { code: 'invalid_field', field: 'password', message: 'invalid field' })
          if (passwordThrottle || (failures.get(user) || 0) >= 3) return reply(429, { code: 'login_throttled', message: 'login failed' })
          if (body.current_password !== 'example-password-1') {
            failures.set(user, (failures.get(user) || 0) + 1)
            return reply(401, { code: 'invalid_credentials', message: 'invalid credentials' })
          }
          failures.delete(user)
          for (const [id, name] of sessions) if (name === user) {
            sessions.delete(id)
            for (const [stream, session] of streams) if (session === id) { stream.end(); streams.delete(stream) }
          }
          res.setHeader('Set-Cookie', 'xdrop_session=; Path=/api/v1; Max-Age=0; HttpOnly; SameSite=Strict')
          return reply(204)
        }
        if ((path === '/audit' || path === '/audit/export') && req.method === 'GET') {
          const exporting = path === '/audit/export', query = url.searchParams, format = query.get('format')
          if (exporting && currentUser?.role !== 'admin') return reply(403, { code: 'admin_required', message: 'administrator required' })
          for (const field of ['from','to']) if ((exporting || query.get(field)) && !auditTimeValid(query.get(field) || '')) return reply(400, { code: 'invalid_field', field, message: 'invalid field' })
          if (exporting && format !== 'csv' && format !== 'json') return reply(400, { code: 'invalid_field', field: 'format', message: 'invalid field' })
          const matched = (auditEmpty ? [] : audit).filter(row => (!query.get('action') || row.action === query.get('action')) && (!query.get('from') || row.at >= query.get('from')!) && (!query.get('to') || row.at < query.get('to')!))
          if (exporting) {
            const csv = (value: unknown) => { let cell = value === null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value); if (/^[=+\-@\t\r]/.test(cell)) cell = "'" + cell; return /[",\r\n]/.test(cell) ? '"' + cell.replace(/"/g, '""') + '"' : cell }
            const text = format === 'json' ? JSON.stringify(matched) : 'id,at,actor,source,action,target,before,after\n' + matched.map(row => [row.id,row.at,row.actor,row.source,row.action,row.target,row.before,row.after].map(csv).join(',') + '\n').join('')
            res.setHeader('Content-Type', format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json')
            res.setHeader('Content-Disposition', `attachment; filename="xdrop-audit-${query.get('from')}-${query.get('to')}.${format}"`)
            const size = Math.max(1, Math.ceil(text.length / 3)); res.write(text.slice(0, size))
            setTimeout(() => { res.write(text.slice(size, size * 2)); setTimeout(() => { if (auditCut) res.destroy(); else res.end(text.slice(size * 2)) }, 10) }, 10)
            return
          }
          if (auditError) return reply(400, { code: 'invalid_field', field: 'cursor', message: 'invalid field' })
          const rawLimit = query.get('limit') ?? '100', limit = Number(rawLimit)
          if (!/^[+-]?\d+$/.test(rawLimit) || !Number.isInteger(limit) || limit < 1 || limit > 1000) return reply(400, { code: 'invalid_field', field: 'limit', message: 'invalid field' })
          let cursor: { At: string; ID: number } | undefined
          if (query.get('cursor')) {
            try { cursor = JSON.parse(atob(query.get('cursor')!.replace(/-/g, '+').replace(/_/g, '/'))); if (!cursor || !auditTimeValid(cursor.At) || !Number.isSafeInteger(cursor.ID) || cursor.ID < 1) throw new Error() }
            catch { return reply(400, { code: 'invalid_field', field: 'cursor', message: 'invalid field' }) }
          }
          const sorted = matched.filter(row => !cursor || row.at < cursor.At || (row.at === cursor.At && row.id < cursor.ID)).slice().reverse(), items = sorted.slice(0, limit), last = items.at(-1)
          const next_cursor = sorted.length > items.length && last ? btoa(JSON.stringify({ At: last.at, ID: last.id })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') : ''
          return reply(200, { items, next_cursor })
        }
        if (path === '/auth/me/prefs') {
          if (req.method === 'PUT') {
            prefs[user] = body;
            return reply(204)
          };
          return reply(200, prefs[user] || {
          })
        }
        const invalid = (field: string) => reply(400, { code: 'invalid_field', field, message: 'invalid field' })
        const accountError = (code: string, status = 409) => reply(status, { code, message: code })
        const bytes = (value: string) => new TextEncoder().encode(value).length
        const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
        const decode = (fields: string[], numeric: string[] = []) => {
          const field = Object.keys(body).find(k => !fields.includes(k) || (body[k] !== null && (numeric.includes(k) ? !Number.isInteger(body[k]) : typeof body[k] !== 'string')))
          if (field === undefined) return true
          reply(400, { code: 'bad_request', field, message: 'invalid JSON request' }); return false
        }
        const invalidateUser = (name: string) => {
          for (const [id, owner] of sessions) if (owner === name) {
            sessions.delete(id)
            for (const [stream, session] of streams) if (session === id) { stream.end(); streams.delete(stream) }
          }
        }
        if (path === '/users' && req.method === 'GET') return reply(200, [...users].sort((a,b) => a.username < b.username ? -1 : a.username > b.username ? 1 : 0))
        if (path === '/users' && req.method === 'POST') {
          if (!decode(['username','role','password'])) return
          const name = String(body.username ?? ''), role = String(body.role ?? ''), password = String(body.password ?? '')
          if (!validName.test(name)) return invalid('username')
          if (!['admin','operator'].includes(role)) return invalid('role')
          if (bytes(password) < 10 || bytes(password) > 72) return invalid('password')
          if (users.some(row => row.username === name)) return accountError('user_exists')
          users.push({ username: name, role: role as 'admin' | 'operator', created_at: now(), created_by: 'user:' + user, password_changed_at: now() }); passwords.set(name, password)
          return reply(201)
        }
        const userRoute = /^\/users\/([^/]+)(?:\/(password|role))?$/.exec(path)
        if (userRoute) {
          const name = decodeURIComponent(userRoute[1]!), operation = userRoute[2], row = users.find(u => u.username === name)
          if (operation && !decode([operation])) return
          if (operation === 'password' && (bytes(String(body.password ?? '')) < 10 || bytes(String(body.password ?? '')) > 72)) return invalid('password')
          if (operation === 'role' && !['admin','operator'].includes(String(body.role))) return invalid('role')
          if (!row) return accountError('user_not_found', 404)
          if (req.method === 'DELETE') {
            if (users.length === 1) return accountError('last_user')
            if (row.role === 'admin' && users.filter(u => u.role === 'admin').length === 1) return accountError('last_admin')
            users.splice(users.indexOf(row), 1); passwords.delete(name); failures.delete(name); invalidateUser(name); return reply(204)
          }
          if (req.method === 'PUT' && operation === 'password') { passwords.set(name, String(body.password)); row.password_changed_at = now(); invalidateUser(name); return reply(204) }
          if (req.method === 'PUT' && operation === 'role') {
            if (row.role === body.role) return reply(204)
            if (row.role === 'admin' && users.filter(u => u.role === 'admin').length === 1) return accountError('last_admin')
            row.role = body.role as 'admin' | 'operator'; return reply(204)
          }
        }
        if (path === '/credentials' && req.method === 'GET') return reply(200, credentials.map(c => ({ ...c, active: active(c) })).sort((a,b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id)))
        if (path === '/credentials' && req.method === 'POST') {
          if (!decode(['name'])) return
          const name = String(body.name ?? ''); if (!validName.test(name)) return invalid('name')
          const at = now(), end = new Date(Date.now() + 86400000).toISOString().replace(/\.\d{3}Z$/, 'Z'), retired: { id: string; retire_at: string }[] = []
          for (const old of credentials) if (old.name === name && active(old) && (!old.retire_at || old.retire_at > end)) { old.retire_at = end; retired.push({ id: old.id, retire_at: end }) }
          const id = String(++serial).padStart(16, '0')
          credentials.push({ id, name, created_at: at, created_by: 'user:' + user, retire_at: null, revoked_at: null, revoked_by: null, active: true })
          return reply(201, { id, name, key: 'xdk_' + '0'.repeat(16) + '_' + 'A'.repeat(43), created_at: at, retired })
        }
        if (path.startsWith('/credentials/') && req.method === 'DELETE') {
          const row = credentials.find(c => c.id === decodeURIComponent(path.slice('/credentials/'.length)))
          if (!row) return accountError('credential_not_found', 404)
          if (!row.revoked_at) { row.revoked_at = now(); row.revoked_by = 'user:' + user; row.active = false }
          return reply(204)
        }
        if (path === '/settings' && req.method === 'PUT') {
          const numeric = ['session_hours','audit_retention_days','history_retention_days','reconcile_interval_minutes']
          if (!decode([...numeric, 'default_language'], numeric)) return
          for (const [field, max] of [['session_hours',720],['audit_retention_days',3650],['history_retention_days',90],['reconcile_interval_minutes',1440]] as const) {
            if (body[field] != null && (Number(body[field]) < 1 || Number(body[field]) > max)) return invalid(field)
          }
          if (body.default_language != null && !['zh-CN','ja-JP','en-US'].includes(String(body.default_language))) return invalid('default_language')
          Object.assign(settings, Object.fromEntries(Object.entries(body).filter(([,v]) => v !== null))); return reply(200, settings)
        }
        const templateRoute = /^\/templates(?:\/([^/]+))?$/.exec(path)
        if (templateRoute && ['POST','PUT','DELETE'].includes(req.method || '')) {
          const id = templateRoute[1] ? decodeURIComponent(templateRoute[1]) : '', old = templates.find(t => t.id === id)
          if (req.method === 'DELETE') {
            if (!old) return accountError('not_found', 404)
            templates.splice(templates.indexOf(old), 1); return reply(204)
          }
          if (!decode(['name','body'])) return
          const name = String(body.name ?? ''), content = String(body.body ?? '')
          if ([...name].length < 1 || [...name].length > 64) return invalid('name')
          if (bytes(content) > 65536) return invalid('body')
          if (!id && templates.length >= 100) return reply(409, { code: 'table_full', table: 'templates', message: 'template capacity exceeded' })
          if (id && !old) return accountError('not_found', 404)
          if (templates.some(t => t.name === name && t.id !== id)) return accountError('rule_conflict')
          const row = old || { id: 'template_' + ++serial, name, body: content, created_at: now(), created_by: 'user:' + user, updated_at: now(), updated_by: 'user:' + user }
          if (!old) templates.push(row)
          if (row.name !== name || row.body !== content) Object.assign(row, { name, body: content, updated_at: now(), updated_by: 'user:' + user })
          emptyTemplates = false; return reply(id ? 200 : 201, row)
        }
        const nodeRoute = /^\/nodes(?:\/([^/]+))?(?:\/(test))?$/.exec(path)
        if (nodeRoute && ['POST','PATCH','DELETE'].includes(req.method || '')) {
          const test = req.method === 'POST' && (path === '/nodes/test' || nodeRoute[2] === 'test'), named = !(req.method === 'POST' && path === '/nodes/test') && !!nodeRoute[1]
          const name = named ? decodeURIComponent(nodeRoute[1]!) : String(body.name ?? ''), old = managedNodes.find(n => n.name === name)
          const nodeError = (message: string) => reply(400, { code: 'invalid_field', message })
          const validURL = (value: string) => {
            try { const parsed = new URL(value); return /^https?:\/\//i.test(value) && !/^[\s]|[\t\r\n]/.test(value) && !!parsed.host && !value.split('/')[2]?.includes('@') && !parsed.search && !parsed.hash }
            catch { return false }
          }
          if (test) {
            if (named) {
              if (!old) return accountError('node_not_found', 404)
              if (old.key_unreadable) return reply(200, { reachable: false, compatible: false, key_accepted: false, message: 'node key unreadable' })
            } else {
              if (!decode(['base_url','api_key'])) return
              if (body.base_url == null || body.api_key == null || bytes(String(body.api_key)) < 1 || bytes(String(body.api_key)) > 4096) return nodeError('base_url and api_key (1..4096 bytes) required')
              if (!validURL(String(body.base_url))) return nodeError('invalid node URL')
            }
            return reply(200, nodeTestResult)
          }
          if (req.method !== 'DELETE' && !decode(req.method === 'POST' ? ['name','base_url','api_key'] : ['base_url','api_key'])) return
          if (!name.trim()) return nodeError('name must not be empty')
          if (name.includes('/')) return nodeError("name must not contain '/'")
          if (req.method !== 'DELETE' && (req.method === 'POST' && (body.base_url == null || body.api_key == null) || body.base_url == null && body.api_key == null)) return nodeError('node fields required')
          if (body.api_key != null && (bytes(String(body.api_key)) < 1 || bytes(String(body.api_key)) > 4096)) return nodeError('api_key must contain 1..4096 bytes')
          if (req.method === 'POST' && old) return reply(409, { code: 'rule_conflict', message: 'node already exists' })
          if (req.method !== 'POST' && !old) return accountError('node_not_found', 404)
          if (req.method === 'DELETE') { managedNodes.splice(managedNodes.indexOf(old!), 1); for (const stream of streams.keys()) frame(stream); return reply(204) }
          if (old?.key_unreadable && body.api_key == null) return nodeError('node key unreadable; supply api_key')
          const base_url = body.base_url == null ? old!.base_url : String(body.base_url)
          if (!validURL(base_url)) return nodeError('invalid node URL')
          if (old) Object.assign(old, { base_url, key_unreadable: false })
          else managedNodes.push({ ...seedSnapshot().nodes[2]!, name, base_url, key_unreadable: false })
          for (const stream of streams.keys()) frame(stream)
          return reply(req.method === 'POST' ? 201 : 200, { name, base_url })
        }
        if (path === '/settings') return reply(200, settings)
        if (path === '/nodes') return reply(200, snapshot())
        if (path === '/capacity') return reply(200, capacity())
        if (path === '/traffic/top' && url.searchParams.get('n') === 'all') return reply(200, {
          ...top(), updated_at: topReads++ === 0 ? null : new Date().toISOString(), incomplete: false,
          rules: rules.filter((r, i) => r.enabled && i % 8 === 1).map(r => ({ rule_id: r.id, target: r.dst_ip, dropped_pps: 1250, dropped_bytes_ps: 80000, share: .1, nodes: 1 })),
        })
        if (path === '/traffic/top') return reply(200, top())
        if (path === '/traffic/history') {
          const range = url.searchParams.get('range') || '15m', step_s = ['15m', '1h'].includes(range) ? 5 : ['6h', '24h'].includes(
            range) ? 60 : 3600
          const n = range === '15m' ? 180 : range === '1h' ? 720 : range === '6h' ? 360 : range === '24h' ? 1440 : range === '7d' ? 168 : 720
          const end = Math.floor(Date.now() / 1000 / step_s) * step_s
          const points = Array.from({
            length: n
          }, (_, i) => {
            const f = .6 + Math.sin(i / 7) * .15 + Math.sin(i / 2) * .1;
            return {
              t: end - (n - 1 - i) * step_s, dropped_pps: 1200000 * f, passed_pps: 320000 * (1 + Math.sin(i / 11) * .1), dropped_bytes_ps:
                780000000 * f, passed_bytes_ps: 250000000 * (1 + Math.sin(i / 11) * .1), ...(!['15m', '1h'].includes(range) ? {
                dropped_pps_max: 1500000, passed_pps_max: 400000, dropped_bytes_ps_max: 900000000, passed_bytes_ps_max: 300000000
              } : {
              })
            }
          }).filter((_, i) => i < Math.floor(n * .58) || i > Math.floor(n * .65))
          return reply(200, {
            range, step_s, node: '', capped: false, points
          })

        }
        if (/^\/nodes\/[^/]+\/(sync|reconcile)$/.test(path)) return reply(202, {
          status: 'accepted'
        })
        const changed = () => { ruleSeq++; for (const res of streams.keys()) frame(res) }
        if (path === '/rules' && req.method === 'GET') {
          const q = (url.searchParams.get('q') || '').trim(), state = url.searchParams.get('state')
          if (q && !q.startsWith('rule_') && !/[.:]/.test(q)) return reply(400, { code: 'bad_request', field: 'q', message: 'query' })
          const matched = rules.filter(r => !q || r.id === q || [r.src_ip,r.dst_ip,r.src_cidr,r.dst_cidr].some(a => a.includes(q)))
          const counts = { all: matched.length, drop: matched.filter(r => r.enabled && r.action === 'drop').length, rate_limit: matched.filter(r => r.enabled && r.action === 'rate_limit').length, disabled: matched.filter(r => !r.enabled).length }
          const filtered = matched.filter(r => (!state || (state === 'disabled' ? !r.enabled : r.enabled && r.action === state)) && r.logical_id > Number(url.searchParams.get('after') || 0))
          const items = filtered.slice(0, Number(url.searchParams.get('limit') || 100))
          return reply(200, { items, next_after: filtered.length > items.length ? items.at(-1)!.logical_id : null, ...(url.searchParams.get('counts') === '1' ? { counts } : {}) })
        }
        if (url.pathname === '/__mock/fixtures') {
          emptyTemplates = Boolean(body.emptyTemplates); rejectBatch = Boolean(body.rejectBatch)
          auditCut = Boolean(body.auditCut); passwordThrottle = Boolean(body.passwordThrottle); auditEmpty = Boolean(body.auditEmpty); auditError = Boolean(body.auditError)
          nodeTestResult = body.nodeTest === 'incompatible' ? { reachable: true, compatible: false, key_accepted: true, message: '' } : body.nodeTest === 'unreachable' ? { reachable: false, compatible: false, key_accepted: false, message: 'node unreachable' } : { reachable: true, compatible: true, key_accepted: true, message: '' }
          return reply(204)
        }
        if (path === '/templates' && req.method === 'GET') return reply(200, emptyTemplates ? [] : [...templates].sort((a,b) => a.name < b.name ? -1 : a.name > b.name ? 1 : a.id.localeCompare(b.id)))
        if (path === '/whitelist' && req.method === 'GET') {
          const sorted = whitelist.filter(w => w.id > (url.searchParams.get('after') || '')).sort((a,b) => a.id.localeCompare(b.id))
          const items = sorted.slice(0, Number(url.searchParams.get('limit') || 100))
          return reply(200, { items, next_after: sorted.length > items.length ? items.at(-1)!.id : null })
        }
        if (path === '/whitelist' && req.method === 'POST') {
          const b = { src_ip: '', dst_ip: '', src_port: 0, dst_port: 0, protocol: 'all', comment: '', ...body }
          const bad = (field: string, message: string) => reply(400, { code: 'invalid_rule', field, message })
          for (const key of ['src_port','dst_port'] as const) {
            if (typeof b[key] !== 'number' || !Number.isInteger(b[key])) return reply(400, { code: 'bad_request', field: key, message: 'decode' })
            if (b[key] < 0 || b[key] > 65535) return bad('port', 'port out of range')
          }
          for (const key of ['src_ip','dst_ip'] as const) {
            if (b[key] && !isIP(b[key])) return bad('ip', 'invalid IP address')
            if (isIP(b[key]) === 6) b[key] = new URL('http://[' + b[key] + ']').hostname.slice(1, -1)
            if (/^::ffff:[0-9a-f]{1,4}:[0-9a-f]{1,4}$/i.test(b[key])) return reply(400, { code: 'mapped_ipv6', message: 'mapped' })
            if (['0.0.0.0','::'].includes(b[key])) b[key] = ''
          }
          if (b.src_ip && b.dst_ip && isIP(b.src_ip) !== isIP(b.dst_ip)) return reply(400, { code: 'address_family_mismatch', message: 'family' })
          b.protocol ||= 'all'
          if (!['all','tcp','udp','icmp','icmpv6','igmp','gre','esp'].includes(b.protocol)) return bad('protocol', 'unknown protocol')
          if (!['all','tcp','udp'].includes(b.protocol) && (b.src_port || b.dst_port)) return bad('protocol', 'protocol does not support ports')
          if (!b.src_ip && !b.dst_ip && !b.src_port && !b.dst_port && b.protocol === 'all') return bad('tuple', 'rule field combination is not recognized')
          const old = whitelist.find(w => ['src_ip','dst_ip','src_port','dst_port','protocol'].every(k => w[k as keyof WhitelistDTO] === b[k as keyof typeof b]))
          if (old) return reply(200, { ...old, existing: true })
          const row = { ...b, id: 'wl_' + String(++serial + 10).padStart(8, '0'), created_at: new Date().toISOString(), created_by: 'user:' + user }
          whitelist.push(row); changed(); return reply(201, { ...row, existing: false })
        }
        if (path.startsWith('/whitelist/') && req.method === 'DELETE') {
          const i = whitelist.findIndex(w => w.id === decodeURIComponent(path.slice('/whitelist/'.length)))
          if (i >= 0) { whitelist.splice(i, 1); changed() }
          return reply(204)
        }
        if (path === '/rules/batch') {
          const items = body.items as Record<string, unknown>[]
          if (!Array.isArray(items) || !items.length || items.length > 500) return reply(400, { code: 'batch_too_large', field: 'items', message: 'batch size' })
          const decode = items.map(item => validate(item, 'items.')).find(e => e?.code === 'bad_request')
          if (decode || rejectBatch) return reply(400, decode || { code: 'bad_request', message: 'fixture' })
          const dry = url.searchParams.get('validate') === '1', pool = dry ? rules.map(r => ({ ...r })) : rules
          const refs = new Map<RuleDTO, number>()
          const results = items.map((item, index) => ({ index, ...createRule(item, pool, dry, refs, index) }))
          if (!dry && results.some(r => !r.error)) changed()
          return reply(200, { epoch: 'development', results })
        }
        if (path === '/rules' && req.method === 'POST') {
          const error = validate(body); if (error) return reply(400, error)
          const old = identical(body)
          const result = createRule(body, rules, false)
          if (result.error) return reply(409, result.error)
          changed(); return reply(old ? 200 : 201, { ...result.rule, existing: result.existing })
        }
        if (/^\/rules\/rule_[a-f0-9]{32}(\/enabled)?$/.test(path)) {
          const id = path.split('/')[2], i = rules.findIndex(r => r.id === id), rule = rules[i]
          if (req.method === 'DELETE') { if (i >= 0) rules.splice(i, 1); changed(); return reply(204) }
          if (!rule) return reply(404, { code: 'not_found', message: 'not found' })
          if (req.method === 'PUT') {
            if (rule.logical_id === 1) return reply(409, { code: 'condition_capacity', message: 'capacity', rule_ids: [rules[1]!.id] })
            rule.enabled = Boolean(body.enabled); changed(); return reply(200, { enabled: rule.enabled })
          }
          if (req.method === 'PATCH') {
            const error = validate({ ...rule, ...body }); if (error) return reply(400, error)
            const old = identical({ ...rule, ...body })
            if (old && old.id !== rule.id) return reply(409, { code: 'rule_conflict', message: 'conflict', rule_id: old.id })
            apply(rule, body); changed()
          }
          return reply(200, rule)
        }
        if (path.startsWith('/rules/')) {
          const i = Number(path.split('_').at(-1)) || 0;
          return reply(200, {
            id: 'rule_development_' + i, logical_id: 1201 + i, src_ip: '', src_cidr: '', dst_ip: targets[i] || targets[0], dst_cidr: '',
              src_port: 0, dst_port: [53, 123, 443, 80, 0][i], protocol: ['udp', 'udp', 'tcp', 'tcp', 'all'][i], ttl: null, dscp: null,
                icmp_type: null, icmp_code: null, fragment: null, pkt_len: i === 1 ? '64-512' : null, tcp_flags: i === 2 ? 'SYN,!ACK' : '',
                  match_anomaly: 0, action: i === 4 ? 'rate_limit' : 'drop', rate_limit: i === 4 ? 20000 : 0, enabled: true, kind: 'exact',
                    group_key: '', cond_key: '', comment: '', created_at: '', updated_at: '', expires_at: null, created_by: 'user:admin',
                      updated_by: 'user:admin'
          })
        }
        if (path === '/system') return reply(200, {
          controller: {
            started_at: new Date().toISOString(), uptime_seconds: 120, db_bytes: 4096, rules_enabled: 1284, rules_total: 1300, whitelist:
              37, go_mem: {
              alloc_bytes: 4096, sys_bytes: 8192
            }
          }, nodes: []
        })
        if (path === '/events') {
          res.writeHead(200, {
            'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache'
          });
          res.write('retry: 3000\n\n');
          streams.set(res, token);
          frame(res);
          res.once('close', () => streams.delete(res));
          return
        }
        reply(404, {
          code: 'not_found', message: 'not found'
        })

      })

    }
  }
}
