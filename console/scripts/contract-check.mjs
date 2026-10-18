import {
  readFile
} from 'node:fs/promises'
import {
  fileURLToPath
} from 'node:url'
const text = await readFile(new URL('../src/api/contract.ts', import.meta.url), 'utf8')
const entries = JSON.parse(text.split('export const contracts: ContractEntry[] = ')[1].split('// END CONTRACT JSON')[0])
export function resolvePath(value, path, nullable = false, empty = []) {
  const segments = path.split('.')
  function walk(current, i) {
    if (current === null) return nullable ? ['hit'] : ['missing']
    if (i === segments.length) return current === undefined ? ['missing'] : ['hit']
    const part = segments[i], array = part.endsWith('[]'), key = array ? part.slice(0, -2) : part
    if (part !== '[]' && (!current || !Object.hasOwn(current, key))) return ['missing']
    const next = part === '[]' ? current : current[key]
    if (!array) return walk(next, i + 1)
    if (!Array.isArray(next)) return ['missing']
    if (!next.length) { empty.push(segments.slice(0, i + 1).join('.')); return ['uncovered'] }
    return next.flatMap(item => walk(item, i + 1))

  }
  const result = walk(value, 0)
  return result.includes('missing') ? 'missing' : result.includes('hit') ? 'hit' : 'uncovered'
}
export function requireSampledCPU(nodes) {
  const sampled = nodes.nodes.some(node => typeof node?.stats?.system?.cpu_percent === 'number')
  if (!sampled) throw new Error('Lab node control requires a sampled CPU value')
}
async function main() {
  const base = new URL(process.argv[2])
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname) && !process.env.CONTRACT_ALLOW_LAB) throw new Error(
    'Set CONTRACT_ALLOW_LAB for the owner-operated lab check')
  const login = await fetch(new URL('/api/v1/auth/login', base), {
    method: 'POST', headers: {
      'Content-Type': 'application/json'
    }, body: JSON.stringify({
      username: process.env.CONTRACT_USERNAME, password: process.env.CONTRACT_PASSWORD
    })
  })
  if (!login.ok) throw new Error(`Authentication HTTP ${login.status}`)
  const cookie = login.headers.getSetCookie().map(v => v.split(';')[0]).join('; ')
  const cache = new Map(), events = {
  }, controller = new AbortController()
  const deadline = setTimeout(() => controller.abort(), 12000)
  try {
    const response = await fetch(new URL('/api/v1/events', base), {
      headers: {
        Cookie: cookie
      }, signal: controller.signal
    })
    if (!response.ok || !response.body) throw new Error(`Events HTTP ${response.status}`)
    const reader = response.body.getReader(), decoder = new TextDecoder();
    let buffer = ''
    while (!['rules', 'nodes', 'traffic'].every(key => key in events)) {
      const chunk = await reader.read();
      if (chunk.done) throw new Error('Events ended before all three classes')
      buffer += decoder.decode(chunk.value, {
        stream: true
      }).replace(/\r/g, '')
      let split
      while ((split = buffer.indexOf('\n\n')) >= 0) {
        const block = buffer.slice(0, split);
        buffer = buffer.slice(split + 2)
        const name = /^event: (.+)$/m.exec(block)?.[1], data = /^data: (.+)$/m.exec(block)?.[1]
        if (name && data && !events[name]) events[name] = JSON.parse(data)

      }

    }
    await reader.cancel()

  } finally {
    clearTimeout(deadline);
    controller.abort()
  }
  async function get(endpoint, expected = 200, query = '') {
    if (query) endpoint += (endpoint.includes('?') ? '&' : '?') + query
    if (!cache.has(endpoint)) cache.set(endpoint, (async () => {
      const response = await fetch(new URL(endpoint.replace(/^GET /, ''), base), {
        headers: {
          Cookie: cookie
        }
      })
      if (response.status !== expected) throw new Error(`${endpoint} HTTP ${response.status}, expected ${expected}`)
      return response.json()

    })())
    return cache.get(endpoint)

  }
  const unauthenticated = await fetch(new URL('/api/v1/auth/me', base))
  if (unauthenticated.status !== 401) throw new Error('Expected unauthenticated HTTP 401')
  const errorEnvelope = await unauthenticated.json()
  const top = await get('GET /api/v1/traffic/top?n=5')
  const samples = top.rules.length ? top.rules : (await get('GET /api/v1/rules?limit=1')).items.map(row => ({ rule_id: row.id }))
  const missing = [], uncovered = [], hit = [], writes = [], emptyArrays = []
  for (const entry of entries) {
    const label = `${entry.endpoint}${entry.event ? ' [' + entry.event + ']' : ''} · ${entry.path}`
    if (!entry.endpoint.startsWith('GET ')) { writes.push(label); continue }
    const empty = []
    const candidates = entry.status === 401 ? [errorEnvelope] : entry.event ? [events[entry.event]] :
      entry.endpoint.includes('{rule_id}') ? await Promise.all(samples.map(row =>
      get(entry.endpoint.replace('{rule_id}', encodeURIComponent(row.rule_id))))) : [await get(entry.endpoint, entry.status || 200, entry.query)]
    const results = candidates.map(value => resolvePath(value, entry.path, entry.nullable, empty))
    emptyArrays.push(...empty.map(path => `${entry.endpoint}${entry.event ? ' [' + entry.event + ']' : ''} · ${path}`))
    const status = results.includes('missing') ? 'missing' : results.includes('hit') ? 'hit' : 'uncovered'
      ;
    ({
      missing, uncovered, hit
    }[status]).push(`${entry.endpoint}${entry.event ? ' [' + entry.event + ']' : ''} · ${entry.path}`)

  }
  console.log(`条目总数 ${entries.length} · 命中 ${hit.length} · 缺失 ${missing.length} · 未覆盖 ${uncovered.length}`)
  for (const line of missing) console.log('缺失 ' + line)
  for (const line of uncovered) console.log('未覆盖 ' + line)
  for (const line of [...new Set(emptyArrays)]) console.log('未覆盖（经空数组） ' + line)
  for (const line of writes) console.log('未覆盖（写接口） ' + line)
  console.log(`写接口未覆盖 ${writes.length} · 经空数组条目 ${uncovered.length}`)
  console.log('7d 原始回包 ' + JSON.stringify(await get('GET /api/v1/traffic/history?range=7d')))
  if (process.env.CONTRACT_CONTROLS) {
    const controls = [['GET /api/v1/capacity', 'tightest.used'], ['GET /api/v1/auth/me', 'rolee'], ['GET /api/v1/rules', 'items[].claimants']]
    if (process.env.CONTRACT_CONTROLS === 'lab') {
      const nodes = await get('GET /api/v1/nodes')
      requireSampledCPU(nodes)
      controls.push(['GET /api/v1/nodes', 'nodes[].cpu_percent'])

    }
    for (const [endpoint, path] of controls) {
      const result = resolvePath(await get(endpoint), path)
      console.log(`阳性对照 ${endpoint} · ${path} · ${result}`)
      if (result === 'uncovered') throw new Error('Positive control fixture invalid: empty array')
      if (result !== 'missing') throw new Error('Positive control failed')

    }

  }
  if (missing.length) process.exitCode = 1
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(error => {
  console.error(error.message);
  process.exitCode = 1
})
