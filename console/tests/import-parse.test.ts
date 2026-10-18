import { it, expect } from 'vitest'
import { parseImport, expandTargets, splitLines, failedText, applyResults, receipt } from '../src/import'
import { serializeRule } from '../src/rules'
import type { RuleDTO } from '../src/api/types'
it('G2 V1 V2 fixed first-equals and quote escapes', () => {
  expect(parseImport('comment=a=b')[0]!.patch).toEqual({ comment: 'a=b' })
  expect(parseImport('comment="x \\"y\\" z"')[0]!.patch).toEqual({ comment: 'x "y" z' })
  expect(parseImport('expires_in=1h1m\nexpires_in=2562047h47m16s').map(r => r.patch)).toEqual([{ expires_in: '1h1m' }, { expires_in: '2562047h47m16s' }])
})
it('G2 true TAB and CR differ character-for-character from literal slash-t', () => {
  const values = parseImport('comment="a\tb"\ncomment="a\rb"\ncomment="a\\\\tb"').map(r => String(r.patch!.comment))
  expect(values.map(v => Array.from(v).map(c => c.charCodeAt(0)))).toEqual([[97,9,98],[97,13,98],[97,92,116,98]])
})
it('G2 V3 four numeric keys have number type; booleans are booleans', () => {
  expect(parseImport('src_port=123 dst_port=179 match_anomaly=4 rate_limit=50000 enabled=false')[0]!.patch).toEqual({ src_port: 123, dst_port: 179, match_anomaly: 4, rate_limit: 50000, enabled: false })
})
it('G2 lexical errors each retain original line numbers; no semantic checks', () => {
  const invalid = ['missing=value','protocol=tcp protocol=udp','comment="open','comment="bad\\q"','src_port=-1','dst_port=1.2','match_anomaly=9007199254740993','rate_limit=abc','enabled=FALSE']
  const rows = parseImport('# comment\n\n' + invalid.join('\n') + '\ndst_ip=invalid protocol=unusual ttl=!oops expires_in=wrong')
  expect(rows.slice(0,9).map(r => [r.no, r.status, r.patch])).toEqual(invalid.map((_,i) => [i+3,'lex',undefined]))
  expect(rows[9]!.patch).toEqual({ dst_ip:'invalid', protocol:'unusual', ttl:'!oops', expires_in:'wrong' })
  expect(parseImport(' \n# comment\n\t')).toEqual([])
})
it('G2 seeded 320-rule export projection roundtrip', () => {
  let seed = 20261016
  const random = () => { seed = (Math.imul(seed,1664525)+1013904223)>>>0; return seed }
  const comments = ['', 'x "y" z', 'a=b', 'a\tb', 'a\rb', 'a\\tb', '# memo', 'line\nnext']
  const now = Date.parse('2026-10-16T00:00:00Z')
  for (let i=0;i<320;i++) {
    const r = { src_ip:'', dst_ip:'192.0.2.'+(i%250+1), src_cidr:'', dst_cidr:'', protocol: i%2?'tcp':'udp', src_port:random()%65536, dst_port:random()%65536,
      ttl: i%3?'64,128':null, dscp:null, icmp_type:null, icmp_code:null, fragment:null, pkt_len:'64-512', tcp_flags:i%2?'SYN,!ACK':'', match_anomaly:i%5?0:4,
      action: i%2?'drop':'rate_limit', rate_limit:i%2?0:random()%100000+1, enabled:i%4!==0, comment:comments[random()%comments.length]!, expires_at:i%3?null:'2026-10-16T01:01:00Z' } as RuleDTO
    const expected: Record<string, unknown> = { dst_ip:r.dst_ip, protocol:r.protocol, action:r.action, pkt_len:r.pkt_len }
    for (const k of ['src_port','dst_port','ttl','tcp_flags','match_anomaly','comment'] as const) if (r[k]) expected[k]=r[k]
    if (!r.enabled) expected.enabled=false
    if (r.action==='rate_limit') expected.rate_limit=r.rate_limit
    if (r.expires_at) expected.expires_in='1h1m'
    const row=parseImport(serializeRule(r,now))[0]!
    expect(row.status).toBe('pending'); expect(row.patch).toEqual(expected)
  }
})
it('G3 V4 V18 target expansion, template rejection and lexical isolation', () => {
  const r=expandTargets('192.0.2.1\n203.0.113.0/24\n','protocol=udp\n# skip\naction=drop')
  expect([r.targets,r.template,r.rows.length]).toEqual([2,2,4]); expect(r.rows.map(v=>v.no)).toEqual([1,2,3,4])
  expect(r.rows[2]!.patch).toEqual({dst_cidr:'203.0.113.0/24',protocol:'udp'})
  expect(expandTargets('192.0.2.1','dst_ip=198.51.100.1')["rows"][0]!.lex?.kind).toBe('target')
  for (const target of ['192.0.2.1 enabled=false','192.0.2.1"x','192.0.2.1\\x','192.0.2.1#x']) {
    const row=expandTargets(target,'protocol=udp').rows[0]!
    expect(row.patch).toEqual({dst_ip:target,protocol:'udp'}); expect(row.raw).toContain('dst_ip="'); expect(parseImport(row.raw)[0]!.patch).toEqual(row.patch)
  }
})
it('G4 V8 V20 failure membership and raw text are exact', () => {
  const statuses=['created','renewed','skipped','duplicateSkipped','error','rejected','unsent','unknown'] as const
  const rows=statuses.map((status,i)=>({...parseImport('comment='+i)[0]!,no:i+1,status}))
  expect(failedText(rows)).toBe('comment=4\ncomment=5\ncomment=6')
  expect(receipt([{...rows[0]!,status:'existing'},{...rows[1]!,status:'duplicate'}]).map(r=>r.status)).toEqual(['skipped','duplicateSkipped'])
  expect(splitLines(parseImport(Array.from({length:1201},(_,i)=>'dst_port='+i).join('\n'))).map(c=>c.length)).toEqual([500,500,201])
  expect(applyResults([rows[0]!], {epoch:'test',results:[{index:0,existing:true,rule:{id:'rule_1'} as RuleDTO}]},'submit')[0]!.status).toBe('renewed')
})
