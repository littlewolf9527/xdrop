import { it, expect } from 'vitest'
import { conditionKeys, numeric, protocolOptions, conditionRanges } from '../src/rules'
import { conditionNames } from '../src/errors'
import { numeric as importNumeric } from '../src/import'
import { messages } from '../src/i18n'
it('FE G1 literal tables preserve every value and order', () => {
  expect(protocolOptions).toEqual(['all','tcp','udp','icmp','icmpv6','igmp','gre','esp'])
  expect(conditionKeys).toEqual(['ttl','dscp','pkt_len','icmp_type','icmp_code','fragment','tcp_flags','match_anomaly'])
  expect(numeric).toEqual(['src_port','dst_port','match_anomaly','rate_limit'])
  expect(Object.entries(conditionRanges)).toEqual([['ttl','0–255'],['dscp','0–63'],['pkt_len','0–65535'],['icmp_type','0–255'],['icmp_code','0–255'],['match_anomaly','1–15']])
})
it('FE G1 error and import consumers share exported objects', () => {
  expect(conditionNames).toBe(conditionKeys); expect(importNumeric).toBe(numeric)
})
it('FE G3 all languages describe dot exclusions and ASCII node names', () => {
  for (const { settingsUI: text } of Object.values(messages)) {
    expect(text.usernameInvalid).toContain('..'); expect(text.keyNameInvalid).toContain('..')
    expect(text.nodeNameInvalid).toContain('ASCII'); expect(text.nodeNameInvalid).toContain('1–64')
    for (const literal of ['.','_','-','..']) expect(text.nodeNameInvalid).toContain(literal)
  }
})
