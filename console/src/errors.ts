import { ApiError } from './api/client'
import type { WriteError } from './api/types'
import { i18n, messages } from './i18n'
export const errorCodes = [
  'invalid_rule', 'empty_value', 'invalid_expires_in', 'mapped_ipv6', 'address_family_mismatch', 'bad_request',
  'batch_too_large', 'invalid_field', 'unauthenticated', 'invalid_credentials', 'forbidden', 'admin_required',
  'not_found', 'node_not_found', 'route_not_found', 'user_not_found', 'credential_not_found', 'method_not_allowed',
  'rule_conflict', 'condition_capacity', 'cidr_overlap', 'table_full', 'gen_epoch_mismatch', 'user_exists',
  'last_user', 'last_admin', 'login_throttled', 'internal',
] as const
export function envelope(e: unknown): WriteError | undefined { return e instanceof ApiError ? e.envelope : undefined }
import { conditionKeys as conditionNames } from './rules'
export { conditionNames }
const ruleMessages: [string, RegExp][] = [
  ['ip', /^(?:invalid IP address|invalid IP "(?:\\.|[^"\\])*")$/],
  ['cidr', /^invalid CIDR "(?:\\.|[^"\\])*"$/],
  ['portsProtocol', /^(?:protocol does not support ports|protocol [a-z0-9]+ does not carry ports)$/],
  ['protocol', /^(?:unknown protocol|invalid protocol "(?:\\.|[^"\\])*")$/],
  ['portRange', /^(?:port out of range|port outside 0-65535)$/],
  ['rateRange', /^rate out of range$/],
  ['ratePositive', /^(?:rate must be positive|rate_limit requires positive rate)$/],
  ['action', /^(?:unknown action|action must be drop or rate_limit)$/],
  ['mixedAddress', /^(?:exact IP and CIDR cannot be combined|cannot mix exact IP and CIDR)$/],
  ['wide', /^rule field combination is not recognized$/],
  ['anomalyRange', /^(?:anomaly out of range|match_anomaly outside 0x0F)$/],
  ['anomalyBits', /^unknown anomaly bits$/],
  ['anomalyTarget', /^anomaly requires a bounded target$/],
  ['anomalyIPv6', /^(?:anomaly is not supported for IPv6|match_anomaly 0x01\/0x08 unsupported for IPv6 target)$/],
  ['flagsTCP', /^(?:flags require tcp|tcp_flags requires protocol tcp)$/],
  ['requiresProtocol', /^(?<key>icmp_type|icmp_code|ttl|dscp|pkt_len|fragment|match_anomaly) requires protocol (?<protos>[a-z0-9,]+)$/],
  ['fragmentIPv4', /^fragment requires IPv4 address or CIDR anchor$/],
  ['nonfirst', /^D2: nonfirst fragment or anomaly 0x08 cannot satisfy .+$/],
  ['conditionTarget', /^condition rule requires a five-tuple anchor$/],
  ['lengthRange', /^legacy packet length outside 0-65535$/],
  ['lengthBoth', /^new and legacy packet length coexist$/],
  ['reversed', /^(?:legacy packet length )?reversed interval$/],
  ['decimal', /^invalid decimal (?<quoted>"(?:\\.|[^"\\])*")$/],
  ['valueRange', /^value (?<quoted>"(?:\\.|[^"\\])*") outside 0-(?<max>[0-9]+)$/],
  ['illegal', /^illegal character$/],
  ['emptyExpression', /^empty expression$/],
  ['emptyItem', /^empty item$/],
  ['fragmentName', /^invalid name (?<quoted>"(?:\\.|[^"\\])*")$/],
  ['interval', /^invalid interval (?<quoted>"(?:\\.|[^"\\])*")$/],
  ['emptySet', /^empty set$/],
  ['fullSet', /^full set; please remove this key$/],
  ['flagName', /^unknown TCP flag (?<quoted>"(?:\\.|[^"\\])*")$/],
  ['flagConflict', /^contradictory TCP flags: (?<value>.+)$/],
]
function conditionField(message: string) {
  const key = /^(\w+)(?:: | requires protocol )/.exec(message)?.[1] || ''
  return conditionNames.some(k => k === key) ? key : ''
}
function unquote(text: string) {
  const simple: Record<string, string> = { a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', '"': '"' }
  let decoded = ''
  for (let i = 1; i < text.length - 1; i++) {
    const char = text[i]!
    if (char !== '\\' || i + 1 >= text.length - 1) { decoded += char; continue }
    const escape = text[++i]!
    if (Object.hasOwn(simple, escape)) { decoded += simple[escape]; continue }
    const length = escape === 'x' ? 2 : escape === 'u' ? 4 : escape === 'U' ? 8 : 0
    const digits = text.slice(i + 1, i + 1 + length), octal = text.slice(i, i + 3)
    if (length && digits.length === length && /^[a-fA-F0-9]+$/.test(digits) && parseInt(digits, 16) <= 0x10ffff) {
      decoded += String.fromCodePoint(parseInt(digits, 16)); i += length
    } else if (/^[0-7]{3}$/.test(octal) && parseInt(octal, 8) <= 255) {
      decoded += String.fromCharCode(parseInt(octal, 8)); i += 2
    } else decoded += '\\' + escape
  }
  return decoded
}
export function ruleMessage(message: string, field: string) {
  if (field === 'cidr') return { id: 'cidr', key: field, value: '', protos: '', max: '' }
  const unwrapped = message.replace(/^rule [^:]+: /, ''), prefix = /^(\w+): ([\s\S]*)$/.exec(unwrapped)
  const key = prefix && conditionNames.some(k => k === prefix[1]!) ? prefix[1]! : message.startsWith('legacy packet length') ? 'pkt_len' : field
  const inner = prefix && conditionNames.some(k => k === prefix[1]!) ? prefix[2]! : unwrapped
  for (const [id, regex] of ruleMessages) {
    const match = regex.exec(inner)
    if (!match) continue
    const groups = match.groups || {}, value = Array.from(groups.quoted ? unquote(groups.quoted) : groups.value || '')
    return { id, key: groups.key || key, value: value.slice(0, 40).join('') + (value.length > 40 ? '…' : ''), protos: groups.protos || '', max: groups.max || '' }
  }
}
function ruleErrorText(value: WriteError) {
  const field = value.field!.replace(/^items\./, ''), match = ruleMessage(value.message, field), t = i18n.global.t
  if (match) return t('ruleErrors.' + match.id, match)
  const actual = field === 'conditions' ? conditionField(value.message) || field : field
  const address = ['ip', 'cidr', 'tuple', 'src_ip', 'dst_ip', 'src_cidr', 'dst_cidr'].includes(actual)
  const label = ['src_ip', 'src_cidr'].includes(actual) ? 'src_address' : ['dst_ip', 'dst_cidr'].includes(actual) ? 'dst_address' :
    address ? 'target' : actual === 'port' ? 'ports' : actual === 'expires_in' ? 'expiry' : actual
  const key = conditionNames.some(k => k === label) ? label : label === 'rate_limit' ? 'pps' :
    ['src_address', 'dst_address', 'target', 'ports', 'expiry', 'protocol', 'src_port', 'dst_port', 'conditions', 'action', 'comment', 'enabled'].includes(label) ? t(label) : t('rules')
  const hint = address ? 'address' : Object.hasOwn(messages['zh-CN'].ruleHints, actual) ? actual : ''
  return t('ruleErrors.fallback', { key }) + (hint ? ' ' + t('ruleHints.' + hint) : '')
}
export function errorText(e: unknown): string {
  const value = envelope(e), t = i18n.global.t
  if (!value) return t(e instanceof TypeError ? 'unreachable' : 'operationFailed')
  if (!errorCodes.some(code => code === value.code)) return t('operationFailed')
  if (value.field) return ruleErrorText(value)
  let text = t('errors.' + value.code)
  if (value.code === 'table_full' && value.table) {
    const group = Object.hasOwn(messages['zh-CN'].dimensions, value.table) ? 'dimensions' : 'tables'
    if (Object.hasOwn(messages['zh-CN'][group], value.table)) text += ' · ' + t(group + '.' + value.table)
  }
  return text
}
export function errorRules(e: unknown): string[] {
  const value = envelope(e)
  if (!value || !['rule_conflict', 'condition_capacity', 'cidr_overlap'].includes(value.code)) return []
  return [...new Set([...(value.rule_id ? [value.rule_id] : []), ...(value.rule_ids || [])])]
    .filter(id => /^rule_[a-f0-9]{32}$/.test(id) || /^batch:\d+$/.test(id))
}
export function errorField(e: unknown): string {
  const value = envelope(e)
  if (!value) return ''
  const field = value.field?.replace(/^items\./, '') || ''
  if (['mapped_ipv6', 'address_family_mismatch'].includes(value.code) || ['ip', 'cidr', 'tuple'].includes(field)) return 'target'
  if (value.code === 'invalid_expires_in' && !field) return 'expires_in'
  if (field === 'conditions') return conditionField(value.message) || 'conditions'
  if (field === 'port') return 'ports'
  if (['src_ip', 'src_cidr'].includes(field)) return 'src_address'
  if (['dst_ip', 'dst_cidr'].includes(field)) return 'dst_address'
  return ['protocol', 'src_port', 'dst_port', 'ttl', 'dscp', 'pkt_len', 'icmp_type', 'icmp_code', 'fragment',
    'tcp_flags', 'match_anomaly', 'action', 'rate_limit', 'expires_in', 'comment', 'enabled'].includes(field) ? field : ''
}

export function batchLine(id: string, lineNumbers?: number[]) {
  return /^batch:\d+$/.test(id) ? lineNumbers?.[Number(id.slice(6))] : undefined
}
export function whitelistError(e: unknown): { text: string; field: string } {
  if (!e) return { text: '', field: '' }
  const value = envelope(e), t = i18n.global.t
  if (value) {
    const field = value.field || ''
    if (value.code === 'invalid_rule' && ['ip','port','tuple','protocol'].includes(field)) {
      const key = field === 'protocol' && value.message === 'protocol does not support ports' ? 'portsProtocol' : field
      return { text: t('whitelistErrors.' + key), field }
    }
    if (['mapped_ipv6','address_family_mismatch','table_full'].includes(value.code)) return { text: t('whitelistErrors.' + value.code), field: '' }
    const { field: _field, ...generic } = value
    return { text: errorText(new ApiError((e as ApiError).status, generic)), field: '' }
  }
  return { text: errorText(e), field: '' }
}

const genericCodes = ['bad_request', 'invalid_field', 'forbidden', 'admin_required', 'node_not_found', 'route_not_found', 'method_not_allowed', 'gen_epoch_mismatch', 'internal']
export function genericKey(e: unknown): string {
  if (!(e instanceof ApiError)) return e instanceof TypeError ? 'unreachable' : 'operationFailed'
  return genericCodes.includes(e.envelope.code) ? 'errors.' + e.envelope.code : 'operationFailed'
}
