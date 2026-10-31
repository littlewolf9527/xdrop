const ipv4Segment = /^(?:0|[1-9][0-9]{0,2})$/
const hexSegment = /^[0-9a-fA-F]{1,4}$/

function ipv4(value: string): boolean {
  const parts = value.split('.')
  return parts.length === 4 && parts.every(part => ipv4Segment.test(part) && Number(part) <= 255)
}

/** Parse address literals without DNS, URL normalization, or browser dependencies. */
export function isIP(input: unknown): 0 | 4 | 6 {
  const value = `${input}`
  if (ipv4(value)) return 4
  const zone = value.indexOf('%')
  if (zone !== -1 && !/^[0-9a-zA-Z.:-]+$/.test(value.slice(zone + 1))) return 0
  const address = zone === -1 ? value : value.slice(0, zone)
  if (!address.includes(':')) return 0
  const halves = address.split('::')
  if (halves.length > 2) return 0
  const parts = halves.flatMap(half => half === '' ? [] : half.split(':'))
  let words = 0
  for (const [index, part] of parts.entries()) {
    if (hexSegment.test(part)) words++
    else if (index === parts.length - 1 && address.endsWith(part) && ipv4(part)) words += 2
    else return 0
  }
  return (halves.length === 2 ? words < 8 : words === 8) ? 6 : 0
}
