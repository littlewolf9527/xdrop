import {
  readdirSync, readFileSync, statSync, writeFileSync
} from 'node:fs'
import {
  join, relative
} from 'node:path'
function files(dir) {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path]
  })
}
function scan(paths) {
  const hits = [];
  let mock = 0, google = 0
  for (const path of paths) {
    const text = readFileSync(path).toString('utf8')
    for (const match of text.matchAll(/https?:\/\/[^\s<>"'`]+/g)) hits.push({
      path, original: match[0], context: text.slice(Math.max(0, match.index - 60), match.index + match[0].length + 60)
    })
    mock += (text.match(/\/__mock|XDROP_MOCK_ONLY/g) || []).length
    google += (text.match(/fonts\.googleapis|fonts\.gstatic/g) || []).length

  }
  return {
    hits, mock, google
  }
}
const root = '../controller/core/webui/build', paths = files(root)
if (process.env.C5D_SCAN_EXTRA) paths.push(process.env.C5D_SCAN_EXTRA)
const result = scan(paths), list = paths.map(path => ({
  path: relative(root, path), bytes: statSync(path).size
}))
console.log(list.map(f => `${f.path} · ${f.bytes}`).join('\n'))
console.log(`总字节 ${list.reduce((n, f) => n + f.bytes, 0)} · 最大 JS 字节 ${Math.max(...list.filter(f => f.path.endsWith('.js')).map(f => f.bytes))}`)
for (const hit of result.hits) console.log(`外链原文 ${hit.path} · ${hit.original}`)
const exceptions = ['https://vuejs.org/error-reference/#runtime-${n}', 'https://element-plus.org/en-US/component/button.html#button-attributes', 'https://github.com/littlewolf9527/xdrop', 'https://element-plus.org/en-US/component/dialog.html#slots']
const licenseHits = result.hits.filter(hit => hit.path === root + '/third-party.txt')
console.log(`third-party.txt 外链命中 ${licenseHits.length}`)
const violations = result.hits.filter(hit => hit.path !== root + '/third-party.txt' && !hit.original.startsWith('http://www.w3.org/') && !(hit.path.endsWith('.js') &&
  exceptions.includes(hit.original)))
for (const exception of exceptions) {
  const hits = result.hits.filter(hit => hit.original === exception);
  console.log(`惰性例外 ${exception} · 次数 ${hits.length}`);
  for (const hit of hits) console.log(`例外上下文 ${hit.path} · ${hit.context}`)
}
const keys = ['group', 'name', 'version', 'license', 'note'], groups = ['browser', 'controller', 'go', 'font', 'node', 'bpf']
let metadataInvalid = 0, executableLicense = 0
for (const path of paths.filter(p => p.endsWith('.json'))) {
  const raw = readFileSync(path, 'utf8')
  if (raw.includes('://')) metadataInvalid++
  const containsURL = value => typeof value === 'string' ? value.includes('://') :
    value !== null && typeof value === 'object' && Object.entries(value).some(([key, item]) => key.includes('://') || containsURL(item))
  if (containsURL(JSON.parse(raw))) metadataInvalid++
  if (path.endsWith('third-party.json')) {
    const entries = JSON.parse(raw)
    if (!Array.isArray(entries) || entries.some(e => !groups.includes(e.group) || Object.keys(e).some(k => !keys.includes(k)) || ['name', 'version', 'license'].some(k => typeof e[k] !== 'string'))) metadataInvalid++
  }
}
for (const path of paths.filter(p => /\.(html|js)$/.test(p))) if (/<(?:script|link)\b[^>]*third-party\.txt/i.test(readFileSync(path, 'utf8'))) executableLicense++
console.log(`json 键/URL 违例 ${metadataInvalid} · 许可证 script/link 引用 ${executableLicense}`)
console.log(`不允许外链 ${violations.length} · mock 哨兵 ${result.mock} · Google Fonts ${result.google}`)
const positive = scan(files('mock'))
console.log(`阳性对照 mock 源码 · 外链 ${positive.hits.length} · mock 哨兵 ${positive.mock}`)
writeFileSync(process.env.C5D_SCAN_JSON || '../../out/artifact-scan.json', JSON.stringify({
  files: list, ...result, violations, positive, licenseHits, metadataInvalid, executableLicense
}, null, 2))
process.exitCode = metadataInvalid || executableLicense || violations.length || result.mock || result.google || positive.mock < 1 ? 1 : 0
