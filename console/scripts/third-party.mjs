import { readFileSync, readdirSync, statSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs'
import { resolve, dirname, join, relative, basename } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), output = resolve(root, '../controller/core/webui/build')
const read = file => readFileSync(file, 'utf8'), json = file => JSON.parse(read(file))
const walk = dir => readdirSync(dir).flatMap(name => { const p = join(dir, name); return statSync(p).isDirectory() ? walk(p) : [p] })
const command = (bin, args, cwd = root, env = {}) => execFileSync(bin, args, { cwd, encoding: 'utf8', env: { ...process.env, GOFLAGS: '-mod=readonly', ...env } }).trim()
function packageFor(id) {
  const clean = id.replaceAll('\\', '/').split('?')[0], marker = clean.lastIndexOf('node_modules/')
  if (marker < 0) return null
  const parts = clean.slice(marker + 13).split('/'), count = parts[0].startsWith('@') ? 2 : 1
  const dir = resolve(root, clean.slice(0, marker + 13) + parts.slice(0, count).join('/'))
  return { dir, ...json(join(dir, 'package.json')) }
}
function texts(dir) {
  const names = readdirSync(dir).filter(n => /^(LICENSE|NOTICE|PATENTS|COPYING)(\b|[._-])/i.test(n) && statSync(join(dir, n)).isFile())
  const extra = existsSync(join(dir, 'licenses')) ? walk(join(dir, 'licenses')) : []
  return [...names.map(n => join(dir, n)), ...extra].map(p => relative(dir, p) + '\n' + read(p)).join('\n\n')
}
function fingerprint(text) {
  const result = []
  if (/Permission is hereby granted, free of charge/i.test(text)) result.push('MIT')
  if (/Redistribution and use in source and binary forms/i.test(text)) result.push(/Neither the name|names of (?:its )?contributors|name of the author/i.test(text) ? 'BSD-3-Clause' : 'BSD-2-Clause')
  if (/Apache License[\s\S]{0,90}Version 2\.0/i.test(text)) result.push('Apache-2.0')
  if (/Permission to use, copy, modify, and(?:\/or)? distribute this software/i.test(text)) result.push(/for any purpose with or without fee/i.test(text) && !/provided that/i.test(text) ? '0BSD' : 'ISC')
  if (/GNU GENERAL PUBLIC LICENSE[\s\S]{0,100}Version 2, June 1991/.test(text)) result.push('GPL-2.0')
  if (!result.length) throw new Error('Unrecognized license fingerprint')
  return result.join(' AND ')
}
// Distribution packages (Debian golang-go, RHEL golang) move LICENSE out of GOROOT; the checked-in copy is the same Go Authors text.
export function goLicense(goroot) {
  const direct = join(goroot, 'LICENSE'), parent = join(goroot, '../LICENSE'), bundled = resolve(root, 'scripts/licenses/Go-BSD-3-Clause.txt')
  const file = existsSync(direct) ? direct : existsSync(parent) ? parent : bundled, text = read(file)
  if (!/^Copyright[^\n]*The Go Authors\./m.test(text) || fingerprint(text) !== 'BSD-3-Clause') throw new Error('Invalid Go Authors license')
  const selected = file === direct ? 'GOROOT/LICENSE' : file === parent ? 'GOROOT/../LICENSE' : 'scripts/licenses/Go-BSD-3-Clause.txt'
  console.log(`Go LICENSE ${selected} SHA256 ${createHash('sha256').update(readFileSync(file)).digest('hex')}`)
  return { text, selected }
}
export function bpfSources(dir) {
  const entries = [], licenseText = read(join(root, 'scripts/licenses/GPL-2.0.txt'))
  if (fingerprint(licenseText) !== 'GPL-2.0') throw new Error('Invalid GPL-2.0 full text')
  for (const file of walk(join(dir, 'headers')).sort()) {
    const first = read(file).split('\n')[0]
    if (first !== '// Copyright (c) 2019 Dropbox, Inc.') throw new Error('Unknown BPF header copyright: ' + basename(file))
    entries.push({ entry: { group: 'bpf', name: basename(file) + ' (dropbox/goebpf)', version: '', license: 'GPL-2.0' }, text: first + '\n' + licenseText })
  }
  const programs = readdirSync(dir).filter(name => name.endsWith('.c')).sort().reverse()
  if (!programs.length) throw new Error('No BPF programs')
  for (const file of programs) {
    const source = read(join(dir, file)), declarations = [...source.matchAll(/SEC\s*\(\s*"license"\s*\)/g)]
    if (declarations.length !== 1) throw new Error('Unexpected BPF license: ' + file)
    const start = declarations[0].index + declarations[0][0].length, end = source.indexOf(';', start), initializer = source.slice(start, end).trim()
    if (end < 0 || !initializer.startsWith('=') || initializer.slice(1).trim() !== '"GPL"') throw new Error('Unexpected BPF license: ' + file)
  }
  entries.push({ entry: { group: 'bpf', name: programs.join(' · '), version: '', license: 'GPL-2.0', note: 'ELF license 段声明 GPL；仓库 README：node/bpf 按 GPL-2.0' }, text: programs.join(' · ') + '\n' + licenseText })
  return entries
}
export function generateThirdParty(bundle) {
  const packages = new Map(), entries = [], full = []
  for (const item of Object.values(bundle)) {
    if (item.type === 'chunk') for (const [id, module] of Object.entries(item.modules)) {
      if (typeof module.renderedLength !== 'number') throw new Error('Missing renderedLength: ' + id)
      const pkg = module.renderedLength > 0 && packageFor(id)
      if (pkg) packages.set('browser:' + pkg.name, { pkg, group: 'browser' })
    }
    if (item.type === 'asset' && item.fileName.endsWith('.woff2')) {
      if (!item.originalFileNames?.length) throw new Error('Font origin absent: ' + item.fileName)
      for (const id of item.originalFileNames) {
        const pkg = packageFor(id)
        if (!pkg?.name.startsWith('@fontsource/')) throw new Error('Unexpected font origin: ' + id)
        packages.set('font:' + pkg.name, { pkg, group: 'font' })
      }
    }
  }
  const add = (entry, text) => { entries.push(entry); full.push(`${entry.name} ${entry.version} ${entry.license}\n${entry.note || ''}\n${text}`) }
  for (const { pkg, group } of packages.values()) {
    const licenseText = texts(pkg.dir)
    if (!licenseText || typeof pkg.license !== 'string') throw new Error('Package license absent: ' + pkg.name)
    add({ group, name: pkg.name, version: pkg.version, license: pkg.license }, licenseText)
  }
  for (const [group, cwd, target, env] of [
    ['controller', '../controller', './cmd/xdrop-controller', {}],
    ['node', '../node/agent', '.', { GOOS: 'linux', GOARCH: 'amd64' }],
  ]) {
    const modules = command('go', ['list', '-deps', '-f', '{{with .Module}}{{.Path}} {{.Version}} {{.Dir}}{{end}}', target], resolve(root, cwd), env)
    for (const line of [...new Set(modules.split('\n'))].filter(Boolean).sort()) {
      const [name, version, dir] = line.split(' ')
      if (!version) continue
      const licenseText = texts(dir), license = fingerprint(licenseText)
      add({ group, name, version, license, ...(name.endsWith('/go-sqlite3') ? { note: '内含 SQLite（公有领域）' } : {}) }, licenseText)
    }
  }
  for (const { entry, text } of bpfSources(resolve(root, '../node/bpf'))) add(entry, text)
  const goText = goLicense(command('go', ['env', 'GOROOT'])).text
  add({ group: 'go', name: 'Go', version: command('go', ['env', 'GOVERSION']), license: fingerprint(goText) }, goText)
  entries.sort((a, b) => (a.group + ':' + a.name).localeCompare(b.group + ':' + b.name))
  if (JSON.stringify(entries).includes('://')) throw new Error('URL in license metadata')
  this.emitFile({ type: 'asset', fileName: 'third-party.json', source: JSON.stringify(entries, null, 2) + '\n' })
  this.emitFile({ type: 'asset', fileName: 'third-party.txt', source: full.join('\n\n' + '='.repeat(72) + '\n\n') + '\n' })
}
export function serveThirdParty(server) {
  server.middlewares.use((req, res, next) => {
    if (!['/third-party.json', '/third-party.txt'].includes(req.url)) return next()
    try { res.setHeader('Content-Type', req.url.endsWith('.json') ? 'application/json' : 'text/plain; charset=utf-8'); res.end(read(join(output, req.url.slice(1)))) }
    catch { res.statusCode = 404; res.end() }
  })
}
function equal(label, actual, expected) {
  const a = [...new Set(actual)].sort(), e = [...new Set(expected)].sort(), missing = a.filter(x => !e.includes(x)), extra = e.filter(x => !a.includes(x))
  console.log(`${label} 独立派生 ${JSON.stringify(a)}\n${label} json 集合 ${JSON.stringify(e)}\n${label} 差集 missing=${JSON.stringify(missing)} extra=${JSON.stringify(extra)}`)
  return missing.length === 0 && extra.length === 0
}
export function bpfWitness(dir, manifest) {
  const headers = walk(join(dir, 'headers')), bpf = manifest.filter(x => x.group === 'bpf')
  const programs = readdirSync(dir).filter(n => n.endsWith('.c')).sort().reverse(), programName = programs.join(' · ')
  const headerEntries = bpf.filter(x => x.name !== programName)
  let ok = headers.length === headerEntries.length && bpf.some(x => x.name === programName) && bpf.every(x => x.license === 'GPL-2.0')
  console.log(`BPF headers independent=${headers.length} json=${headerEntries.length} files=${JSON.stringify(headers.map(p => relative(root, p)))}`)
  for (const name of programs) {
    const lines = read(join(dir, name)).split('\n'), declarations = []
    for (let i = 0; i < lines.length; i++) {
      const position = lines[i].search(/\bSEC\b/)
      if (position < 0) continue
      let statement = lines[i].slice(position)
      while (!statement.includes(';') && i + 1 < lines.length) statement += '\n' + lines[++i]
      if (!statement.includes('"license"')) continue
      const parts = statement.split(';')
      for (const [index, candidate] of parts.entries()) {
        if (!candidate.includes('"license"')) continue
        const open = candidate.indexOf('('), close = candidate.indexOf(')', open + 1), ending = candidate.slice(close + 1).trim().replace(/^=\s*/, '= ')
        declarations.push(index < parts.length - 1 && candidate.slice(0, open).trim() === 'SEC' && candidate.slice(open + 1, close).trim() === '"license"' && ending === '= "GPL"')
      }
    }
    const pass = declarations.length === 1 && declarations[0] === true
    console.log(`BPF independent statement ${name} declarations=${declarations.length} ${pass ? 'PASS' : 'FAIL'}`); ok = pass && ok
  }
  const md5 = createHash('md5').update(readFileSync(join(root, 'scripts/licenses/GPL-2.0.txt'))).digest('hex')
  ok = md5 === '570a9b3749dd0463a1778803b12a6dce' && ok
  console.log(`GPL-2.0.txt md5=${md5} BPF ${ok ? 'PASS' : 'FAIL'}`); return ok
}
// Independent witness: sourcemap paths and content-addressed font files. Never calls packageFor/generateThirdParty.
async function check() {
  const temp = mkdtempSync(join(tmpdir(), 'third-party-check-'))
  command(process.execPath, [join(root, 'node_modules/vite/bin/vite.js'), 'build', '--sourcemap', '--outDir', temp])
  const built = walk(temp), manifest = json(process.env.C5D_LICENSE_JSON || join(output, 'third-party.json')), browsers = new Set()
  for (const file of built.filter(p => p.endsWith('.map'))) for (const source of json(file).sources) {
    const sourcePath = resolve(dirname(file), source), match = /^(.*\/node_modules\/(?:@[^/]+\/)?[^/]+)\//.exec(sourcePath)
    if (match) { const pkg = json(join(match[1], 'package.json')); browsers.add(pkg.name + '@' + pkg.version) }
  }
  let ok = equal('browser', [...browsers], manifest.filter(x => x.group === 'browser').map(x => x.name + '@' + x.version))
  const referenced = new Set()
  for (const css of built.filter(p => p.endsWith('.css'))) for (const url of read(css).matchAll(/url\(\s*["']?([^"')\s]+)["']?\s*\)/g)) {
    const pathname = decodeURIComponent(url[1].split(/[?#]/)[0])
    if (pathname.endsWith('.woff2')) referenced.add(pathname.startsWith('/') ? join(temp, pathname) : resolve(dirname(css), pathname))
  }
  ok = equal('woff2 CSS/产物', [...referenced].map(p => relative(temp, p)), built.filter(p => p.endsWith('.woff2')).map(p => relative(temp, p))) && ok
  const digest = file => createHash('sha256').update(readFileSync(file)).digest('hex'), candidates = new Map(), fonts = new Set()
  for (const file of walk(join(root, 'node_modules/@fontsource')).filter(p => p.endsWith('.woff2'))) {
    let dir = dirname(file)
    while (!existsSync(join(dir, 'package.json'))) dir = dirname(dir)
    const pkg = json(join(dir, 'package.json')), hash = digest(file), entries = candidates.get(hash) || []
    entries.push({ file, pkg: pkg.name + '@' + pkg.version }); candidates.set(hash, entries)
  }
  for (const file of referenced) {
    if (!existsSync(file)) { console.log('字体引用不存在 ' + file); ok = false; continue }
    const hash = digest(file), matches = candidates.get(hash) || [], owners = [...new Set(matches.map(x => x.pkg))]
    console.log(`${relative(temp, file)} → ${hash} → ${JSON.stringify(owners)}`)
    if (owners.length !== 1) { console.log('字体来源失败 ' + JSON.stringify(matches)); ok = false }
    else fonts.add(owners[0])
  }
  ok = equal('font', [...fonts], manifest.filter(x => x.group === 'font').map(x => x.name + '@' + x.version)) && ok
  for (const [name, licenses] of [['zrender', ['BSD-3-Clause']], ['echarts', ['Apache-2.0']], ['gopkg.in/yaml.v3', ['MIT', 'Apache-2.0']], ['tslib', ['0BSD']], ['golang.org/x/crypto', ['BSD-3-Clause']], ['Go', ['BSD-3-Clause']]]) {
    const item = manifest.find(x => x.name === name), pass = licenses.every(x => item?.license.split(' AND ').includes(x))
    console.log(`点名 ${name} ${item?.license} ${pass ? 'PASS' : 'FAIL'}`); ok = pass && ok
  }
  const nodeBinary = join(temp, 'xdrop-agent'), nodeEnv = { GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' }
  console.log('node go env GOOS GOARCH CGO_ENABLED GOVERSION\n' + command('go', ['env', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOVERSION'], root, nodeEnv))
  command('go', ['build', '-o', nodeBinary, '.'], resolve(root, '../node/agent'), nodeEnv)
  const nodeInfo = command('go', ['version', '-m', nodeBinary]); console.log(nodeInfo)
  const nodeDeps = [...nodeInfo.matchAll(/^\s*dep\s+(\S+)\s+(\S+)/gm)].map(m => m[1] + '@' + m[2])
  ok = equal('node', nodeDeps, manifest.filter(x => x.group === 'node').map(x => x.name + '@' + x.version)) && ok
  ok = bpfWitness(resolve(root, '../node/bpf'), manifest) && ok
  if (process.env.C5D_BINARY) {
    console.log('go env GOOS GOARCH CGO_ENABLED GOVERSION\n' + command('go', ['env', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOVERSION']))
    const info = command('go', ['version', '-m', process.env.C5D_BINARY]); console.log(info)
    const deps = [...info.matchAll(/^\s*dep\s+(\S+)\s+(\S+)/gm)].map(m => m[1] + '@' + m[2])
    ok = equal('controller', deps, manifest.filter(x => x.group === 'controller').map(x => x.name + '@' + x.version)) && ok
    const go = manifest.filter(x => x.group === 'go'), version = info.split('\n')[0].match(/go\d[^\s]*$/)?.[0]
    const pass = go.length === 1 && go[0].version === version; console.log(`Go 单列 ${JSON.stringify(go)} binary=${version} ${pass ? 'PASS' : 'FAIL'}`); ok = pass && ok
  }
  console.log(`G2 ${ok ? 'PASS' : 'FAIL'}`); process.exitCode = ok ? 0 : 1
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href && process.argv.includes('--check')) await check()
