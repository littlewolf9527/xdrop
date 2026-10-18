import { it, expect } from 'vitest'
const fsModule = 'node:fs', cpModule = 'node:child_process', processModule = 'node:process', osModule = 'node:os'
const fs = await import(fsModule), cp = await import(cpModule), process = await import(processModule), os = await import(osModule)
it('R4-5 R3-5 artifact scan uses a self-contained fixture and rejects decoded URLs recursively', () => {
  const temp = fs.mkdtempSync(os.tmpdir() + '/r4-scan-'), extra = temp + '/escaped.json', report = temp + '/scan.json'
  const fixtureConsole = temp + '/console', build = temp + '/controller/core/webui/build'
  const scanner = process.cwd() + '/scripts/artifact-scan.mjs'
  const cases = [String.raw`[{"note":"https\u003a//example.invalid/"}]`, String.raw`{"nested":[{"https\u003a//example.invalid/":"plain"}]}`,
    String.raw`{"nested":[{"value":"https:\/\/example.invalid/"}]}`]
  try {
    fs.mkdirSync(build, { recursive: true }); fs.mkdirSync(fixtureConsole + '/mock', { recursive: true })
    fs.writeFileSync(build + '/third-party.json', JSON.stringify([{ group: 'browser', name: 'fixture', version: '1', license: 'MIT' }]))
    fs.writeFileSync(build + '/index.js', 'export {};'); fs.writeFileSync(fixtureConsole + '/mock/control.js', '/* XDROP_MOCK_ONLY */')
    const scan = () => cp.spawnSync(process.execPath, [scanner], { cwd: fixtureConsole, encoding: 'utf8', env: { ...process.env, C5D_SCAN_EXTRA: extra, C5D_SCAN_JSON: report } })
    fs.writeFileSync(extra, '{}'); expect(scan().status).toBe(0)
    for (const raw of cases) {
      expect(raw.includes('://')).toBe(false); fs.writeFileSync(extra, raw)
      const run = scan(), result = JSON.parse(fs.readFileSync(report, 'utf8'))
      expect(result.metadataInvalid).toBeGreaterThanOrEqual(1); expect(run.status).toBe(1)
      expect(run.stdout).toContain('json 键/URL 违例'); console.log('R4-5 R3-5 escaped JSON positive', JSON.stringify({ raw, metadataInvalid: result.metadataInvalid, rc: run.status }))
    }
  } finally { fs.rmSync(temp, { recursive: true }) }
})
it('R10b-1 real artifact contains one JS-only exact ElDialog diagnostic; other contexts and URLs stay rejected', () => {
  const temp = fs.mkdtempSync(os.tmpdir() + '/r10b-scan-'), fixtureConsole = temp + '/console', build = temp + '/controller/core/webui/build'
  const scanner = process.cwd() + '/scripts/artifact-scan.mjs', report = temp + '/scan.json', url = 'https://element-plus.org/en-US/component/dialog.html#slots'
  const paths = (dir: string): string[] => fs.readdirSync(dir).flatMap((name: string) => fs.statSync(dir + '/' + name).isDirectory() ? paths(dir + '/' + name) : [dir + '/' + name])
  try {
    fs.mkdirSync(fixtureConsole + '/mock', { recursive: true }); fs.writeFileSync(fixtureConsole + '/mock/control.js', '/* XDROP_MOCK_ONLY */')
    const built = cp.spawnSync(process.execPath, [process.cwd() + '/node_modules/vite/bin/vite.js', 'build', '--outDir', build, '--emptyOutDir'], { encoding: 'utf8', env: { ...process.env, NODE_ENV: 'production' } })
    expect(built.status, built.stdout + built.stderr).toBe(0)
    const occurrences = paths(build).flatMap(path => {
      const count = fs.readFileSync(path, 'utf8').split(url).length - 1
      return count ? [{ path, count }] : []
    })
    expect(occurrences.reduce((n, entry) => n + entry.count, 0)).toBe(1)
    expect(occurrences.every(entry => entry.path.endsWith('.js'))).toBe(true)
    const scan = (extra?: string) => cp.spawnSync(process.execPath, [scanner], { cwd: fixtureConsole, encoding: 'utf8', env: { ...process.env, C5D_SCAN_EXTRA: extra || '', C5D_SCAN_JSON: report } })
    expect(scan().status).toBe(0); expect(JSON.parse(fs.readFileSync(report, 'utf8')).violations).toEqual([])
    console.log('R10b-1 independent artifact occurrences', JSON.stringify(occurrences))
    for (const [suffix, content] of [['html', `<a href="${url}">doc</a>`], ['json', JSON.stringify({ note: url })], ['js', `const diagnostic="${url}-other";`]]) {
      const extra = temp + '/positive.' + suffix; fs.writeFileSync(extra, content)
      const checked = scan(extra), result = JSON.parse(fs.readFileSync(report, 'utf8'))
      expect(checked.status).toBe(1); expect(result.violations.length + result.metadataInvalid).toBeGreaterThan(0)
      console.log('R10b-1 artifact-positive', JSON.stringify({ suffix, violations: result.violations.length, metadataInvalid: result.metadataInvalid, rc: checked.status }))
    }
  } finally { fs.rmSync(temp, { recursive: true }) }
}, 60000)
