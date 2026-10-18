import { spawnSync } from 'node:child_process'
import { mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
export function validVitestReport(report) {
  return report?.success === true && Number.isInteger(report.numPassedTests) && report.numPassedTests > 0 && report.numFailedTests === 0
    && report.numPendingTests === 0 && report.numTodoTests === 0
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const out = resolve(process.env.C5D_OUT || '../../out')
  mkdirSync(out, { recursive: true })
  const commands = [
    ['npm-ci', 'npm', ['ci', '--ignore-scripts']],
    ['vue-tsc', 'npx', ['--no-install', 'vue-tsc', '--noEmit']],
    ['vitest', 'npx', ['--no-install', 'vitest', 'run', '--reporter=json', `--outputFile=${out}/vitest.json`]],
    ['build', 'npm', ['run', 'build']],
  ]
  let failed = false
  for (const [name, command, args] of commands) {
    if (name === 'vitest') rmSync(`${out}/vitest.json`, { force: true })
    const result = spawnSync(command, args, { encoding: 'utf8' }), raw = (result.stdout || '') + (result.stderr || '')
    writeFileSync(`${out}/${name}.txt`, raw)
    const diagnostics = raw.split('\n').filter(line => /error TS\d+|\bError\b|\bFAIL\b|failed|npm error|ERR_/i.test(line)).length
    console.log(`${command} ${args.join(' ')} · RC ${result.status} · 诊断行数 ${diagnostics}`)
    if (name === 'vue-tsc' && diagnostics > 0) failed = true
    if (result.status !== 0) failed = true
    if (name === 'vitest') {
      try {
        const report = JSON.parse(readFileSync(`${out}/vitest.json`, 'utf8'))
        console.log(`Vitest JSON · 通过 ${report.numPassedTests} · 失败 ${report.numFailedTests}`
          + ` · 跳过 ${report.numPendingTests} · todo ${report.numTodoTests}`)
        if (!validVitestReport(report)) failed = true
      } catch { failed = true }
    }
  }
  process.exitCode = failed ? 1 : 0
}
