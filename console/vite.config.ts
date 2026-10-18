import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import type { Plugin } from 'vite'
const childProcessModule = 'node:child_process', urlModule = 'node:url', fsModule = 'node:fs', processModule = 'node:process'
const { execFileSync } = await import(childProcessModule) as { execFileSync(command: string, args: string[], options: { cwd: string; encoding: string; stdio: string[] }): string }
const { fileURLToPath } = await import(urlModule) as { fileURLToPath(url: URL): string }
const { realpathSync } = await import(fsModule) as { realpathSync(path: string): string }
const { env } = await import(processModule) as { env: Record<string, string | undefined> }
// Same order as scripts/build-node.sh: XDROP_VERSION, then git describe only when the repository root is itself the checkout.
function version() {
  if (env.XDROP_VERSION) return env.XDROP_VERSION
  const repo = realpathSync(fileURLToPath(new URL('..', import.meta.url))), git = (...args: string[]) => execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  try { if (git('rev-parse', '--show-toplevel') === repo) return git('describe', '--tags', '--always', '--dirty') } catch { /* no git or no .git */ }
  console.warn('WARNING: not a git checkout and XDROP_VERSION is unset; the console reports version "unknown"')
  return 'unknown'
}
const licenseModule = new URL('./scripts/third-party.mjs', import.meta.url).href
const licenses = await import(licenseModule)
export default defineConfig(async ({ command, mode }) => ({
  define: { __XD_VERSION__: JSON.stringify(version()) },
  plugins: [vue(), { name: 'third-party', generateBundle(_options, bundle) { licenses.generateThirdParty.call(this, bundle) }, configureServer(server) { licenses.serveThirdParty(server) } } as Plugin, ...(command === 'serve' && mode === 'development' ? [(await import('./mock/server.ts')).mockPlugin()] : [])],
  server: { host: '127.0.0.1', port: 5173, strictPort: true, ...(mode === 'real' ? { proxy: { '/api': { target: 'http://127.0.0.1:18080', configure(proxy: unknown) { const events = proxy as { on(name: string, listener: (response: unknown, request: unknown) => void): void }; events.on('proxyRes', (response, request) => { const r = response as unknown as { statusCode: number }; const q = request as unknown as { method: string; url: string }; console.info('G6_API', q.method, q.url, r.statusCode) }) } } } } : {}) },
  build: { outDir: '../controller/core/webui/build', emptyOutDir: true, chunkSizeWarningLimit: 1500 },
  test: { environment: 'jsdom', include: ['tests/**/*.test.ts'], restoreMocks: true },
}))
