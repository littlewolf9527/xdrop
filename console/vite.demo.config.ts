import { defineConfig, type Plugin } from 'vite'
import vue from '@vitejs/plugin-vue'

const pathModule = 'node:path', fsModule = 'node:fs', urlModule = 'node:url', processModule = 'node:process'
const { resolve } = await import(pathModule) as { resolve(...paths: string[]): string }
const { copyFileSync } = await import(fsModule) as { copyFileSync(from: string, to: string): void }
const { fileURLToPath } = await import(urlModule) as { fileURLToPath(url: URL): string }
const { env } = await import(processModule) as { env: Record<string, string | undefined> }
const licenses = await import(new URL('./scripts/third-party.mjs', import.meta.url).href)
const demoRoot = fileURLToPath(new URL('./demo/', import.meta.url))

export default defineConfig({
  root: 'demo',
  base: '/xdrop/',
  define: { __XD_VERSION__: JSON.stringify(env.XDROP_VERSION || 'demo') },
  plugins: [vue(), {
    name: 'third-party',
    generateBundle(_options, bundle) {
      const normalized = Object.fromEntries(Object.entries(bundle).map(([name, item]) => [name,
        item.type === 'asset' && item.originalFileNames ? { ...item, originalFileNames: item.originalFileNames.map(id => resolve(demoRoot, id)) } : item,
      ]))
      licenses.generateThirdParty.call(this, normalized)
    },
  } as Plugin, {
    name: 'pages-fallback',
    writeBundle(options) {
      const directory = options.dir || resolve(demoRoot, '../demo-dist')
      copyFileSync(resolve(directory, 'index.html'), resolve(directory, '404.html'))
    },
  }],
  build: { outDir: '../demo-dist', emptyOutDir: true },
})
