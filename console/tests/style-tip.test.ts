import { it, expect } from 'vitest'
const fsModule='node:fs', pathModule='node:path'
const fs=await import(fsModule), path=await import(pathModule)
function invalid(text: string) {
  if (/attr\(\s*data-tip\s*\)/.test(text)) return true
  return [...text.replace(/\/\*[\s\S]*?\*\//g,'').matchAll(/([^{}]+)\{/g)].some(m => m[1]!.split(',').some(s => /^\.tip(?:\s*:[\w-]+(?:\([^)]*\))?)*\s*::?(?:after|before)(?:\b|$)/.test(s.trim().replace(/\s+/g,' '))))
}
it('G9 V17 every css and Vue style has no tip pseudo-elements or data-tip outlet', () => {
  function read(dir: string): string[] { return fs.readdirSync(dir,{withFileTypes:true}).flatMap((d: {name:string;isDirectory():boolean})=> { const p=path.join(dir,d.name); return d.isDirectory()?read(p):/\.(css|vue)$/.test(p)?[p]:[] }) }
  const files = read('src')
  expect(files.filter(file => file.endsWith('.css')).length).toBeGreaterThanOrEqual(1)
  expect(files.filter(file => file.endsWith('.vue')).length).toBeGreaterThanOrEqual(1)
  for (const file of files) { const raw=fs.readFileSync(file,'utf8'); const style=file.endsWith('.css')?raw:[...raw.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/g)].map(m=>m[1]).join('\n'); expect(invalid(style),file).toBe(false) }
})
it.each(['.tip::after{opacity:1}', '.x::before{content:attr(data-tip)}', '.a,.tip:hover::after{}', '.tip:focus-visible::after{}', '.tip:before{}', '.tip\n:hover\n::after\n{ opacity: 1 }'])('G9 independent positive %s', text => { expect(invalid(text)).toBe(true) })
it('G9 negative hover control', () => { expect(invalid('.tip:hover{color:red}')).toBe(false) })
