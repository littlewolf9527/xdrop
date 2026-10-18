declare module 'node:fs' {
  export function readFileSync(path: string | URL, encoding: 'utf8'): string
}
declare module 'node:process' {
  export function cwd(): string
}
