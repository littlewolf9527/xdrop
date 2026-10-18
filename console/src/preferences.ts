import type {
  Language, Theme, PanelKey, Preferences
} from './api/types'
export const languages: Language[] = ['zh-CN', 'ja-JP', 'en-US']
export const themes: Theme[] = ['auto', 'light', 'dark']
export const defaultOrder: PanelKey[] = ['pps', 'ip', 'bps', 'rules']
export const isLanguage = (v: unknown): v is Language => languages.includes(v as Language)
export const isTheme = (v: unknown): v is Theme => themes.includes(v as Theme)
export function browserLanguage(list: readonly string[]): Language | undefined {
  for (const language of list) {
    const found = ({
      zh: 'zh-CN', ja: 'ja-JP', en: 'en-US'
    } as const)[language.split('-')[0]!.toLowerCase() as 'zh' | 'ja' | 'en']
    if (found) return found

  }
}
export function resolveLanguage(prefs: unknown, list: readonly string[], system: unknown = 'en-US'): Language {
  return isLanguage(prefs) ? prefs : browserLanguage(list) ?? (isLanguage(system) ? system : 'en-US')
}
export function stored(key: 'xd.lang' | 'xd.theme'): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}
export function storeLocal(key: 'xd.lang' | 'xd.theme', value: string): void {
  try {
    localStorage.setItem(key, value)
  } catch {
  }
}
export const loginLanguage = (list: readonly string[] = navigator.languages): Language => resolveLanguage(stored('xd.lang'), list)
export const resolveTheme = (pref: unknown, local: unknown): Theme => isTheme(pref) ? pref : isTheme(local) ? local : 'auto'
export const clampSplit = (value: unknown): number => typeof value === 'number' && Number.isFinite(value) ? Math.min(3.5, Math.max(.5,
  value)) : 1.4
export function readLayout(prefs: Preferences): {
  order: PanelKey[];
  split: number
} {
  const o = prefs.overview?.order
  return {
    order: Array.isArray(o) && o.length === 4 && new Set(o).size === 4 && o.every(k => defaultOrder.includes(k)) ? [...o] : [
      ...defaultOrder], split: clampSplit(prefs.overview?.split)
  }
}
export function mergePreferences(base: Preferences, patch: Preferences): Preferences {
  return {
    ...base, ...patch, v: 1, ...(patch.overview ? {
      overview: {
        ...base.overview, ...patch.overview
      }
    } : {
    })
  }
}
export function encodePreferences(prefs: Preferences): string | null {
  const body = JSON.stringify(prefs)
  if (new TextEncoder().encode(body).byteLength > 8192) {
    console.warn('Preferences exceed 8192 UTF-8 bytes');
    return null
  }
  return body
}
export function createPreferencesWriter(read: () => Promise<Preferences>, put: (body: string) => Promise<unknown>) {
  let pending: Promise<unknown> = Promise.resolve()
  return (patch: Preferences, isCurrent: () => boolean = () => true) => {
    const operation = pending.catch(() => {
    }).then(async () => {
      if (!isCurrent()) return
      const base = await read()
      if (!isCurrent()) return
      const value = mergePreferences(base, patch)
      const body = encodePreferences(value)
      if (body !== null && isCurrent()) await put(body)

    })
    pending = operation
    return operation

  }
}
