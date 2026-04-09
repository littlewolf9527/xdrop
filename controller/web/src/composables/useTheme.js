import { ref, readonly } from 'vue'

const VALID_THEMES = ['classic', 'amber']
const STORAGE_KEY = 'theme'

function normalizeTheme(raw) {
  if (VALID_THEMES.includes(raw)) return raw
  return 'classic'
}

// Singleton reactive state
const theme = ref('classic')

function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t)
}

export function bootstrapTheme() {
  const saved = localStorage.getItem(STORAGE_KEY)
  const t = normalizeTheme(saved)
  theme.value = t
  applyTheme(t)
  // Migrate legacy values
  if (saved !== t) {
    localStorage.setItem(STORAGE_KEY, t)
  }
}

export function useTheme() {
  function setTheme(t) {
    const normalized = normalizeTheme(t)
    theme.value = normalized
    localStorage.setItem(STORAGE_KEY, normalized)
    applyTheme(normalized)
  }

  return {
    theme: readonly(theme),
    setTheme
  }
}

// Provide/inject key
export const themeKey = Symbol('theme')
