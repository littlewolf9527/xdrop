import { createI18n } from 'vue-i18n'
import zhCN from './zh-CN.json'
import enUS from './en-US.json'
import esES from './es-ES.json'
import koKR from './ko-KR.json'
import jaJP from './ja-JP.json'

const messages = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'es-ES': esES,
  'ko-KR': koKR,
  'ja-JP': jaJP
}

// Language detection: localStorage only, default to English
function getDefaultLocale() {
  const saved = localStorage.getItem('locale')
  if (saved && messages[saved]) return saved
  return 'en-US'
}

export const i18n = createI18n({
  legacy: false,  // Use Composition API
  locale: getDefaultLocale(),
  fallbackLocale: 'en-US',
  messages
})

export const availableLocales = [
  { code: 'en-US', name: 'English', flag: '🇺🇸' },
  { code: 'zh-CN', name: '简体中文', flag: '🇨🇳' },
  { code: 'es-ES', name: 'Español', flag: '🇪🇸' },
  { code: 'ko-KR', name: '한국어', flag: '🇰🇷' },
  { code: 'ja-JP', name: '日本語', flag: '🇯🇵' }
]

export function setLocale(locale) {
  i18n.global.locale.value = locale
  localStorage.setItem('locale', locale)
  document.documentElement.lang = locale
}

export function getCurrentLocale() {
  return i18n.global.locale.value
}
