import { createI18n } from 'vue-i18n'
import zh from './zh-CN.json'
import ja from './ja-JP.json'
import en from './en-US.json'
export const messages = { 'zh-CN': zh, 'ja-JP': ja, 'en-US': en }
export const i18n = createI18n({ legacy: false, locale: 'en-US', fallbackLocale: 'en-US', messages })
