import { watch } from 'vue'
import { i18n } from '../src/i18n'

const messages = {
  'en-US': ['Demo · sample data', 'Sample data in this tab only; reloading resets it.'],
  'zh-CN': ['演示 · 示例数据', '示例数据只存在于本标签页，刷新即恢复。'],
  'ja-JP': ['デモ · サンプルデータ', 'サンプルデータはこのタブ内だけに保存され、再読み込みで元に戻ります。'],
}
const badge = document.createElement('span')
badge.id = 'xdrop-demo-badge'
badge.style.cssText = 'position:fixed;right:12px;bottom:4px;z-index:1000;padding:2px 8px;border-radius:4px;font-size:11px;line-height:16px;pointer-events:auto;background:var(--panel);color:var(--ink);border:1px solid var(--line)'
watch(i18n.global.locale, locale => {
  const [label, title] = messages[locale] || messages['en-US']
  badge.textContent = label!
  badge.title = title!
}, { immediate: true })
document.body.appendChild(badge)
