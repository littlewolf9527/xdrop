<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { captureSession } from '../state'
import type { ThirdParty } from '../api/types'
import RuleError from '../components/RuleError.vue'
const { t } = useI18n(), items = ref<ThirdParty[]>([]), error = ref<unknown>(null), version = __XD_VERSION__
function noteTitle(item: ThirdParty) {
  const key = ['controller', 'node'].includes(item.group) && item.name === 'github.com/mattn/go-sqlite3' ? 'sqliteNote' :
    item.group === 'bpf' && item.name === 'xdrop_main.c · xdrop_gate.c' ? 'bpfProgramNote' : ''
  return key ? t(key) : undefined
}
let alive = true
onBeforeUnmount(() => { alive = false })
onMounted(async () => {
  const session = captureSession()
  try {
    const response = await fetch('/third-party.json', { credentials: 'same-origin' })
    if (!response.ok) throw new Error('License resource unavailable')
    const result = await response.json() as ThirdParty[]
    if (alive && session.isCurrent()) items.value = result
  } catch (e) { if (alive && session.isCurrent()) error.value = e }
})
</script>
<template>
  <section class="page about-page"><div class="page-head"><h1>{{ t('about') }}</h1></div>
    <div class="about-brand"><span class="logo-full" role="img" aria-label="XDROP" /><div><strong>XDROP</strong><p>{{ t('version') }} <span class="mono">{{ version }}</span></p><p>© 2026 LittleWolf · {{ t('mit') }}</p><a href="https://github.com/littlewolf9527/xdrop" target="_blank" rel="noopener">https://github.com/littlewolf9527/xdrop</a></div></div>
    <RuleError v-if="error" :error="error" />
    <section v-for="group in ['browser','controller','node','bpf','font']" :key="group" class="panel about-group"><div class="panel-head"><h2>{{ t(group === 'node' ? 'nodeAgent' : group) }}</h2></div><div class="tbl-wrap"><table><thead><tr><th>{{ t('name') }}</th><th>{{ t('version') }}</th><th>{{ t('license') }}</th></tr></thead><tbody>
      <tr v-for="item in items.filter(row => row.group === group || (group === 'controller' && row.group === 'go'))" :key="item.group + item.name"><td :title="noteTitle(item)">{{ item.name }}</td><td class="mono">{{ item.version }}</td><td>{{ item.license }}</td></tr>
    </tbody></table></div></section>
    <a href="/third-party.txt" target="_blank" rel="noopener">{{ t('licensesText') }}</a>
  </section>
</template>
