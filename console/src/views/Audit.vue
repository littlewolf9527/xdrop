<script setup lang="ts">
import { ref, watch, onMounted, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { request, captureSession, canSettings, expire, refreshIdentity } from '../state'
import type { AuditEvent, AuditPage } from '../api/types'
import { genericKey } from '../errors'
import { auditGroups, auditActions, auditActor, auditTime, exportAudit, AuditInterrupted } from '../audit'
const { t } = useI18n(), router = useRouter()
const action = ref(''), rows = ref<AuditEvent[]>([]), cursor = ref(''), busy = ref(false), moreBusy = ref(false), exporting = ref(false)
const error = ref(''), moreError = ref(''), exportError = ref('')
let sequence = 0, alive = true
const actionQuery = () => action.value ? '&action=' + encodeURIComponent(action.value) : ''
async function firstPage() {
  const serial = ++sequence, session = captureSession()
  const current = () => alive && serial === sequence && session.isCurrent()
  rows.value = []; cursor.value = ''; busy.value = true; moreBusy.value = false; error.value = ''; moreError.value = ''
  try {
    const page = await request<AuditPage>('/audit?limit=100' + actionQuery())
    if (!current()) return
    rows.value = page.items; cursor.value = page.next_cursor
  } catch (e) { if (current()) error.value = genericKey(e) }
  finally { if (current()) busy.value = false }
}
async function more() {
  if (!cursor.value || busy.value || moreBusy.value) return
  const serial = sequence, session = captureSession()
  const current = () => alive && serial === sequence && session.isCurrent()
  moreBusy.value = true; moreError.value = ''
  try {
    const page = await request<AuditPage>('/audit?limit=100&cursor=' + encodeURIComponent(cursor.value) + actionQuery())
    if (!current()) return
    rows.value.push(...page.items); cursor.value = page.next_cursor
  } catch (e) { if (current()) moreError.value = genericKey(e) }
  finally { if (current()) moreBusy.value = false }
}
async function download(format: 'csv' | 'json') {
  if (exporting.value || !canSettings.value) return
  const session = captureSession(), current = () => alive && session.isCurrent()
  exporting.value = true; exportError.value = ''
  try {
    await exportAudit(format, action.value, current, {
      expired: expire,
      demoted: async () => { await refreshIdentity(); if (current()) await router.replace('/overview') },
    })
  } catch (e) { if (current()) exportError.value = e instanceof AuditInterrupted ? 'auditInterrupted' : genericKey(e) }
  finally { if (current()) exporting.value = false }
}
watch(action, firstPage)
onMounted(firstPage)
onBeforeUnmount(() => { alive = false })
</script>
<template>
  <div class="page audit-page">
    <div class="page-head"><h1>{{ t('audit') }}</h1><div class="toolbar">
      <select v-model="action" :aria-label="t('auditFilter')"><option value="">{{ t('auditAll') }}</option><template v-for="(group, i) in auditGroups" :key="i"><option v-for="value in group" :key="value" :value="value">{{ t('auditActions.' + value) }}</option></template></select>
      <button class="btn" @click="firstPage">{{ t('auditRefresh') }}</button>
      <template v-if="canSettings"><button v-for="format in ['csv', 'json'] as const" :key="format" class="btn audit-export" :disabled="exporting" :aria-busy="exporting" @click="download(format)">{{ t(format === 'csv' ? 'auditCSV' : 'auditJSON') }}</button></template>
    </div></div>
    <p v-if="error" class="error-text" role="alert">{{ t(error) }}</p>
    <p v-if="exportError" class="error-text" role="alert">{{ t(exportError) }}</p>
    <p v-if="busy" role="status">{{ t('auditLoading') }}</p>
    <div class="tbl-wrap rules"><table><thead><tr><th v-for="key in ['auditTime', 'auditActor', 'action', 'auditTarget', 'auditSource']" :key="key">{{ t(key) }}</th></tr></thead><tbody>
      <tr v-for="row in rows" :key="row.id"><td class="num" :title="row.at">{{ auditTime(row.at) }}</td><td class="mono" :title="row.actor">{{ auditActor(row.actor) }}</td><td :class="{ crit: row.action === 'auth.login_failed' }">{{ auditActions.includes(row.action) ? t('auditActions.' + row.action) : row.action }}</td><td class="mono">{{ row.target }}</td><td class="mono">{{ row.source || '—' }}</td></tr>
    </tbody></table></div>
    <p v-if="!busy && !error && !rows.length" class="audit-empty">{{ t(action ? 'auditFilteredEmpty' : 'auditEmpty') }}</p>
    <div class="audit-more"><button v-if="cursor" class="btn" :disabled="moreBusy" :aria-busy="moreBusy" @click="more">{{ t('loadMore') }}</button><span v-if="moreError" class="error-text" role="alert">{{ t(moreError) }}</span></div>
  </div>
</template>
<style scoped>
.audit-page .btn, .audit-page select { min-height: 28px; white-space: nowrap; }
.audit-page select { max-width: 100%; min-width: 0; }
.audit-page td, .audit-page th { white-space: nowrap; }
.audit-page .crit { color: var(--crit); }
.audit-more { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.audit-empty { color: var(--muted); }
</style>
