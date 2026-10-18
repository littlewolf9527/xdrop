<script setup lang="ts">
import { computed, ref, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElTooltip } from 'element-plus'
import { request } from '../../state'
import { ApiError } from '../../api/client'
import type { Settings } from '../../api/types'
import { jsonWrite, settingsError, settingsDelta, useSettingsRequests } from '../../settings'
const { t } = useI18n()
const { data, loading, error, writing, actionError, load, write } = useSettingsRequests<Settings | null>('/settings', null, e => settingsError('system', e))
const draft = ref<Settings | null>(null), saved = ref(false), fieldError = ref('')
const fields = [
  { key: 'session_hours', values: [8,24,72], standard: 24, unit: 'hours', help: 'sessionHelp' },
  { key: 'audit_retention_days', values: [90,180,365], standard: 180, unit: 'days', help: '' },
  { key: 'reconcile_interval_minutes', values: [5,15,60], standard: 15, unit: 'minutes', help: 'reconcileHelp' },
  { key: 'history_retention_days', values: [7,30,90], standard: 30, unit: 'days', help: 'historyHelp' },
] as const
const delta = computed(() => data.value && draft.value ? settingsDelta(data.value, draft.value) : {})
watch(data, (value, previous) => {
  if (value) {
    const edits = previous && draft.value ? settingsDelta(previous, draft.value) : {}
    draft.value = { ...value, ...edits }
  }
})
function changed() { saved.value = false; fieldError.value = ''; actionError.value = '' }
function options(field: typeof fields[number]) { const current = data.value?.[field.key]; return [...new Set([...field.values, ...(current === undefined ? [] : [current])])].sort((a,b) => a-b) }
function save() {
  if (!Object.keys(delta.value).length || writing.value) return
  changed()
  void write(() => request<Settings>('/settings', jsonWrite('PUT', delta.value)), value => { data.value = value; draft.value = { ...value }; saved.value = true; void load() }, e => {
    if (e instanceof ApiError && e.envelope.code === 'invalid_field' && ['default_language', ...fields.map(field => field.key)].includes(e.envelope.field || '')) { fieldError.value = e.envelope.field!; actionError.value = '' }
  })
}
onMounted(() => load())
</script>
<template>
  <section data-tab="system">
    <div class="toolbar settings-actions"><button class="btn" @click="load()">{{ t('auditRefresh') }}</button></div>
    <p v-if="error" class="error-text" role="alert">{{ t(error) }}</p><p v-if="loading" role="status">{{ t('auditLoading') }}</p>
    <form v-if="draft" class="panel sys" @submit.prevent="save" @change="changed">
      <div v-for="field in fields" :key="field.key" class="srow" :data-field="field.key"><label :for="'setting-' + field.key">{{ t('settingsUI.' + field.key) }} <ElTooltip v-if="field.help" :content="t('settingsUI.' + field.help)" :trigger="['hover','click','focus']" popper-class="rule-help-popover"><span class="tip" tabindex="0" role="img" :aria-label="t('settingsUI.' + field.key)" :data-tip="t('settingsUI.' + field.help)">?</span></ElTooltip></label><select :id="'setting-' + field.key" v-model.number="draft[field.key]" :disabled="writing"><option v-for="value in options(field)" :key="value" :value="value">{{ t('settingsUI.' + field.unit, { n: value }) }}{{ value === field.standard ? t('settingsUI.default') : '' }}</option></select><span v-if="fieldError === field.key" class="error-text" role="alert">{{ t('settingsUI.outOfRange') }}</span></div>
      <div class="srow" data-field="default_language"><label for="setting-language">{{ t('settingsUI.default_language') }} <ElTooltip :content="t('settingsUI.languageHelp')" :trigger="['hover','click','focus']" popper-class="rule-help-popover"><span class="tip" tabindex="0" role="img" :aria-label="t('settingsUI.default_language')" :data-tip="t('settingsUI.languageHelp')">?</span></ElTooltip></label><select id="setting-language" v-model="draft.default_language" :disabled="writing"><option value="zh-CN">中文</option><option value="ja-JP">日本語</option><option value="en-US">English</option></select><span v-if="fieldError === 'default_language'" class="error-text" role="alert">{{ t('settingsUI.outOfRange') }}</span></div>
      <p v-if="actionError" class="error-text" role="alert">{{ t(actionError) }}</p><p v-if="saved" role="status">{{ t('settingsUI.saved') }}</p><div class="toolbar settings-actions"><button class="btn primary" :disabled="!Object.keys(delta).length || writing" :aria-busy="writing">{{ t('settingsUI.save') }}</button></div>
    </form>
  </section>
</template>
