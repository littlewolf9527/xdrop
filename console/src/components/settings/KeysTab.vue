<script setup lang="ts">
import { computed, ref, watch, onMounted, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElTooltip } from 'element-plus'
import { request, state, captureSession } from '../../state'
import { ApiError } from '../../api/client'
import type { CredentialDTO, IssuedDTO } from '../../api/types'
import { jsonWrite, settingsError, settingTime, groupCredentials, useSettingsRequests } from '../../settings'
const { t } = useI18n()
const { data, loading, loaded, error, writing, actionError, load, write } = useSettingsRequests<CredentialDTO[]>('/credentials', [], e => settingsError('keys', e))
const rows = computed(() => groupCredentials(data.value)), form = ref(false), name = ref(''), selected = ref(''), confirmation = ref('')
const plaintext = ref(''), keybox = ref<HTMLElement>(), manual = ref(false)
let alive = true
const canIssue = computed(() => name.value !== '' && loaded.value && !loading.value && !writing.value)
function closeKey() { plaintext.value = ''; manual.value = false }
watch(() => state.user, user => { if (user === null) closeKey() })
onBeforeUnmount(() => { alive = false; closeKey() })
function begin(kind: string, target = '') { form.value = kind === 'issue'; name.value = ''; selected.value = target; confirmation.value = form.value ? '' : kind; actionError.value = '' }
function issued(value: IssuedDTO) { plaintext.value = value.key; manual.value = false; form.value = false; name.value = ''; confirmation.value = ''; void load() }
function issue(rotate = false) {
  if (writing.value || (!rotate && !canIssue.value)) return
  if (!rotate && rows.value.some(row => row.name === name.value)) { actionError.value = 'settingsUI.keyExists'; return }
  void write(() => request<IssuedDTO>('/credentials', jsonWrite('POST', { name: rotate ? selected.value : name.value })), issued)
}
function revoke() {
  const group = rows.value.find(row => row.name === selected.value); if (!group) return
  void write(async current => {
    for (const row of group.active) {
      try { await request('/credentials/' + encodeURIComponent(row.id), jsonWrite('DELETE')) }
      catch (e) { if (!(e instanceof ApiError && e.envelope.code === 'credential_not_found')) throw e }
      if (!current()) return
    }
  }, () => { confirmation.value = ''; void load() }, () => { void load() })
}
async function copy() {
  const session = captureSession(), value = plaintext.value
  try { await navigator.clipboard.writeText(value) }
  catch {
    if (!alive || !session.isCurrent() || plaintext.value !== value || !keybox.value) return
    const range = document.createRange(); range.selectNodeContents(keybox.value)
    const selection = window.getSelection(); selection?.removeAllRanges(); selection?.addRange(range); manual.value = true
  }
}
onMounted(() => load())
</script>
<template>
  <section data-tab="keys">
    <div class="toolbar settings-actions"><button class="btn" @click="load()">{{ t('auditRefresh') }}</button><button class="btn primary" :disabled="writing" @click="begin('issue')">{{ t('settingsUI.issueKey') }}</button></div>
    <form v-if="form" class="panel form" data-form="key" @submit.prevent="issue()"><label class="field"><span>{{ t('name') }}</span><input v-model="name" name="name" autocomplete="off" :disabled="writing"></label><p v-if="actionError" class="error-text" role="alert">{{ t(actionError) }}</p><div class="toolbar"><button class="btn primary" :disabled="!canIssue" :aria-busy="writing">{{ t('settingsUI.issue') }}</button><button type="button" class="btn" :disabled="writing" @click="form = false; name = ''; actionError = ''">{{ t('cancel') }}</button></div></form>
    <div v-if="plaintext" class="panel confirm" data-key-panel><span>{{ t('settingsUI.keyOnce') }}</span><div ref="keybox" class="keybox mono">{{ plaintext }}</div><p v-if="manual" role="status">{{ t('settingsUI.manualCopy') }}</p><div class="toolbar"><button class="btn sm primary" @click="copy">{{ t('settingsUI.copy') }}</button><button class="btn sm" @click="closeKey">{{ t('settingsUI.keySaved') }}</button></div></div>
    <p v-if="error" class="error-text" role="alert">{{ t(error) }}</p><p v-if="loading" role="status">{{ t('auditLoading') }}</p>
    <div class="tbl-wrap rules"><table><thead><tr><th v-for="label in ['name', 'status', 'settingsUI.issuedAt', 'settingsUI.actions']" :key="label">{{ t(label) }}</th></tr></thead><tbody>
      <template v-for="row in rows" :key="row.name"><tr :data-row="row.name"><td class="mono strong">{{ row.name }}</td><td><ElTooltip :disabled="!row.retire_at" :content="t('settingsUI.retireAt', { time: settingTime(row.retire_at) })" :trigger="['hover','click','focus']" popper-class="rule-help-popover"><span class="pill" :class="row.status === 'normal' ? 'ok' : 'warn'" :tabindex="row.retire_at ? 0 : undefined">{{ t('settingsUI.' + row.status) }}</span></ElTooltip></td><td class="num muted" :title="row.created_at">{{ settingTime(row.created_at) }}</td><td class="r nw"><button class="btn sm" :disabled="writing" @click="begin('rotate', row.name)">{{ t('settingsUI.rotate') }}</button> <button class="btn sm" :disabled="writing" @click="begin('revoke', row.name)">{{ t('settingsUI.revoke') }}</button></td></tr>
        <tr v-if="confirmation && selected === row.name"><td colspan="4" class="wrap"><div class="confirm"><span>{{ t('settingsUI.' + (confirmation === 'rotate' ? 'rotateConfirm' : 'revokeConfirm'), { name: row.name }) }}</span><p v-if="actionError" class="error-text" role="alert">{{ t(actionError) }}</p><div class="toolbar"><button class="btn sm danger" :disabled="writing" :aria-busy="writing" @click="confirmation === 'rotate' ? issue(true) : revoke()">{{ t('settingsUI.' + confirmation) }}</button><button class="btn sm" :disabled="writing" @click="confirmation = ''; actionError = ''">{{ t('cancel') }}</button></div></div></td></tr>
      </template>
    </tbody></table></div>
  </section>
</template>
