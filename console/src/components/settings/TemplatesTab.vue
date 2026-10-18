<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { request } from '../../state'
import { ApiError } from '../../api/client'
import type { TemplateDTO } from '../../api/types'
import { jsonWrite, settingsError, settingTime, templateCheck, templateCount, useSettingsRequests } from '../../settings'
const { t } = useI18n()
const { data: rows, loading, error, writing, actionError, load, write } = useSettingsRequests<TemplateDTO[]>('/templates', [], e => settingsError('templates', e))
const form = ref(false), selected = ref<TemplateDTO>(), confirmation = ref<TemplateDTO>(), name = ref(''), body = ref('')
const precheck = computed(() => templateCheck(body.value)), canSave = computed(() => name.value !== '' && precheck.value.length === 0)
function close() { form.value = false; selected.value = undefined; confirmation.value = undefined; name.value = ''; body.value = ''; actionError.value = '' }
function edit(row?: TemplateDTO) { close(); form.value = true; selected.value = row; name.value = row?.name || ''; body.value = row?.body || '' }
function appendExample() { body.value += (body.value && !body.value.endsWith('\n') ? '\n' : '') + t('settingsUI.exampleRules') }
function failure(e: unknown) { if (e instanceof ApiError && e.envelope.code === 'not_found') void load() }
function save() {
  if (!canSave.value || writing.value) return
  void write(() => request(selected.value ? '/templates/' + encodeURIComponent(selected.value.id) : '/templates', jsonWrite(selected.value ? 'PUT' : 'POST', { name: name.value, body: body.value })), () => { close(); void load() }, failure)
}
function remove() {
  const row = confirmation.value; if (!row) return
  void write(() => request('/templates/' + encodeURIComponent(row.id), jsonWrite('DELETE')), () => { close(); void load() }, failure)
}
onMounted(() => load())
</script>
<template>
  <section data-tab="templates">
    <div class="toolbar settings-actions"><button class="btn" @click="load()">{{ t('auditRefresh') }}</button><button class="btn primary" :disabled="writing" @click="edit()">{{ t('settingsUI.addTemplate') }}</button></div>
    <form v-if="form" class="panel form" data-form="template" @submit.prevent="save"><label class="field"><span>{{ t('name') }}</span><input v-model="name" name="name" :disabled="writing"></label><label class="field"><span>{{ t('settingsUI.content') }}</span><textarea v-model="body" name="body" class="mono" spellcheck="false" :disabled="writing"></textarea></label>
      <details class="template-guide"><summary>{{ t('settingsUI.writingGuide') }}</summary>
        <p>{{ t('settingsUI.writingIntro') }}</p><p>{{ t('settingsUI.writingTarget') }}</p>
        <table><tbody><tr v-for="[field, help] in [['protocol', 'Protocol'], ['src_port', 'Port'], ['dst_port', 'Port'], ['tcp_flags', 'Flags'], ['action', 'Action'], ['rate_limit', 'Rate'], ['expires_in', 'Expiry']]" :key="field"><th scope="row"><code>{{ field }}</code></th><td>{{ t('settingsUI.writing' + help) }}</td></tr></tbody></table>
        <pre>{{ t('settingsUI.exampleRules') }}</pre><button type="button" class="btn" :disabled="writing" @click="appendExample">{{ t('settingsUI.appendExample') }}</button>
      </details>
      <p v-for="item in precheck" :key="item.no" class="error-text" role="alert">{{ t('settingsUI.' + item.key, { n: item.no }) }}</p><p v-if="actionError" class="error-text" role="alert">{{ t(actionError) }}</p><div class="toolbar"><button class="btn primary" :disabled="!canSave || writing" :aria-busy="writing">{{ t('settingsUI.save') }}</button><button type="button" class="btn" :disabled="writing" @click="close">{{ t('cancel') }}</button></div></form>
    <p v-if="error" class="error-text" role="alert">{{ t(error) }}</p><p v-if="loading" role="status">{{ t('auditLoading') }}</p>
    <div class="tbl-wrap rules"><table><thead><tr><th v-for="label in ['name', 'settingsUI.ruleCount', 'settingsUI.updated', 'settingsUI.actions']" :key="label">{{ t(label) }}</th></tr></thead><tbody>
      <template v-for="row in rows" :key="row.id"><tr :data-row="row.id"><td class="strong">{{ row.name }}</td><td class="num">{{ templateCount(row.body) }}</td><td class="num muted" :title="row.updated_at"><span :title="row.updated_by">{{ settingTime(row.updated_at) }}</span></td><td class="r nw"><button class="btn sm" :disabled="writing" @click="edit(row)">{{ t('edit') }}</button> <button class="btn sm" :disabled="writing" @click="close(); confirmation = row">{{ t('delete') }}</button></td></tr>
        <tr v-if="confirmation?.id === row.id"><td colspan="4" class="wrap"><div class="confirm"><span>{{ t('settingsUI.templateDeleteConfirm', { name: row.name }) }}</span><p v-if="actionError" class="error-text" role="alert">{{ t(actionError) }}</p><div class="toolbar"><button class="btn sm danger" :disabled="writing" :aria-busy="writing" @click="remove">{{ t('delete') }}</button><button class="btn sm" :disabled="writing" @click="close">{{ t('cancel') }}</button></div></div></td></tr>
      </template>
    </tbody></table></div><p v-if="!loading && !error && !rows.length" class="muted">{{ t('importEmpty') }}</p>
  </section>
</template>
