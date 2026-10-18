<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElTooltip } from 'element-plus'
import { request, state } from '../../state'
import type { UserDTO } from '../../api/types'
import { openPassword } from '../../password'
import { jsonWrite, settingsError, settingTime, useSettingsRequests } from '../../settings'
const { t } = useI18n()
const { data: rows, loading, error, writing, actionError, load, write } = useSettingsRequests<UserDTO[]>('/users', [], e => settingsError('users', e))
const form = ref(''), selected = ref<UserDTO>(), confirmation = ref<'role' | 'delete' | ''>(''), username = ref(''), role = ref('operator'), password = ref(''), again = ref(''), resetName = ref('')
const canSave = computed(() => !!password.value && !!again.value && (form.value === 'reset' || !!username.value))
function close() { form.value = ''; selected.value = undefined; confirmation.value = ''; username.value = ''; role.value = 'operator'; password.value = ''; again.value = ''; actionError.value = '' }
function begin(kind: string, row?: UserDTO) {
  resetName.value = ''; close()
  if (kind === 'password' && row?.username === state.user?.name) { openPassword(); return }
  selected.value = row
  if (kind === 'role' || kind === 'delete') confirmation.value = kind
  else form.value = row ? 'reset' : 'add'
}
function refresh() { resetName.value = ''; void load() }
function save() {
  if (!canSave.value || writing.value) return
  resetName.value = ''
  if (password.value !== again.value) { actionError.value = 'passwordMismatch'; return }
  const target = selected.value?.username
  void write(() => request(target ? '/users/' + encodeURIComponent(target) + '/password' : '/users', jsonWrite(target ? 'PUT' : 'POST', target ? { password: password.value } : { username: username.value, password: password.value, role: role.value })), () => {
    close(); void load(() => { if (target) resetName.value = target })
  })
}
function confirm() {
  const row = selected.value; if (!row) return
  const change = confirmation.value === 'role'
  void write(() => request('/users/' + encodeURIComponent(row.username) + (change ? '/role' : ''), jsonWrite(change ? 'PUT' : 'DELETE', change ? { role: row.role === 'admin' ? 'operator' : 'admin' } : undefined)), () => { close(); void load() })
}
onMounted(() => load())
</script>
<template>
  <section data-tab="users" @input="resetName = ''">
    <div class="toolbar settings-actions"><button class="btn" @click="refresh">{{ t('auditRefresh') }}</button><button class="btn primary" :disabled="writing" @click="begin('add')">{{ t('settingsUI.addUser') }}</button></div>
    <form v-if="form === 'add'" class="panel form" data-form="user" @submit.prevent="save">
      <label class="field"><span>{{ t('username') }}</span><input v-model="username" name="username" autocomplete="off" :disabled="writing"></label>
      <label class="field"><span>{{ t('settingsUI.role') }}</span><select v-model="role" name="role" :disabled="writing"><option value="operator">{{ t('settingsUI.operator') }}</option><option value="admin">{{ t('settingsUI.admin') }}</option></select></label>
      <label class="field"><span>{{ t('password') }}</span><input v-model="password" name="password" type="password" autocomplete="new-password" :disabled="writing"></label>
      <label class="field"><span>{{ t('passwordAgain') }}</span><input v-model="again" name="again" type="password" autocomplete="new-password" :disabled="writing"></label>
      <p v-if="actionError" class="error-text" role="alert">{{ t(actionError) }}</p><div class="toolbar"><button class="btn primary" :disabled="!canSave || writing" :aria-busy="writing">{{ t('settingsUI.save') }}</button><button type="button" class="btn" :disabled="writing" @click="close">{{ t('cancel') }}</button></div>
    </form>
    <p v-if="error" class="error-text" role="alert">{{ t(error) }}</p><p v-if="loading" role="status">{{ t('auditLoading') }}</p>
    <div class="tbl-wrap rules"><table><thead><tr><th>{{ t('username') }}</th><th>{{ t('settingsUI.role') }} <ElTooltip :content="t('settingsUI.roleHelp')" :trigger="['hover','click','focus']" popper-class="rule-help-popover"><span class="tip" tabindex="0" role="img" :aria-label="t('settingsUI.role')" :data-tip="t('settingsUI.roleHelp')">?</span></ElTooltip></th><th>{{ t('settingsUI.createdBy') }}</th><th>{{ t('settingsUI.passwordAt') }}</th><th>{{ t('settingsUI.actions') }}</th></tr></thead><tbody>
      <template v-for="row in rows" :key="row.username">
        <tr :data-row="row.username"><td class="mono strong">{{ row.username }}</td><td><span class="pill" :class="{ ok: row.role === 'admin' }">{{ t('settingsUI.' + row.role) }}</span></td><td class="mono muted">{{ row.created_by || '—' }}</td><td class="num muted" :title="row.password_changed_at">{{ settingTime(row.password_changed_at) }}</td><td class="r nw">
          <button class="btn sm" :disabled="writing" @click="begin('password', row)">{{ t('settingsUI.changePassword') }}</button>
          <template v-if="row.username !== state.user?.name"> <button class="btn sm" :disabled="writing" @click="begin('role', row)">{{ t('settingsUI.changeRole') }}</button> <button class="btn sm" :disabled="writing" @click="begin('delete', row)">{{ t('delete') }}</button></template>
        </td></tr>
        <tr v-if="resetName === row.username"><td colspan="5" class="wrap" role="status">{{ t('settingsUI.resetDone') }}</td></tr>
        <tr v-if="form === 'reset' && selected?.username === row.username"><td colspan="5" class="wrap"><form class="panel form" data-form="reset" @submit.prevent="save">
          <label class="field"><span>{{ t('passwordNew') }}</span><input v-model="password" name="password" type="password" autocomplete="new-password" :disabled="writing"></label>
          <label class="field"><span>{{ t('passwordAgain') }}</span><input v-model="again" name="again" type="password" autocomplete="new-password" :disabled="writing"></label>
          <p v-if="actionError" class="error-text" role="alert">{{ t(actionError) }}</p><div class="toolbar"><button class="btn primary" :disabled="!canSave || writing" :aria-busy="writing">{{ t('settingsUI.save') }}</button><button type="button" class="btn" :disabled="writing" @click="close">{{ t('cancel') }}</button></div>
        </form></td></tr>
        <tr v-if="confirmation && selected?.username === row.username"><td colspan="5" class="wrap"><div class="confirm"><span>{{ t('settingsUI.' + (confirmation === 'role' ? 'roleConfirm' : 'userDeleteConfirm'), { name: row.username, role: t('settingsUI.' + (row.role === 'admin' ? 'operator' : 'admin')) }) }}</span><p v-if="actionError" class="error-text" role="alert">{{ t(actionError) }}</p><div class="toolbar"><button class="btn sm danger" :disabled="writing" :aria-busy="writing" @click="confirm">{{ t(confirmation === 'role' ? 'settingsUI.changeRole' : 'delete') }}</button><button class="btn sm" :disabled="writing" @click="close">{{ t('cancel') }}</button></div></div></td></tr>
      </template>
    </tbody></table></div>
  </section>
</template>
