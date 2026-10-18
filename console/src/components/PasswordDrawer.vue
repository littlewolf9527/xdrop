<script setup lang="ts">
import { reactive, ref, onMounted, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { request, captureSession, expire, state } from '../state'
import { passwordOpen } from '../password'
import { ApiError } from '../api/client'
import { genericKey } from '../errors'
const { t } = useI18n()
const form = reactive({ current_password: '', password: '', confirmation: '' })
const busy = ref(false), error = ref(''), field = ref(''), first = ref<HTMLInputElement>()
const trigger = document.activeElement as HTMLElement | null
let alive = true
function close() { passwordOpen.value = false }
function key(e: KeyboardEvent) { if (e.key === 'Escape') { e.preventDefault(); close() } }
onMounted(() => { first.value?.focus(); document.addEventListener('keydown', key) })
onBeforeUnmount(() => {
  alive = false; document.removeEventListener('keydown', key)
  form.current_password = ''; form.password = ''; form.confirmation = ''
  if (document.activeElement === document.body || document.activeElement?.closest('.password-drawer')) trigger?.focus()
})
async function submit() {
  if (busy.value || state.user === null || !form.current_password || !form.password || !form.confirmation) return
  error.value = ''; field.value = ''
  if (form.password !== form.confirmation) { field.value = 'confirmation'; error.value = 'passwordMismatch'; return }
  const session = captureSession(), current = () => alive && session.isCurrent()
  busy.value = true
  try {
    await request('/auth/me/password', { method: 'PUT', body: JSON.stringify({ current_password: form.current_password, password: form.password }) })
    if (!current()) return
    close(); expire(); state.notice = 'passwordChanged'
  } catch (e) {
    if (!current()) return
    if (e instanceof ApiError && ((e.status === 401 && e.envelope.code === 'invalid_credentials') || (e.status === 429 && e.envelope.code === 'login_throttled'))) {
      field.value = 'current_password'; error.value = 'passwordCurrentWrong'
    } else if (e instanceof ApiError && e.status === 400 && e.envelope.code === 'invalid_field' && e.envelope.field === 'password') {
      field.value = 'password'; error.value = 'passwordLength'
    } else error.value = genericKey(e)
  } finally { if (current()) busy.value = false }
}
</script>
<template>
  <div class="scrim" @click="close" />
  <section class="drawer password-drawer" role="dialog" aria-modal="true" :aria-label="t('passwordChange')">
    <div class="drawer-head"><h2>{{ t('passwordChange') }}</h2><button class="btn" @click="close">{{ t('close') }}</button></div>
    <form id="password-form" class="drawer-body rule-form" @submit.prevent="submit">
      <p v-if="error && !field" class="error-text drawer-error" role="alert">{{ t(error) }}</p>
      <div v-for="(name, i) in ['current_password', 'password', 'confirmation'] as const" :key="name" class="field" :data-field="name">
        <label :for="'own-' + name">{{ t(['passwordCurrent', 'passwordNew', 'passwordAgain'][i]!) }}</label>
        <input :id="'own-' + name" :ref="el => { if (i === 0) first = el as HTMLInputElement }" v-model="form[name]" type="password" :autocomplete="i === 0 ? 'current-password' : 'new-password'" :disabled="busy">
        <p v-if="error && field === name" class="error-text" role="alert">{{ t(error) }}</p>
      </div>
    </form>
    <div class="drawer-foot"><button class="btn primary" form="password-form" type="submit" :disabled="busy || !form.current_password || !form.password || !form.confirmation" :aria-busy="busy">{{ t('passwordModify') }}</button></div>
  </section>
</template>
<style scoped>
.password-drawer { width: min(520px, 100vw); }
.password-drawer .drawer-body { grid-template-columns: minmax(0, 1fr); }
.password-drawer .btn { min-height: 28px; white-space: nowrap; }
.password-drawer .field { grid-template-columns: 128px minmax(0, 1fr); }
.password-drawer .field .error-text { grid-column: 2; margin: 0; overflow-wrap: anywhere; }
</style>
