<script setup lang="ts">
import { reactive, ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElTooltip } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import { request, captureSession, state } from '../state'
import { type WhitelistDTO, isOpenSelectTarget } from '../api/types'
import { whitelistError } from '../errors'
const emit = defineEmits<{ close: []; saved: [] }>(), { t } = useI18n()
const form = reactive({ src_ip: '', dst_ip: '', src_port: '', dst_port: '', protocol: 'all', comment: '' })
const busy = ref(false), existing = ref(false), error = ref<unknown>(null), first = ref<HTMLInputElement>()
const failure = computed(() => whitelistError(error.value)), trigger = document.activeElement as HTMLElement | null
let alive = true
function close() { emit('close') }
function key(e: KeyboardEvent) { if (e.key === 'Escape' && !isOpenSelectTarget(e.target)) { e.preventDefault(); close() } }
onMounted(() => { first.value?.focus(); document.addEventListener('keydown', key) })
onBeforeUnmount(() => {
  alive = false; document.removeEventListener('keydown', key)
  if (document.activeElement === document.body || document.activeElement?.closest('.whitelist-drawer')) trigger?.focus()
})
async function submit() {
  if (busy.value || state.user === null) return
  const session = captureSession(), current = () => alive && session.isCurrent()
  const body: Record<string, string | number> = { src_ip: form.src_ip.trim(), dst_ip: form.dst_ip.trim(), protocol: form.protocol, comment: form.comment.trim() }
  for (const key of ['src_port','dst_port'] as const) {
    const value = form[key].trim()
    body[key] = !value ? 0 : /^[0-9]+$/.test(value) && Number.isSafeInteger(Number(value)) ? Number(value) : value
  }
  busy.value = true; error.value = null; existing.value = false
  try {
    const result = await request<WhitelistDTO & { existing: boolean }>('/whitelist', { method: 'POST', body: JSON.stringify(body) })
    if (!current()) return
    if (result.existing) existing.value = true
    else emit('saved')
  } catch (e) { if (current()) error.value = e }
  finally { if (current()) busy.value = false }
}
</script>
<template>
  <div class="scrim" @click="close" />
  <section class="drawer whitelist-drawer" role="dialog" aria-modal="true" :aria-label="t('whitelistNew')">
    <div class="drawer-head"><h2>{{ t('whitelistNew') }}</h2><button class="btn" @click="close">{{ t('close') }}</button></div>
    <form id="whitelist-form" class="drawer-body rule-form" @submit.prevent="submit">
      <div v-if="existing" class="rule-notice">{{ t('whitelistExisting') }} <button type="button" class="btn" @click="close">{{ t('close') }}</button></div>
      <p v-if="error && !failure.field" class="error-text drawer-error" role="alert">{{ failure.text }}</p>
      <fieldset :disabled="busy" data-field="ip">
        <div v-for="(name, i) in ['src_ip','dst_ip'] as const" :key="name" class="field" :data-field="name"><div class="rule-label"><label :for="'wl-' + name">{{ t(name === 'src_ip' ? 'whitelistSource' : 'whitelistDestination') }}</label><ElTooltip :content="t('whitelistAddressHelp')" :trigger="['hover','click']" popper-class="rule-help-popover"><button type="button" class="rule-help" :aria-label="t('explanation')"><QuestionFilled /></button></ElTooltip></div><input :id="'wl-' + name" :ref="el => { if (i === 0) first = el as HTMLInputElement }" v-model="form[name]" placeholder="192.0.2.1"></div>
        <p v-if="error && ['ip','tuple'].includes(failure.field)" class="error-text" role="alert">{{ failure.text }}</p>
      </fieldset>
      <fieldset :disabled="busy" data-field="port">
        <div class="field" data-field="protocol"><label for="wl-protocol">{{ t('protocol') }}</label><select id="wl-protocol" v-model="form.protocol"><option v-for="p in ['all','tcp','udp','icmp','icmpv6','igmp','gre','esp']" :key="p">{{ p }}</option></select><p v-if="error && failure.field === 'protocol'" class="error-text" role="alert">{{ failure.text }}</p></div>
        <div v-for="name in ['src_port','dst_port'] as const" :key="name" class="field" :data-field="name"><label :for="'wl-' + name">{{ t(name) }}</label><input :id="'wl-' + name" v-model="form[name]" placeholder="0-65535" inputmode="numeric"></div>
        <p v-if="error && failure.field === 'port'" class="error-text" role="alert">{{ failure.text }}</p>
      </fieldset>
      <fieldset :disabled="busy"><legend>{{ t('comment') }}</legend><textarea id="wl-comment" v-model="form.comment" :aria-label="t('comment')" rows="3" /></fieldset>
    </form>
    <div class="drawer-foot"><button class="btn primary" form="whitelist-form" type="submit" :disabled="busy" :aria-busy="busy">{{ t('submit') }}</button></div>
  </section>
</template>
<style scoped>
.whitelist-drawer { width: min(520px, 100vw); }
.whitelist-drawer .drawer-body { grid-template-columns: minmax(0, 1fr); }
.whitelist-drawer .btn { min-height: 28px; white-space: nowrap; }
.whitelist-drawer .field .error-text { grid-column: 2; }
.whitelist-drawer .field { grid-template-columns: 128px minmax(0, 1fr); }
</style>
