<script setup lang="ts">
import { computed, reactive, ref, onMounted, onBeforeUnmount, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElTooltip } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import { type RuleDTO, type BatchResult, isOpenSelectTarget } from '../api/types'
import { ApiError } from '../api/client'
import { request, captureSession, state } from '../state'
import { ruleForm, ruleBody, conditionKeys } from '../rules'
import { errorField } from '../errors'
import RuleError from './RuleError.vue'
const props = defineProps<{ rule?: RuleDTO }>(), emit = defineEmits<{ close: []; saved: []; search: [id: string] }>()
const { t } = useI18n(), initial = ruleForm(props.rule), form = reactive({ ...initial })
const busy = ref(false), error = ref<unknown>(null), existing = ref(false), first = ref<HTMLInputElement>()
const trigger = document.activeElement as HTMLElement | null
let alive = true, validated: ReturnType<typeof ruleBody> | undefined
const body = computed(() => ruleBody(form, props.rule ? initial : undefined, props.rule))
const location = computed(() => errorField(error.value))
const ranges: Record<string, string> = { ttl: '0–255', dscp: '0–63', pkt_len: '0–65535', icmp_type: '0–255', icmp_code: '0–255', match_anomaly: '1–15' }
watch(form, () => { validated = undefined; existing.value = false }, { flush: 'sync' })
function close() { emit('close') }
function search(id: string) { emit('search', id); close() }
function key(event: KeyboardEvent) { if (event.key === 'Escape' && !isOpenSelectTarget(event.target)) { event.preventDefault(); close() } }
onMounted(() => { first.value?.focus(); document.addEventListener('keydown', key) })
onBeforeUnmount(() => {
  alive = false; document.removeEventListener('keydown', key)
  if (document.activeElement === document.body || first.value?.closest('.drawer')?.contains(document.activeElement)) trigger?.focus()
})
async function submit() {
  if (state.user === null || busy.value) return
  const session = captureSession(), current = () => alive && session.isCurrent()
  busy.value = true; error.value = null
  const payload = validated || body.value
  try {
    if (props.rule) await request('/rules/' + encodeURIComponent(props.rule.id), { method: 'PATCH', body: JSON.stringify(payload) })
    else {
      if (!validated) {
        const result = await request<BatchResult>('/rules/batch?validate=1', { method: 'POST', body: JSON.stringify({ items: [payload] }) })
        if (!current()) return
        const item = result.results[0]
        if (!item) throw new Error('Missing validation result')
        if (item.error) throw new ApiError(400, item.error)
        validated = payload
        if (item.existing) { existing.value = true; return }
      }
      await request('/rules', { method: 'POST', body: JSON.stringify(payload) })
    }
    if (current()) emit('saved')
  } catch (e) { if (current()) error.value = e }
  finally { if (current()) busy.value = false }
}
</script>
<template>
  <div class="scrim" @click="close" />
  <section class="drawer rule-drawer" role="dialog" aria-modal="true" :aria-label="t(rule ? 'edit' : 'createRule')">
    <div class="drawer-head"><h2>{{ t(rule ? 'edit' : 'createRule') }}</h2><button class="btn" @click="close">{{ t('close') }}</button></div>
    <form id="rule-form" class="drawer-body rule-form" @submit.prevent="submit">
      <div v-if="existing" class="rule-notice">{{ t('existingRule') }}</div>
      <RuleError v-if="error && !location" :error="error" class="drawer-error" @search="search" />
      <fieldset :disabled="busy"><legend>{{ t('target') }}</legend>
        <RuleError v-if="error && location === 'target'" :error="error" @search="search" />
        <div v-for="(name, index) in ['src_address', 'dst_address']" :key="name" class="field" :data-field="name">
          <div class="rule-label"><label :for="name">{{ t(name) }}</label><ElTooltip :content="t('ruleHints.address')" :trigger="['hover', 'click']" popper-class="rule-help-popover"><button type="button" class="rule-help" :aria-label="t(name) + ' ' + t('explanation')"><QuestionFilled aria-hidden="true" /></button></ElTooltip></div><input :placeholder="t('rulePlaceholders.address')" :id="name" :ref="el => { if (index === 0) first = el as HTMLInputElement }" v-model="form[name]">
          <RuleError v-if="error && location === name" :error="error" @search="search" />
        </div>
      </fieldset>
      <fieldset :disabled="busy"><legend>{{ t('ports') }}</legend>
        <RuleError v-if="error && location === 'ports'" :error="error" @search="search" />
        <div class="field" data-field="protocol"><div class="rule-label"><label for="protocol">{{ t('protocol') }}</label><ElTooltip :content="t('ruleHints.protocol')" :trigger="['hover', 'click']" popper-class="rule-help-popover"><button type="button" class="rule-help" :aria-label="t('protocol') + ' ' + t('explanation')"><QuestionFilled aria-hidden="true" /></button></ElTooltip></div>
          <select id="protocol" v-model="form.protocol"><option v-for="p in ['all','tcp','udp','icmp','icmpv6','igmp','gre','esp']" :key="p">{{ p }}</option></select>
          <RuleError v-if="error && location === 'protocol'" :error="error" @search="search" />
        </div>
        <div v-for="name in ['src_port','dst_port']" :key="name" class="field" :data-field="name"><label :for="name">{{ t(name) }}</label><input :id="name" v-model="form[name]" placeholder="1–65535" inputmode="numeric">
          <RuleError v-if="error && location === name" :error="error" @search="search" />
        </div>
      </fieldset>
      <fieldset :disabled="busy"><legend>{{ t('conditions') }}</legend>
        <RuleError v-if="error && location === 'conditions'" :error="error" @search="search" />
        <div v-for="name in conditionKeys" :key="name" class="field" :data-field="name"><div class="rule-label"><label :for="name">{{ name }}</label><ElTooltip :content="t('ruleHints.' + name)" :trigger="['hover', 'click']" popper-class="rule-help-popover"><button type="button" class="rule-help" :aria-label="name + ' ' + t('explanation')"><QuestionFilled aria-hidden="true" /></button></ElTooltip></div><input :id="name" v-model="form[name]" :placeholder="ranges[name]">
          <RuleError v-if="error && location === name" :error="error" @search="search" />
        </div>
      </fieldset>
      <fieldset :disabled="busy"><legend>{{ t('actionRate') }}</legend>
        <div class="field" data-field="action"><label for="action">{{ t('action') }}</label><select id="action" v-model="form.action"><option value="drop">{{ t('dropAction') }}</option><option value="rate_limit">{{ t('rateAction') }}</option></select>
          <RuleError v-if="error && location === 'action'" :error="error" @search="search" />
        </div>
        <div v-if="form.action === 'rate_limit'" class="field" data-field="rate_limit"><label for="rate_limit">pps</label><input id="rate_limit" v-model="form.rate_limit" placeholder="1–4294967295" inputmode="numeric">
          <RuleError v-if="error && location === 'rate_limit'" :error="error" @search="search" />
        </div>
      </fieldset>
      <fieldset :disabled="busy" data-field="expires_in"><legend>{{ t('expiry') }}</legend>
        <div class="toolbar"><label v-for="mode in ['permanent','duration']" :key="mode"><input v-model="form.expires_mode" type="radio" name="expiry" :value="mode"> {{ t(mode) }}</label></div>
        <div v-if="form.expires_mode === 'duration'" class="field"><label for="expires_in">{{ t('durationMinutes') }}</label><input id="expires_in" v-model="form.expires_in" :placeholder="t('rulePlaceholders.duration')" inputmode="numeric"></div>
        <RuleError v-if="error && location === 'expires_in'" :error="error" @search="search" />
      </fieldset>
      <fieldset :disabled="busy" data-field="comment"><legend>{{ t('comment') }}</legend><textarea id="comment" v-model="form.comment" :aria-label="t('comment')" rows="3" />
        <RuleError v-if="error && location === 'comment'" :error="error" @search="search" />
      </fieldset>
      <label v-if="!rule" class="rule-enabled" data-field="enabled"><input v-model="form.enabled" type="checkbox" true-value="true" false-value="false" :disabled="busy"> {{ t('enabled') }}
        <RuleError v-if="error && location === 'enabled'" :error="error" @search="search" />
      </label>
    </form>
    <div class="drawer-foot"><button class="btn primary" form="rule-form" type="submit" :aria-busy="busy" :disabled="busy || (!!rule && !Object.keys(body).length)">{{ t(existing ? 'submitAnyway' : 'submit') }}</button></div>
  </section>
</template>
