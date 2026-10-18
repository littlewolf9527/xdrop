<script setup lang="ts">
import { reactive, ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElTooltip, ElDropdown, ElDropdownMenu, ElDropdownItem } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import { request, captureSession, state } from '../state'
import { trailingThrottle } from '../api/events'
import type { RuleDTO, TopAll, RuleEnabled } from '../api/types'
import { listState, ruleList, searchError, target, direction, grouped, ruleRate, remaining, conditionKeys, exportRules, ExportExpired, localISO } from '../rules'
import type { RuleQuery } from '../rules'
import { metric } from '../metrics'
import RuleDrawer from '../components/RuleDrawer.vue'
import ImportDrawer from '../components/ImportDrawer.vue'
import RuleError from '../components/RuleError.vue'
const { t } = useI18n(), list = reactive(listState()), q = ref(''), filter = ref<RuleQuery['state']>('')
const confirmation = ref(''), drawer = ref(false), editing = ref<RuleDTO>(), top = ref<TopAll | null>(null)
const busy = reactive<Record<string, boolean>>({}), rowErrors = reactive<Record<string, unknown>>({})
const importing = ref(false)
const exporting = ref(false), exported = ref(0), exportError = ref<unknown>(null)
let alive = true, trafficSerial = 0, searchTimer: ReturnType<typeof setTimeout> | undefined
const model = ruleList(list, path => request(path), captureSession, () => { confirmation.value = '' }, () => refresh())
const groups = computed(() => grouped(list.rows)), filters = ['', 'drop', 'rate_limit', 'disabled'] as const
const group = (r: RuleDTO) => groups.value.get(r.group_key)!
function query() { clearTimeout(searchTimer); if (state.user === null) return; void model.query({ q: q.value, state: filter.value }) }
function search(id: string) { q.value = id; filter.value = ''; query() }
function input() { clearTimeout(searchTimer); searchTimer = setTimeout(query, 300) }
function choose(value: RuleQuery['state']) { filter.value = value; query() }
function open(rule?: RuleDTO) {
  if (rule) document.getElementById('rule-menu-' + rule.id)?.focus()
  editing.value = rule ? { ...rule } : undefined; drawer.value = true
}
function confirm(rule: RuleDTO) { confirmation.value = rule.id }
function saved() { drawer.value = false; void model.written() }
async function toggle(rule: RuleDTO) {
  if (state.user === null) return
  const session = captureSession(), id = rule.id
  busy[id] = true; delete rowErrors[id]
  try {
    const result = await request<RuleEnabled>('/rules/' + id + '/enabled', { method: 'PUT', body: JSON.stringify({ enabled: !rule.enabled }) })
    if (alive && session.isCurrent()) { const row = list.rows.find(r => r.id === id); if (row) row.enabled = result.enabled; void model.written() }
  } catch (error) { if (alive && session.isCurrent()) rowErrors[id] = error }
  finally { if (alive && session.isCurrent()) busy[id] = false }
}
async function remove(rule: RuleDTO) {
  if (state.user === null) return
  const session = captureSession(), id = rule.id
  busy[id] = true; delete rowErrors[id]
  try {
    await request('/rules/' + id, { method: 'DELETE' })
    if (alive && session.isCurrent()) { confirmation.value = ''; void model.written() }
  } catch (error) { if (alive && session.isCurrent()) rowErrors[id] = error }
  finally { if (alive && session.isCurrent()) busy[id] = false }
}
async function rates() {
  if (state.user === null) return
  const session = captureSession(), serial = ++trafficSerial
  try {
    const result = await request<TopAll>('/traffic/top?n=all')
    if (alive && session.isCurrent() && serial === trafficSerial) top.value = result
  } catch { /* Missing measurements remain unknown. */ }
}
const refresh = trailingThrottle(() => { if (state.user !== null) void model.refresh() }, 2000), traffic = trailingThrottle(() => { if (state.user !== null) void rates() }, 5000)
watch(() => list.rows, rows => { if (!rows.some(rule => rule.id === confirmation.value)) confirmation.value = '' })
watch(() => state.rules, () => { if (state.user !== null) refresh() })
watch(() => state.top, () => { if (state.user !== null) traffic() })
onMounted(() => { query(); traffic() })
onBeforeUnmount(() => { alive = false; model.stop(); refresh.cancel(); traffic.cancel(); clearTimeout(searchTimer) })
async function download() {
  if (state.user === null) return
  const session = captureSession(), current = () => alive && session.isCurrent()
  exporting.value = true; exported.value = 0; exportError.value = null
  try {
    const text = await exportRules({ ...list.applied }, path => request(path), current, n => { if (current()) exported.value = n })
    if (!current()) return
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' })), link = document.createElement('a')
    link.href = url; link.download = 'xdrop-rules-' + localISO(new Date()).slice(0, 19).replace(/[-:]/g, '').replace('T', '-') + '.txt'
    link.click(); URL.revokeObjectURL(url)
  } catch (error) { if (current()) exportError.value = error }
  finally { if (current()) exporting.value = false }
}
</script>
<template>
  <section class="page rules-page">
    <div class="page-head"><h1>{{ t('blocklist') }}</h1><div class="toolbar">
      <button class="btn" :disabled="exporting" :aria-busy="exporting" @click="download">{{ t('export') }}<span v-if="exporting"> {{ exported }}</span></button>
      <button class="btn" @click="importing = true">{{ t('importTitle') }}</button>
      <button class="btn primary" @click="open()">{{ t('createRule') }}</button>
    </div></div>
    <div class="toolbar"><input v-model="q" class="search" :placeholder="t('searchPlaceholder')" :aria-label="t('searchRules')" @input="input" @keydown.enter.prevent="query">
      <div class="chips" role="group" :aria-label="t('filter')"><button v-for="value in filters" :key="value" class="chip" :aria-pressed="filter === value" @click="choose(value)">{{ t(value === '' ? 'all' : value === 'rate_limit' ? 'rateAction' : value === 'drop' ? 'dropAction' : 'disabled') }} <span class="num">{{ list.counts[value || 'all'] }}</span></button></div>
    </div>
    <p v-if="list.error && searchError(list.error)" class="error-text" role="alert">{{ t('errors.searchInvalid') }}</p>
    <RuleError v-else-if="list.error" :error="list.error" @search="search" />
    <p v-if="exportError instanceof ExportExpired" class="error-text" role="alert">{{ t('errors.exportExpired') }}</p>
    <RuleError v-else-if="exportError" :error="exportError" @search="search" />
    <div class="tbl-wrap rules"><table><thead><tr>
      <th>{{ t('target') }}</th><th>{{ t('ports') }}</th><th>{{ t('conditions') }}</th><th>{{ t('action') }}</th>
      <th class="r">{{ t('droppedPps') }} <ElTooltip :content="t('rateHelp') + (top?.incomplete ? ' ' + t('rateIncomplete') : '')" :trigger="['hover', 'click']" popper-class="rule-help-popover"><button type="button" class="rule-help" :aria-label="t('droppedPps') + ' ' + t('explanation')"><QuestionFilled aria-hidden="true" /></button></ElTooltip></th><th class="r">{{ t('droppedBps') }}</th>
      <th>{{ t('origin') }}</th><th>{{ t('expiry') }}</th><th>{{ t('enabled') }}</th><th />
    </tr></thead><tbody><template v-for="rule in list.rows" :key="rule.id">
      <tr :data-rule-id="rule.id" :class="{ off: !rule.enabled, 'in-grp': group(rule).count >= 2, 'grp-first': group(rule).first === rule.id }">
        <td :title="rule.id + ' · #' + rule.logical_id + (rule.comment ? ' · ' + rule.comment : '')"><div class="tgt"><span class="mono strong">{{ target(rule) }}</span><span class="muted">{{ t(direction(rule)) }}</span><span v-if="group(rule).count >= 2 && group(rule).first === rule.id" class="grp" :title="t('groupHelp')">{{ t('group', { n: group(rule).count }) }}</span></div></td>
        <td><span class="mono">{{ rule.protocol }}</span><template v-if="rule.src_port"> · {{ t('src_port') }} {{ rule.src_port }}</template><template v-if="rule.dst_port"> · {{ t('dst_port') }} {{ rule.dst_port }}</template></td>
        <td class="wrap"><span v-if="(rule.dst_ip || rule.dst_cidr) && (rule.src_ip || rule.src_cidr)" class="cond">{{ t('source') }} {{ rule.src_ip || rule.src_cidr }}</span><template v-for="key in conditionKeys" :key="key"><span v-if="rule[key]" class="cond">{{ key }}={{ rule[key] }}</span></template><span v-if="!conditionKeys.some(key => rule[key]) && !((rule.dst_ip || rule.dst_cidr) && (rule.src_ip || rule.src_cidr))" class="muted">—</span></td>
        <td><span class="tag" :class="rule.action === 'drop' ? 'drop' : 'rl'">{{ rule.action === 'drop' ? t('dropAction') : t('rateAction') + ' ' + rule.rate_limit + ' pps' }}</span></td>
        <td class="r num c-drop">{{ ruleRate(rule, top) ? metric(ruleRate(rule, top)![0]) : '—' }}</td><td class="r num c-drop b">{{ ruleRate(rule, top) ? metric(ruleRate(rule, top)![1]) : '—' }}</td>
        <td :title="rule.created_by"><span class="mono">{{ rule.created_by.replace(/^(user|cred):/, '') }}</span></td><td :title="rule.expires_at ? new Date(rule.expires_at).toLocaleString() : undefined">{{ rule.expires_at ? remaining(rule, state.now) : t('permanent') }}</td>
        <td><button class="tag rule-status" role="switch" :aria-checked="rule.enabled" :aria-label="t('enabled')" :disabled="busy[rule.id]" :aria-busy="busy[rule.id]" :title="t(rule.enabled ? 'clickDisable' : 'clickEnable')" @click="toggle(rule)">{{ busy[rule.id] ? '…' : t(rule.enabled ? 'enabled' : 'inactive') }}</button></td>
        <td class="r"><ElDropdown :id="'rule-menu-' + rule.id" trigger="click" placement="bottom-end" popper-class="row-menu" :show-arrow="false">
          <button class="row-menu-trigger" :aria-label="t('more')">⋯</button>
          <template #dropdown><ElDropdownMenu><ElDropdownItem :disabled="busy[rule.id]" @click="open(rule)">{{ t('edit') }}</ElDropdownItem><ElDropdownItem :disabled="busy[rule.id]" @click="confirm(rule)">{{ t('delete') }}</ElDropdownItem></ElDropdownMenu></template>
        </ElDropdown></td>
      </tr>
      <tr v-if="rowErrors[rule.id]"><td colspan="10"><RuleError :error="rowErrors[rule.id]" @search="search" /></td></tr>
      <tr v-if="confirmation === rule.id"><td colspan="10" class="wrap"><div class="confirm"><strong>{{ t('deleteQuestion', { target: target(rule) }) }}</strong><p>{{ t('deleteWarning') }}</p><div class="toolbar"><button class="btn danger" :disabled="busy[rule.id]" @click="remove(rule)">{{ t('delete') }}</button><button class="btn" :disabled="busy[rule.id]" @click="confirmation = ''">{{ t('cancel') }}</button></div></div></td></tr>
    </template></tbody></table></div>
    <button v-if="list.next !== null" class="btn load-more" :title="t('loadedHelp', { loaded: list.rows.length, total: list.counts[list.applied.state || 'all'] })" :disabled="list.busy" @click="state.user !== null && model.more()">{{ t('loadMore') }}</button>
    <ImportDrawer v-if="importing" @close="importing = false" @search="search" />
    <RuleDrawer v-if="drawer" :key="editing?.id || 'new'" :rule="editing" @close="drawer = false" @saved="saved" @search="search" />
  </section>
</template>
