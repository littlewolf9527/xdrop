<script setup lang="ts">
import { computed, ref, onMounted, onBeforeUnmount, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElTooltip } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import { request, captureSession, state } from '../state'
import { type TemplateDTO, type BatchResult, isOpenSelectTarget } from '../api/types'
import { ApiError } from '../api/client'
import { conditionKeys } from '../rules'
import { importKeys, parseImport, expandTargets, splitLines, applyResults, sendable, failedText, receipt, rejectedRows } from '../import'
import type { ImportLine } from '../import'
import RuleError from './RuleError.vue'
const emit = defineEmits<{ close: []; search: [id: string] }>(), { t } = useI18n()
const tab = ref('a'), textA = ref(''), targets = ref(''), templateID = ref(''), templates = ref<TemplateDTO[]>([])
const rows = ref<ImportLine[]>([]), checking = ref(false), submitting = ref(false), ready = ref(false), submitted = ref(false)
const error = ref<unknown>(null), progress = ref(0), first = ref<HTMLTextAreaElement>()
const trigger = document.activeElement as HTMLElement | null
let alive = true, sequence = 0, timer: ReturnType<typeof setTimeout> | undefined
const template = computed(() => templates.value.find(v => v.id === templateID.value))
const expanded = computed(() => expandTargets(targets.value, template.value?.body || ''))
const input = computed(() => tab.value === 'a' ? parseImport(textA.value) : expanded.value.rows)
const count = computed(() => sendable(rows.value).length)
const canSubmit = computed(() => ready.value && !checking.value && !submitting.value && !submitted.value && count.value > 0)
const failed = computed(() => failedText(rows.value))
const unknown = computed(() => rows.value.some(r => r.status === 'unknown'))
const replace = (updated: ImportLine[]) => { const byNo = new Map(updated.map(r => [r.no, r])); rows.value = rows.value.map(r => byNo.get(r.no) || r) }
function invalidate() {
  sequence++; clearTimeout(timer); ready.value = false; checking.value = false; submitted.value = false
  error.value = null; progress.value = 0; rows.value = input.value
  timer = setTimeout(() => void precheck(), 600)
}
watch(input, invalidate, { flush: 'sync' })
async function precheck() {
  clearTimeout(timer)
  if (state.user === null || submitting.value) return
  const serial = ++sequence, session = captureSession()
  const current = () => alive && serial === sequence && session.isCurrent()
  rows.value = input.value; checking.value = true; ready.value = false; submitted.value = false; error.value = null
  const chunks = splitLines(rows.value)
  let trusted = true
  for (const chunk of chunks) {
    try {
      const result = await request<BatchResult>('/rules/batch?validate=1', { method: 'POST', body: JSON.stringify({ items: chunk.map(r => r.patch) }) })
      if (!current()) return
      const updated = applyResults(chunk, result, 'validate')
      if (updated.some(r => r.status === 'unknown')) trusted = false
      replace(updated)
    } catch (e) {
      if (!current()) return
      trusted = false
      if (e instanceof ApiError && e.status === 400) replace(rejectedRows(chunk, e))
      else { error.value = e; break }
    }
  }
  if (current()) { checking.value = false; ready.value = trusted }
}
async function submit() {
  if (!canSubmit.value || state.user === null) return
  clearTimeout(timer)
  const serial = sequence, session = captureSession(), current = () => alive && serial === sequence && session.isCurrent()
  const chunks = splitLines(rows.value).map(chunk => ({ original: chunk, sent: sendable(chunk) }))
  const maps = new Map<number, number[]>()
  for (const chunk of chunks) for (const row of chunk.sent) maps.set(row.no, chunk.sent.map(r => r.no))
  sentMaps = maps
  submitted.value = true; submitting.value = true; ready.value = false; rows.value = receipt(rows.value)
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i]!
    if (chunk.sent.length) {
      try {
        const result = await request<BatchResult>('/rules/batch', { method: 'POST', body: JSON.stringify({ items: chunk.sent.map(r => r.patch) }) })
        if (!current()) return
        replace(applyResults(chunk.sent, result, 'submit'))
      } catch (e) {
        if (!current()) return
        if (e instanceof ApiError && e.status === 400) replace(rejectedRows(chunk.sent, e))
        else {
          replace(chunk.sent.map(r => ({ ...r, status: 'unknown' })))
          for (const later of chunks.slice(i + 1)) replace(later.sent.map(r => ({ ...r, status: 'unsent' })))
          break
        }
      }
    }
    if (current()) progress.value = (i + 1) / chunks.length * 100
  }
  if (current()) { sentMaps = maps; submitting.value = false }
}
let sentMaps = new Map<number, number[]>()
function lineNumbers(row: ImportLine) {
  return submitted.value && sentMaps.has(row.no) ? sentMaps.get(row.no) : splitLines(rows.value).find(c => c.some(r => r.no === row.no))?.map(r => r.no)
}
function failures() { const text = failed.value; tab.value = 'a'; textA.value = text; void precheck() }
function close() { emit('close') }
function search(id: string) { emit('search', id); close() }
function key(e: KeyboardEvent) { if (e.key === 'Escape' && !isOpenSelectTarget(e.target)) { e.preventDefault(); close() } }
onMounted(async () => {
  first.value?.focus(); document.addEventListener('keydown', key)
  const session = captureSession()
  try {
    const result = await request<TemplateDTO[]>('/templates')
    if (!alive || !session.isCurrent()) return
    templates.value = result.slice().sort((a, b) => a.name.localeCompare(b.name)); templateID.value = templates.value[0]?.id || ''
  } catch (e) { if (alive && session.isCurrent()) error.value = e }
})
onBeforeUnmount(() => {
  alive = false; sequence++; clearTimeout(timer); document.removeEventListener('keydown', key)
  if (document.activeElement === document.body || document.activeElement?.closest('.import-drawer')) trigger?.focus()
})
</script>
<template>
  <div class="scrim" @click="close" />
  <section class="drawer import-drawer" role="dialog" aria-modal="true" :aria-label="t('importTitle')">
    <div class="drawer-head"><h2>{{ t('importTitle') }}</h2><div class="import-tabs" role="tablist">
      <button v-for="value in ['a','c']" :key="value" role="tab" :aria-selected="tab === value" :disabled="submitting" @click="tab = value">{{ t(value === 'a' ? 'importA' : 'importC') }}</button>
    </div><button class="btn" @click="close">{{ t('close') }}</button></div>
    <div class="drawer-body import-body">
      <div class="import-editor">
        <template v-if="tab === 'a'"><div class="rule-label"><label for="import-a">{{ t('importA') }}</label><ElTooltip :content="t('importHelp')" :trigger="['hover','click']" popper-class="rule-help-popover"><button class="rule-help" :aria-label="t('explanation')"><QuestionFilled /></button></ElTooltip></div>
          <textarea id="import-a" ref="first" v-model="textA" :disabled="submitting" spellcheck="false" placeholder="dst_ip=192.0.2.1 protocol=udp action=drop" />
          <div class="import-cheat"><code v-for="key in importKeys" :key="key">{{ key }}</code></div>
        </template>
        <template v-else><label for="import-targets">{{ t('importTargets') }}</label><textarea id="import-targets" v-model="targets" :disabled="submitting" spellcheck="false" placeholder="192.0.2.1" />
          <label for="import-template">{{ t('importTemplate') }}</label><select v-if="templates.length" id="import-template" v-model="templateID" :disabled="submitting"><option v-for="value in templates" :key="value.id" :value="value.id">{{ value.name }}</option></select>
          <p v-else class="muted">{{ t('importEmpty') }}</p><pre v-if="template" class="import-template">{{ template.body }}</pre>
        </template>
      </div>
      <div class="import-preview"><div class="import-preview-head"><span v-if="tab === 'c'">{{ t('importProduct', { n: expanded.targets, m: expanded.template, k: expanded.rows.length }) }}</span>
        <ElTooltip v-if="splitLines(rows).length > 1" :content="t('importChunkHelp')" :trigger="['hover','click']" popper-class="rule-help-popover"><button class="rule-help" :aria-label="t('explanation')"><QuestionFilled /></button></ElTooltip></div>
        <RuleError v-if="error" :error="error" @search="search" />
        <div class="tbl-wrap rules"><table><thead><tr><th>{{ t('importLine') }}</th><th>{{ t('target') }}</th><th>{{ t('importMatch') }}</th><th>{{ t('action') }}</th><th>{{ t('expiry') }}</th><th>{{ t('importResult') }}</th></tr></thead><tbody>
          <tr v-for="row in rows" :key="row.no" :data-line="row.no" :title="row.raw" :class="{ off: ['existing','duplicate','skipped','duplicateSkipped'].includes(row.status) }">
            <td class="num muted">{{ row.no }}</td>
            <td v-if="row.lex || row.error" colspan="4" class="wrap"><div class="mono import-raw">{{ row.raw }}</div><p v-if="row.lex" class="error-text">{{ t('importLex.' + row.lex.kind, { n: row.no, key: row.lex.key }) }}</p><RuleError v-else :error="row.error" :line-numbers="lineNumbers(row)" @search="search" /></td>
            <template v-else><td class="mono strong">{{ row.patch?.dst_ip || row.patch?.dst_cidr || row.patch?.src_ip || row.patch?.src_cidr || '—' }}</td>
              <td><span class="mono">{{ row.patch?.protocol || 'all' }}</span><template v-for="key in ['src_port','dst_port',...conditionKeys]" :key="key"><span v-if="row.patch?.[key]" class="cond">{{ key }}={{ row.patch[key] }}</span></template></td>
              <td><span class="tag" :class="row.patch?.action === 'rate_limit' ? 'rl' : 'drop'">{{ row.patch?.action === 'rate_limit' ? t('rateAction') + ' ' + row.patch.rate_limit + ' pps' : t('dropAction') }}</span></td><td>{{ row.patch?.expires_in || t('permanent') }}</td>
            </template><td class="import-status" :class="{ crit: ['lex','error','rejected'].includes(row.status), ok: row.status === 'created' }">{{ row.status === 'pending' ? '' : t('importStatus.' + row.status) }}</td>
          </tr>
        </tbody></table></div>
      </div>
    </div>
    <div class="drawer-foot"><div class="import-counts"><span><b class="ok">{{ rows.filter(r => r.status === 'new' || r.status === 'created').length }}</b>{{ t('importStatus.new') }}</span><span><b class="muted">{{ rows.filter(r => ['existing','duplicate','skipped','duplicateSkipped','renewed'].includes(r.status)).length }}</b>{{ t('importExisting') }}</span><span><b class="crit">{{ rows.filter(r => ['lex','error','rejected','unsent','unknown'].includes(r.status)).length }}</b>{{ t('importErrors') }}</span><ElTooltip v-if="unknown" :content="t('importUnknownHelp')" :trigger="['hover','click']" popper-class="rule-help-popover"><button class="rule-help" :aria-label="t('explanation')"><QuestionFilled /></button></ElTooltip></div>
      <div class="toolbar"><div v-if="submitted" class="import-progress" role="progressbar" :aria-valuenow="progress" aria-valuemin="0" aria-valuemax="100"><b :style="{ width: progress + '%' }" /></div><button v-if="submitted" class="btn" :disabled="submitting || !failed" @click="failures">{{ t('importFailures') }}</button><button class="btn" :disabled="checking || submitting || !rows.length" @click="precheck">{{ t('importCheck') }}</button><button class="btn primary" :disabled="!canSubmit" :aria-busy="submitting" @click="submit">{{ submitted ? t('importSubmitted') : t('importSubmit', { n: count }) }}</button></div>
    </div>
  </section>
</template>
<style scoped>
.import-body { grid-template-columns: minmax(0, .85fr) minmax(0, 1.4fr); }
.import-editor, .import-preview { min-width: 0; }
.import-editor { display: flex; flex-direction: column; gap: 8px; }
.import-editor textarea { min-height: 280px; resize: vertical; width: 100%; border: 1px solid var(--line); background: var(--panel); color: var(--ink); border-radius: var(--r); padding: 8px 10px; font: 12px/1.7 var(--font-num); }
#import-targets { min-height: 130px; }
.import-cheat { display: flex; flex-wrap: wrap; gap: 3px; font-size: 11.5px; }
.import-cheat code { font-family: var(--font-num); background: var(--sunk); border: 1px solid var(--line); padding: 0 4px; border-radius: 3px; color: var(--muted); }
.import-template { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; padding: 8px 10px; background: var(--panel); border: 1px solid var(--line); border-radius: var(--r); font: 11.5px/1.7 var(--font-num); }
.import-tabs { display: inline-flex; gap: 2px; background: var(--sunk); padding: 2px; border-radius: var(--r); }
.import-tabs button { background: transparent; border: 0; border-radius: 3px; color: var(--muted); padding: 3px 12px; font-size: 12.5px; cursor: pointer; }
.import-tabs button[aria-selected=true] { background: var(--panel); color: var(--ink); font-weight: 500; box-shadow: 0 1px 2px rgba(0, 0, 0, .1); }
.import-drawer .btn, .import-tabs button, .import-editor select { min-height: 28px; white-space: nowrap; }
.import-preview-head { display: flex; align-items: center; min-height: 28px; }
.import-raw { overflow-wrap: anywhere; }
.import-preview .cond { margin-left: 4px; }
.import-status { white-space: normal; min-width: 130px; }
.import-counts { display: flex; gap: 14px; flex-wrap: wrap; font-size: 12.5px; align-items: baseline; }
.import-counts b { font: 600 16px var(--font-num); margin-right: 3px; }
.import-progress { width: 140px; height: 4px; background: var(--sunk); border-radius: 2px; overflow: hidden; }
.import-progress b { display: block; height: 100%; background: var(--accent); transition: width .25s; }
@media (max-width: 760px) { .import-body { grid-template-columns: minmax(0, 1fr); } .import-editor textarea { min-height: 150px; } .drawer-head { gap: 6px; } .drawer-foot { gap: 8px; } .drawer-foot .toolbar { flex-wrap: wrap; } }
</style>
