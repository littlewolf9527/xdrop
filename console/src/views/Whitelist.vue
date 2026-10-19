<script setup lang="ts">
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElDropdown, ElDropdownMenu, ElDropdownItem } from 'element-plus'
import { request, captureSession, state } from '../state'
import { trailingThrottle } from '../api/events'
import type { WhitelistDTO, WhitelistPage } from '../api/types'
import { errorText } from '../errors'
import WhitelistDrawer from '../components/WhitelistDrawer.vue'
const { t } = useI18n(), rows = ref<WhitelistDTO[]>([]), query = ref(''), applied = ref('')
const busy = ref(false), error = ref<unknown>(null), drawer = ref(false), confirmation = ref(''), deleting = ref('')
let alive = true, sequence = 0, timer: ReturnType<typeof setTimeout> | undefined
const filtered = computed(() => rows.value.filter(r => [r.src_ip, r.dst_ip, r.comment].some(v => v.toLowerCase().includes(applied.value))))
watch(query, () => { clearTimeout(timer); timer = setTimeout(() => { applied.value = query.value.trim().toLowerCase() }, 300) })
async function load() {
  if (state.user === null) return
  const serial = ++sequence, session = captureSession(), current = () => alive && serial === sequence && session.isCurrent()
  busy.value = true
  let after: string | null = null
  const collected: WhitelistDTO[] = []
  try {
    while (true) {
      const result: WhitelistPage = await request('/whitelist?limit=1000' + (after ? '&after=' + encodeURIComponent(after) : ''))
      if (!current()) return
      if (result.next_after !== null && result.next_after === after) throw new Error('Whitelist cursor did not advance')
      collected.push(...result.items); after = result.next_after
      if (after === null) break
    }
    if (current()) { rows.value = collected; error.value = null }
  } catch (e) { if (current()) error.value = e }
  finally { if (current()) busy.value = false }
}
const refresh = trailingThrottle(() => { void load() }, 5000)
watch(() => state.rules, () => { if (state.user !== null) refresh() })
function confirm(row: WhitelistDTO) { confirmation.value = row.id }
async function remove() {
  if (!confirmation.value || deleting.value || state.user === null) return
  const id = confirmation.value, session = captureSession(), current = () => alive && session.isCurrent()
  deleting.value = id; error.value = null
  try {
    await request('/whitelist/' + encodeURIComponent(id), { method: 'DELETE' })
    if (current()) { confirmation.value = ''; void load() }
  } catch (e) { if (current()) error.value = e }
  finally { if (current()) deleting.value = '' }
}
function saved() { drawer.value = false; void load() }
function ports(row: WhitelistDTO) {
  return [row.src_port ? t('source') + ' ' + row.src_port : '', row.dst_port ? t('destination') + ' ' + row.dst_port : ''].filter(Boolean).join(' · ') || '—'
}
function created(at: string) {
  const d = new Date(at), n = (v: number) => String(v).padStart(2, '0')
  return n(d.getMonth() + 1) + '-' + n(d.getDate()) + ' ' + n(d.getHours()) + ':' + n(d.getMinutes())
}
onMounted(() => { void load() })
onBeforeUnmount(() => { alive = false; sequence++; clearTimeout(timer); refresh.cancel() })
</script>
<template>
  <section class="page whitelist-page">
    <div class="page-head"><h1>{{ t('whitelist') }}</h1><button class="btn primary" @click="drawer = true">{{ t('whitelistNew') }}</button></div>
    <div class="toolbar"><input v-model="query" class="search" :placeholder="t('whitelistSearch')" :aria-label="t('whitelistSearch')"><span class="sub">{{ t('whitelistCount', { n: filtered.length }) }}</span></div>
    <p v-if="error" class="error-text" role="alert">{{ errorText(error) }}</p>
    <div class="tbl-wrap rules"><table><thead><tr><th>{{ t('source') }}</th><th>{{ t('destination') }}</th><th>{{ t('protocol') }}</th><th>{{ t('whitelistPorts') }}</th><th>{{ t('comment') }}</th><th>{{ t('whitelistCreator') }}</th><th>{{ t('whitelistCreated') }}</th><th /></tr></thead><tbody>
      <template v-for="row in filtered" :key="row.id"><tr :data-whitelist-id="row.id">
        <td :class="row.src_ip ? 'mono strong' : 'muted'">{{ row.src_ip || t('whitelistAny') }}</td><td :class="row.dst_ip ? 'mono strong' : 'muted'">{{ row.dst_ip || t('whitelistAny') }}</td><td class="mono">{{ row.protocol }}</td><td class="whitelist-ports">{{ ports(row) }}</td><td>{{ row.comment }}</td><td class="mono">{{ row.created_by.replace(/^user:/, '') }}</td><td class="num muted">{{ created(row.created_at) }}</td>
        <td><ElDropdown trigger="click" placement="bottom-end" popper-class="row-menu" :show-arrow="false"><button class="row-menu-trigger" :aria-label="t('more')">⋯</button><template #dropdown><ElDropdownMenu><ElDropdownItem :disabled="!!deleting" @click="confirm(row)">{{ t('delete') }}</ElDropdownItem></ElDropdownMenu></template></ElDropdown></td>
      </tr><tr v-if="confirmation === row.id"><td colspan="8" class="wrap"><div class="confirm"><strong>{{ t('whitelistDelete') }}</strong><div class="toolbar"><button class="btn danger" :disabled="!!deleting" @click="remove">{{ t('delete') }}</button><button class="btn" :disabled="!!deleting" @click="confirmation = ''">{{ t('cancel') }}</button></div></div></td></tr></template>
      <tr v-if="busy && !rows.length"><td colspan="8">{{ t('whitelistLoading') }}</td></tr><tr v-else-if="!filtered.length"><td colspan="8" class="muted">{{ t(applied ? 'whitelistNoMatch' : 'whitelistEmpty') }}</td></tr>
    </tbody></table></div>
    <WhitelistDrawer v-if="drawer" @close="drawer = false" @saved="saved" />
  </section>
</template>
<style scoped>
.whitelist-page .btn, .whitelist-page .search { min-height: 28px; white-space: nowrap; }
.whitelist-page .toolbar { margin-bottom: 12px; }
.whitelist-page .confirm .toolbar { margin: 8px 0 0; }
</style>
