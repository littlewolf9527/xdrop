<script setup lang="ts">
import { computed, ref, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { state, request, captureSession } from '../../state'
import type { Node, NodeTestDTO } from '../../api/types'
import { jsonWrite, settingsError } from '../../settings'
const { t } = useI18n()
const form = ref<'add' | 'edit' | ''>(''), editing = ref<Node>(), name = ref(''), address = ref(''), key = ref('')
const confirmation = ref(''), error = ref(''), busy = ref(false), testing = ref(''), results = ref<Record<string, NodeTestDTO>>({})
let alive = true
onBeforeUnmount(() => { alive = false; key.value = '' })
const path = (name: string) => '/nodes/' + encodeURIComponent(name)
const patch = computed(() => ({ ...(address.value !== editing.value?.base_url ? { base_url: address.value } : {}), ...(key.value !== '' ? { api_key: key.value } : {}) }))
const canSave = computed(() => form.value === 'add' ? !!(name.value && address.value && key.value) : !!editing.value && Object.keys(patch.value).length > 0 && (!editing.value.key_unreadable || key.value !== ''))
function close() { form.value = ''; editing.value = undefined; name.value = ''; address.value = ''; key.value = ''; error.value = '' }
function edit(node?: Node) {
  close(); confirmation.value = ''; form.value = node ? 'edit' : 'add'; editing.value = node
  name.value = node?.name || ''; address.value = node?.base_url || ''; results.value = {}
}
function confirm(name: string) { close(); confirmation.value = name; error.value = '' }
async function write(remove = false) {
  if (busy.value || (!remove && !canSave.value)) return
  const session = captureSession(), current = () => alive && session.isCurrent()
  busy.value = true; error.value = ''
  try {
    await request(remove ? path(confirmation.value) : form.value === 'add' ? '/nodes' : path(name.value),
      jsonWrite(remove ? 'DELETE' : form.value === 'add' ? 'POST' : 'PATCH', remove ? undefined : form.value === 'add' ? { name: name.value, base_url: address.value, api_key: key.value } : patch.value))
    if (!current()) return
    close(); confirmation.value = ''
  } catch (e) { if (current()) error.value = settingsError('nodes', e) }
  finally { if (current()) busy.value = false }
}
async function test(node?: Node) {
  if (testing.value || (!node && !(name.value && address.value && key.value))) return
  const session = captureSession(), current = () => alive && session.isCurrent(), target = node?.name || '@add'
  testing.value = target; error.value = ''
  try {
    const result = await request<NodeTestDTO>(node ? path(node.name) + '/test' : '/nodes/test', jsonWrite('POST', node ? undefined : { base_url: address.value, api_key: key.value }))
    if (!current()) return
    results.value[target] = result
  } catch (e) { if (current()) error.value = settingsError('nodes', e) }
  finally { if (current()) testing.value = '' }
}
const testFields = ['reachable', 'compatible', 'key_accepted'] as const
</script>
<template>
  <section data-tab="nodes">
    <div class="toolbar settings-actions"><button class="btn primary" :disabled="busy || !!testing" @click="edit()">{{ t('settingsUI.addNode') }}</button></div>
    <form v-if="form === 'add'" class="panel form" data-form="node" @submit.prevent="write()">
      <h2>{{ t('settingsUI.addNode') }}</h2>
      <label class="field"><span>{{ t('name') }}</span><input v-model="name" name="name" autocomplete="off" :disabled="busy || !!testing"></label>
      <label class="field"><span>{{ t('settingsUI.address') }}</span><input v-model="address" name="base_url" autocomplete="off" :disabled="busy || !!testing"></label>
      <label class="field"><span>{{ t('settingsUI.nodeKey') }}</span><input v-model="key" name="api_key" type="password" autocomplete="off" :disabled="busy || !!testing"></label>
      <p v-if="error" class="error-text" role="alert">{{ t(error) }}</p>
      <div v-if="results['@add']" :title="results['@add']!.message || undefined" data-result><span v-for="field in testFields" :key="field" :class="results['@add']![field] ? 'ok-text' : 'crit'">{{ t('settingsUI.' + field) }} {{ results['@add']![field] ? '✓' : '✗' }} </span></div>
      <div class="toolbar"><button type="button" class="btn" :disabled="!canSave || busy || !!testing" :aria-busy="testing === '@add'" @click="test()">{{ t('settingsUI.testConnection') }}</button><button class="btn primary" :disabled="!canSave || busy || !!testing" :aria-busy="busy">{{ t('settingsUI.save') }}</button><button type="button" class="btn" :disabled="busy || !!testing" @click="close">{{ t('cancel') }}</button></div>
    </form>
    <p v-if="error && !form && !confirmation" class="error-text" role="alert">{{ t(error) }}</p>
    <div class="tbl-wrap rules"><table><thead><tr><th v-for="label in ['name', 'settingsUI.address', 'status', 'settingsUI.key', 'settingsUI.actions']" :key="label">{{ t(label) }}</th></tr></thead><tbody>
      <template v-for="node in state.nodes" :key="node.name">
        <tr :data-row="node.name"><td class="mono strong">{{ node.name }}</td><td class="mono">{{ node.base_url || '—' }}</td><td><span class="dot" :class="node.online && !node.incompatible ? 'ok' : 'crit'">{{ t(node.incompatible ? 'incompatible' : node.online ? 'online' : 'offline') }}</span></td><td><span :class="node.key_unreadable ? 'crit' : 'muted'" :title="node.key_unreadable ? t('settingsUI.nodeKeyHelp') : undefined">{{ t(node.key_unreadable ? 'settingsUI.unreadable' : 'settingsUI.keySet') }}</span></td><td class="r nw">
          <button class="btn sm" :disabled="busy || !!testing" @click="edit(node)">{{ t('edit') }}</button> <button class="btn sm" :disabled="busy || !!testing" :aria-busy="testing === node.name" @click="test(node)">{{ t('settingsUI.test') }}</button> <button class="btn sm" :disabled="busy || !!testing" @click="confirm(node.name)">{{ t('settingsUI.stop') }}</button>
        </td></tr>
        <tr v-if="results[node.name]"><td colspan="5" class="wrap" :title="results[node.name]!.message || undefined" data-result><span v-for="field in testFields" :key="field" :class="results[node.name]![field] ? 'ok-text' : 'crit'">{{ t('settingsUI.' + field) }} {{ results[node.name]![field] ? '✓' : '✗' }} </span></td></tr>
        <tr v-if="form === 'edit' && name === node.name"><td colspan="5" class="wrap"><form class="panel form" data-form="node" @submit.prevent="write()">
          <label class="field"><span>{{ t('name') }}</span><span class="mono">{{ name }}</span></label>
          <label class="field"><span>{{ t('settingsUI.address') }}</span><input v-model="address" name="base_url" :disabled="busy" autocomplete="off"></label>
          <label class="field"><span>{{ t('settingsUI.nodeKey') }}</span><input v-model="key" name="api_key" :disabled="busy" type="password" autocomplete="off"></label>
          <p v-if="error" class="error-text" role="alert">{{ t(error) }}</p><div class="toolbar"><button class="btn primary" :disabled="!canSave || busy" :aria-busy="busy">{{ t('settingsUI.save') }}</button><button type="button" class="btn" :disabled="busy" @click="close">{{ t('cancel') }}</button></div>
        </form></td></tr>
        <tr v-if="confirmation === node.name"><td colspan="5" class="wrap"><div class="confirm"><span>{{ t('settingsUI.stopConfirm', { name: node.name }) }}</span><p v-if="error" class="error-text" role="alert">{{ t(error) }}</p><div class="toolbar"><button class="btn sm danger" :disabled="busy" :aria-busy="busy" @click="write(true)">{{ t('settingsUI.stop') }}</button><button class="btn sm" :disabled="busy" @click="confirmation = ''; error = ''">{{ t('cancel') }}</button></div></div></td></tr>
      </template>
    </tbody></table></div>
  </section>
</template>
