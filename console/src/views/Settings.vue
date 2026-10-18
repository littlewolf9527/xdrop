<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { canSettings, state } from '../state'
import NodesTab from '../components/settings/NodesTab.vue'
import UsersTab from '../components/settings/UsersTab.vue'
import KeysTab from '../components/settings/KeysTab.vue'
import SystemTab from '../components/settings/SystemTab.vue'
import TemplatesTab from '../components/settings/TemplatesTab.vue'
const { t } = useI18n(), router = useRouter(), tab = ref('nodes')
const tabs = ['nodes', 'users', 'keys', 'system', 'templates']
watch(() => state.user, user => { if (user !== null && user.role === 'operator') void router.replace('/overview') })
</script>
<template>
  <div class="page settings-page">
    <div class="page-head"><h1>{{ t('settings') }}</h1><span v-if="canSettings" class="pill">{{ t('settingsUI.admin') }}</span></div>
    <template v-if="canSettings">
      <div class="settings-tabs" role="tablist"><button v-for="name in tabs" :key="name" role="tab" :aria-selected="tab === name" @click="tab = name">{{ t('settingsUI.' + name) }}</button></div>
      <NodesTab v-if="tab === 'nodes'" /><UsersTab v-if="tab === 'users'" /><KeysTab v-if="tab === 'keys'" /><SystemTab v-if="tab === 'system'" /><TemplatesTab v-if="tab === 'templates'" />
    </template>
  </div>
</template>
<style scoped>
.settings-tabs { display: flex; width: fit-content; max-width: 100%; overflow-x: auto; gap: 2px; background: var(--sunk); padding: 2px; border-radius: var(--r); margin-bottom: 12px; }
.settings-tabs button { flex-shrink: 0; background: transparent; border: 0; border-radius: 3px; color: var(--muted); padding: 3px 12px; font-size: 12.5px; cursor: pointer; min-height: 28px; white-space: nowrap; }
.settings-tabs button[aria-selected=true] { background: var(--panel); color: var(--ink); font-weight: 500; box-shadow: 0 1px 2px rgba(0,0,0,.1); }
.settings-page :deep(.settings-actions) { justify-content: flex-end; margin-bottom: 12px; }
.settings-page :deep(.btn), .settings-page :deep(select), .settings-page :deep(input) { min-height: 28px; white-space: nowrap; }
.settings-page :deep(.tbl-wrap) { max-width: 100%; }
.settings-page :deep(td), .settings-page :deep(th) { white-space: nowrap; }
.settings-page :deep(td.wrap) { white-space: normal; }
.settings-page :deep(.field input), .settings-page :deep(.field select), .settings-page :deep(textarea) { width: 100%; min-width: 0; }
.settings-page :deep(textarea) { min-height: 150px; padding: 8px; resize: vertical; background: var(--panel); color: var(--ink); border: 1px solid var(--line); border-radius: var(--r); }
.settings-page :deep(.crit) { color: var(--crit); }
.settings-page :deep(.ok-text) { color: var(--ok); }
.settings-page :deep(.confirm .toolbar) { margin-top: 8px; }
.settings-page :deep(.pill[tabindex]) { position: relative; }
.settings-page :deep(.tip)::before, .settings-page :deep(.pill[tabindex])::before { content: ''; position: absolute; left: 50%; top: 50%; width: max(100%, 28px); height: max(100%, 28px); transform: translate(-50%, -50%); }
.settings-page :deep(.form) { margin-block: 12px; }
.settings-page :deep(.srow select) { min-width: 0; max-width: 100%; }
.settings-page :deep(.srow .error-text) { grid-column: 2; }
@media (max-width: 480px) { .settings-page :deep(.srow) { grid-template-columns: 120px minmax(0,1fr); gap: 8px; } }
</style>
