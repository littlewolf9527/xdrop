<script setup lang="ts">
import {
  ref, computed, watch
} from 'vue'
import {
  useI18n
} from 'vue-i18n'
import {
  useRoute
} from 'vue-router'
import {
  ElDialog, ElButton
} from 'element-plus'
import {
  DataAnalysis, Tickets, CircleCheck, Connection, Clock, Setting, InfoFilled
} from '@element-plus/icons-vue'
import {
  state, canSettings, logout
} from './state'
import {
  offlineNodes, level, percent
} from './metrics'
import Preferences from './components/Preferences.vue'
import Meter from './components/Meter.vue'
import PasswordDrawer from './components/PasswordDrawer.vue'
import { openPassword, passwordOpen } from './password'
watch(() => state.user, user => { if (user === null) passwordOpen.value = false }, { flush: 'sync' })
const route = useRoute(), {
  t, locale
} = useI18n(), capacityOpen = ref(false), capacityCard = ref<HTMLButtonElement>()
const links = [{
  key: 'overview', icon: DataAnalysis
}, {
  key: 'rules', label: 'blocklist', icon: Tickets
}, {
  key: 'whitelist', icon: CircleCheck
}, {
  key: 'nodes', icon: Connection
}, {
  key: 'audit', icon: Clock
}, {
  key: 'settings', icon: Setting
}]
const offline = computed(() => offlineNodes(state.nodes).length)
</script>
<template>
  <RouterView
    v-if="route.path === '/login'"
   />
  <div
    v-else
    class="shell"
  >
    <aside
      class="side"
    >
      <RouterLink
        class="brand"
        to="/overview"
      ><span
          class="mark"
          aria-hidden="true"
         />XDROP</RouterLink>
      <nav
        class="nav"
      >
        <template
          v-for="link in links"
          :key="link.key"
        >
          <RouterLink
            v-if="link.key !== 'settings' || canSettings"
            :to="'/' + link.key"
            :aria-current="route.path === '/' + link.key ? 'page' : undefined"
          >
            <component
              :is="link.icon"
             />
            <span>{{ t(link.label || link.key) }}</span>
            <span
              v-if="link.key === 'nodes' && offline"
              class="badge"
            >{{ offline }}</span>
          </RouterLink>
        </template>
      </nav>
      <div
        class="side-foot"
      >
        <button
          v-if="state.capacity"
          class="cap"
          ref="capacityCard"
          aria-haspopup="dialog"
          :title="t('capacityHelp') + (locale === 'en-US' ? ' (' : '（') + t('dimensions.' + state.capacity.tightest.name) + (locale === 'en-US' ? ')' : '）')"
          @click="capacityOpen = true"
        >
          <span>{{ t('ruleCapacity') }}</span>
          <Meter
            :ratio="state.capacity.tightest.ratio"
            :exhausted="state.capacity.tightest.exhausted"
           />
        </button>
        <Preferences />
        <div
          class="user"
        >
          <button class="text-btn password-trigger" aria-haspopup="dialog" :title="t('passwordChange')" @click="openPassword">{{ state.user?.name }}</button>
          <button
            class="text-btn"
            @click="logout"
          >{{ t('logout') }}</button>
        </div>
        <RouterLink class="about-link" to="/about" :aria-label="t('about')"><InfoFilled /><span>{{ t('about') }}</span></RouterLink>
      </div>
    </aside>
    <ElDialog v-if="state.capacity" v-model="capacityOpen" :title="t('ruleCapacity')" width="min(880px, calc(100vw - 32px))" align-center append-to-body modal-class="capacity-overlay" class="capacity-dialog" @close-auto-focus="capacityCard?.focus()">
      <div class="tbl-wrap"><table class="capacity-table"><thead><tr><th>{{ t('name') }}</th><th colspan="2" class="r">{{ t('usage') }}</th><th class="r">{{ t('used') }} / {{ t('limit') }}</th></tr></thead><tbody>
        <tr v-for="dim in state.capacity.dimensions" :key="dim.name"><td>{{ t('dimensions.' + dim.name) }}</td>
          <td><span class="capmeter" v-if="dim.ratio !== null"><b :class="level(dim)" :style="{ width: Math.min(100, Math.max(0, dim.ratio * 100)) + '%' }" /></span></td>
          <td class="num r">{{ percent(dim.ratio) }}</td><td class="num r">{{ dim.used.toLocaleString(locale) }} / {{ dim.admission_limit.toLocaleString(locale) }}</td>
        </tr>
      </tbody></table></div>
    </ElDialog>
    <PasswordDrawer v-if="passwordOpen" />
    <main
      class="main"
    >
      <div
        v-if="state.error"
        class="error-banner"
        role="alert"
      >{{ t(state.error) }} <ElButton
          text
          @click="state.error = ''"
        >×</ElButton></div>
      <RouterView />
    </main>
  </div>
</template>

<style scoped>
.user .password-trigger { min-width: 0; min-height: 28px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: left; }
.user > .text-btn:last-child { flex-shrink: 0; }
@media (max-width: 760px) {
  .side-foot:has(.about-link) .user { width: 0; min-width: 0; flex: 1 1 0; }
}
</style>
