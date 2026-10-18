<script setup lang="ts">
import {
  reactive
} from 'vue'
import {
  useI18n
} from 'vue-i18n'
import {
  ElButton, ElTooltip, ElDropdown, ElDropdownMenu, ElDropdownItem
} from 'element-plus'
import type {
  Node
} from '../api/types'
import {
  bits, metric, syncState, heartbeat
} from '../metrics'
import {
  state, request, captureSession
} from '../state'
defineProps<{
  nodes: Node[];
  actions?: boolean
}>()
const {
  t
} = useI18n(), submitted = reactive<Record<string, boolean>>({
}), busy = reactive<Record<string, boolean>>({
})
const rate = (n: Node, key: 'dropped_packets' | 'passed_packets' | 'dropped_bytes' | 'passed_bytes') => !n.online || !n.rates ? '—' :
  metric(key.endsWith('bytes') ? bits(n.rates[key]) : n.rates[key], key.endsWith('bytes') ? 'bps' : 'pps')
async function action(name: string, operation: 'sync' | 'reconcile') {
  const session = captureSession()
  busy[name] = true
  try {
    await request('/nodes/' + encodeURIComponent(name) + '/' + operation, {
      method: 'POST'
    });
    submitted[name] = true;
    setTimeout(() => {
      submitted[name] = false
    }, 2000)
  }
  catch (error) {
    session.report(error)
  } finally {
    busy[name] = false
  }
}
async function all() {
  const session = captureSession()
  for (const n of state.nodes) {
    if (!session.isCurrent()) break
    await action(n.name, 'sync')
  }
}
defineExpose({
  all
})
</script>
<template>
  <div
    class="tbl-wrap"
  >
    <table
      class="node-table"
    >
      <thead>
        <tr>
          <th>{{ t('node') }}</th>
          <th>{{ t('status') }}</th>
          <th
            class="r"
          >{{ t('drop') }}</th>
          <th
            class="r"
          >{{ t('forward') }}</th>
          <th>CPU</th>
          <th>{{ t('memory') }}</th>
          <th>{{ t('sync') }}</th>
          <th>{{ t('heartbeat') }}</th>
          <th
            v-if="actions"
           />
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="node in nodes"
          :key="node.name"
        >
          <td
            class="mono strong"
          >{{ node.name }}</td>
          <td>
            <span
              class="dot"
              :class="node.online ? 'ok' : 'crit'"
            >{{ t(node.online ? 'online' : 'offline') }}</span>
          </td>
          <td
            class="r num rate-pair"
          >
            <span
              class="c-drop"
            >{{ rate(node, 'dropped_packets') }}</span>
            <span
              class="c-drop b"
            >{{ rate(node, 'dropped_bytes') }}</span>
          </td>
          <td
            class="r num rate-pair"
          >
            <span
              class="c-fwd"
            >{{ rate(node, 'passed_packets') }}</span>
            <span
              class="c-fwd b"
            >{{ rate(node, 'passed_bytes') }}</span>
          </td>
          <td
            v-for="field in (['cpu_percent', 'mem_percent'] as const)"
            :key="field"
            class="nw"
          >
            <template
              v-if="node.stats?.system?.[field] != null"
            >
              <span
                class="minibar"
              >
                <b
                  :class="{ warn: node.stats.system[field] >= 70 }"
                  :style="{ width: Math.min(100, Math.max(0, node.stats.system[field])) + '%' }"
                 />
              </span>
              <span
                class="num"
              >{{ Math.round(node.stats.system[field]) }}%</span>
            </template>
            <template
              v-else
            >—</template>
          </td>
          <td>
            <ElTooltip
              :content="[String(node.rules.confirmed_gen), node.rules.reason, node.whitelist.reason].filter(Boolean).join(' · ')"
            >
              <span
                class="sync-word"
                :class="['failed', 'overloaded', 'offline'].includes(syncState(node)) ? 'crit' : ''"
              >{{ t(syncState(node)) }}</span>
            </ElTooltip>
          </td>
          <td
            class="nw muted"
          >{{ heartbeat(node.health_at, state.now) === null ? '—' : t('ago', { n: heartbeat(node.health_at, state.now) }) }}</td>
          <td
            v-if="actions"
            class="nw"
          >
            <span
              v-if="submitted[node.name]"
              role="status"
              class="ok"
            >{{ t('submitted') }}</span>
            <template
              v-else
            >
              <ElButton
                size="small"
                :disabled="busy[node.name]"
                @click="action(node.name, 'sync')"
              >{{ t('resync') }}</ElButton>
              <ElDropdown trigger="click" placement="bottom-end" popper-class="row-menu" :show-arrow="false">
                <button class="row-menu-trigger" :aria-label="t('more')">⋯</button>
                <template #dropdown><ElDropdownMenu><ElDropdownItem :disabled="busy[node.name]" @click="action(node.name, 'reconcile')">{{ t('reconcile') }}</ElDropdownItem></ElDropdownMenu></template>
              </ElDropdown>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
