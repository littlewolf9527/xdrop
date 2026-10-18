<script setup lang="ts">
import {
  ref, computed
} from 'vue'
import {
  useI18n
} from 'vue-i18n'
import {
  ElTooltip, ElButton
} from 'element-plus'
import {
  state, setRange, restoreLayout, swapPanels, setSplit
} from '../state'
import {
  metric, bits, offlineNodes, level
} from '../metrics'
import type {
  Range
} from '../api/types'
import TrafficChart from '../components/TrafficChart.vue'
import TopTable from '../components/TopTable.vue'
import NodeTable from '../components/NodeTable.vue'
const {
  t, locale
} = useI18n(), grid = ref<HTMLElement>(), dragging = ref(-1), moving = ref(false)
const ranges: Range[] = ['15m', '1h', '6h', '24h', '7d', '30d']
const stale = computed(() => state.top.updated_at !== null && state.now - Date.parse(state.top.updated_at) > 15000)
const updated = computed(() => state.top.updated_at === null ? '—' : new Intl.DateTimeFormat(locale.value, {
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
}).format(Date.parse(state.top.updated_at)))
function resize(event: PointerEvent) {
  if (!moving.value || !grid.value) return
  const box = grid.value.getBoundingClientRect(), width = box.width - 12, left = Math.max(1, Math.min(width - 1, event.clientX - box.left - 6))
  state.layout.split = Math.min(3.5, Math.max(.5, left / (width - left)))
}
function start(event: PointerEvent) {
  moving.value = true;
  (event.target as HTMLElement).setPointerCapture(event.pointerId)
}
function end() {
  if (moving.value) {
    moving.value = false;
    setSplit(state.layout.split)
  }
}
</script>
<template>
  <section
    class="page"
  >
    <header
      class="page-head"
    >
      <h1>{{ t('overview') }}</h1>
      <div
        class="toolbar"
      >
        <span
          class="sub"
          :class="{ warn: stale }"
        >{{ t('updated') }} {{ updated }}</span>
        <div
          class="range"
        >
          <button
            v-for="range in ranges"
            :key="range"
            :aria-pressed="state.range === range"
            @click="setRange(range)"
          >{{ range }}</button>
        </div>
        <ElButton
          size="small"
          @click="restoreLayout"
        >{{ t('restore') }}</ElButton>
      </div>
    </header>
    <div
      class="kpis"
    >
      <div
        class="kpi drop"
      >
        <span
          class="k"
        >{{ t('dropping') }}</span>
        <span
          class="v c-drop"
        >{{ metric(state.overview.dropped_pps, 'pps') }}</span>
        <span
          class="v2 c-drop b"
        >{{ metric(bits(state.overview.dropped_bytes_ps), 'bps') }}</span>
      </div>
      <div
        class="kpi"
      >
        <span
          class="k"
        >{{ t('forward') }}</span>
        <span
          class="v c-fwd"
        >{{ metric(state.overview.passed_pps, 'pps') }}</span>
        <span
          class="v2 c-fwd b"
        >{{ metric(bits(state.overview.passed_bytes_ps), 'bps') }}</span>
      </div>
      <div
        class="kpi"
      >
        <span
          class="k"
        >{{ t('targets') }}</span>
        <span
          class="v"
        >{{ state.top.targets_total }}</span>
      </div>
      <div
        class="kpi"
      >
        <span
          class="k"
        >{{ t('onlineNodes') }}</span>
        <ElTooltip
          :disabled="!offlineNodes(state.nodes).length"
          :content="offlineNodes(state.nodes).map(n => n.name).join(' · ')"
        >
          <span
            class="v"
            :class="{ crit: state.overview.nodes_online < state.overview.nodes_total }"
          >{{ state.overview.nodes_online }} / {{ state.overview.nodes_total }}</span>
        </ElTooltip>
      </div>
      <div
        class="kpi"
      >
        <span
          class="k"
        >{{ t('capacity') }}<ElTooltip
            :content="t('capacityHelp')"
          >
            <span
              class="tip"
              tabindex="0"
            >?</span>
          </ElTooltip></span>
        <span
          class="v"
          :class="state.capacity ? level(state.capacity.tightest) : ''"
        >{{ state.capacity?.tightest.ratio == null ? '—' : Math.round(state.capacity.tightest.ratio * 100) + '%' }}</span>
      </div>
    </div>
    <div
      ref="grid"
      class="ov"
      :style="{ '--split': state.layout.split + 'fr' }"
    >
      <section
        v-for="(key, index) in state.layout.order"
        :key="key"
        class="panel cell"
        :class="'slot' + index"
        @dragover.prevent
        @drop.prevent="swapPanels(dragging, index); dragging = -1"
      >
        <header
          class="panel-head"
          draggable="true"
          @dragstart="dragging = index; $event.dataTransfer?.setData('text/plain', String(index))"
          @dragend="dragging = -1"
        >
          <h2><span
              class="grip"
              aria-hidden="true"
            >⠿</span>{{ t(key === 'rules' ? 'topRules' : key) }}<span
              v-if="key === 'ip' || key === 'rules'"
              class="muted"
            >Top 5</span></h2>
          <RouterLink
            v-if="key === 'rules'"
            to="/rules"
          >{{ t('all') }} →</RouterLink>
        </header>
        <TrafficChart
          v-if="key === 'pps' || key === 'bps'"
          :bytes="key === 'bps'"
         />
        <TopTable
          v-else
          :rules="key === 'rules'"
         />
      </section>
      <div
        class="gutter"
        :class="{ active: moving }"
        tabindex="0"
        role="separator"
        aria-orientation="vertical"
        :aria-label="t('split')"
        :aria-valuemin=".5"
        :aria-valuemax="3.5"
        :aria-valuenow="state.layout.split"
        @keydown.left.prevent="setSplit(state.layout.split - .1)"
        @keydown.right.prevent="setSplit(state.layout.split + .1)"
        @pointerdown="start"
        @pointermove="resize"
        @pointerup="end"
        @pointercancel="end"
       />
    </div>
    <section
      class="panel"
    >
      <header
        class="panel-head"
      >
        <h2>{{ t('nodes') }}</h2>
        <RouterLink
          to="/nodes"
        >{{ t('all') }} →</RouterLink>
      </header>
      <NodeTable
        :nodes="state.nodes"
       />
    </section>
  </section>
</template>
