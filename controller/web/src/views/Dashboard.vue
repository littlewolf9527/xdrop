<template>
  <div class="dashboard">
    <!-- Stats cards -->
    <div class="stats-grid">
      <div class="xs-stat-card fade-in" style="animation-delay: 0s">
        <div class="xs-stat-icon"><el-icon><List /></el-icon></div>
        <div class="xs-stat-value number-animate">{{ animatedStats.rulesCount }}</div>
        <div class="xs-stat-label">{{ $t('dashboard.stats.rules') }}</div>
      </div>

      <div class="xs-stat-card fade-in" style="animation-delay: 0.1s">
        <div class="xs-stat-icon"><el-icon><CircleCheck /></el-icon></div>
        <div class="xs-stat-value number-animate">{{ animatedStats.whitelistCount }}</div>
        <div class="xs-stat-label">{{ $t('dashboard.stats.whitelist') }}</div>
      </div>

      <div class="xs-stat-card fade-in" style="animation-delay: 0.2s">
        <div class="xs-stat-icon"><el-icon><Monitor /></el-icon></div>
        <div class="xs-stat-value number-animate">
          {{ animatedStats.nodesOnline }}<span class="divider">/</span>{{ animatedStats.nodesTotal }}
        </div>
        <div class="xs-stat-label">{{ $t('dashboard.stats.nodes') }}</div>
      </div>

      <div class="xs-stat-card xs-stat-success fade-in" style="animation-delay: 0.3s">
        <div class="xs-stat-icon"><el-icon><Promotion /></el-icon></div>
        <div class="xs-stat-value number-animate">{{ formatPPS(animatedStats.totalPassedPPS) }}</div>
        <div class="xs-stat-label">{{ $t('dashboard.stats.passedPPS') }}</div>
      </div>

      <div class="xs-stat-card xs-stat-danger fade-in" style="animation-delay: 0.4s">
        <div class="xs-stat-icon"><el-icon><CircleCloseFilled /></el-icon></div>
        <div class="xs-stat-value number-animate">{{ formatPPS(animatedStats.totalDroppedPPS) }}</div>
        <div class="xs-stat-label">{{ $t('dashboard.stats.droppedPPS') }}</div>
      </div>
    </div>

    <!-- Traffic chart area -->
    <div class="charts-row fade-in" style="animation-delay: 0.5s">
      <div class="xs-card">
        <div class="section-header">
          <h2 class="section-title">{{ $t('dashboard.trafficChart') }}</h2>
        </div>
        <TrafficChart :history="trafficHistory" />
      </div>
      <div class="xs-card">
        <div class="section-header">
          <h2 class="section-title">{{ $t('dashboard.dropRate') }}</h2>
        </div>
        <TrafficGauge
          :droppedPPS="stats.totalDroppedPPS"
          :totalPPS="stats.totalPassedPPS + stats.totalDroppedPPS"
        />
      </div>
    </div>

    <!-- Node overview -->
    <div class="nodes-section fade-in" style="animation-delay: 0.6s">
      <div class="section-header">
        <h2 class="section-title">{{ $t('dashboard.nodeStatus') }}</h2>
        <div class="section-actions">
          <span class="refresh-hint" v-if="!loading">{{ $t('dashboard.autoRefresh', { n: refreshInterval/1000 }) }}</span>
          <el-button
            type="primary"
            size="small"
            @click="refresh"
            :loading="loading"
          >
            <el-icon><Refresh /></el-icon>
            {{ $t('common.refresh') }}
          </el-button>
        </div>
      </div>

      <div class="nodes-grid" v-if="nodes.length > 0">
        <NodeCard
          v-for="node in nodes"
          :key="node.id"
          :node="node"
          @click="showNodeDetail"
        />
      </div>
      <div class="xs-card no-nodes" v-else>
        <span>{{ $t('dashboard.noNodes') || 'No nodes' }}</span>
      </div>
    </div>

    <!-- Top N rules chart -->
    <div class="top-rules-section fade-in" style="animation-delay: 0.7s">
      <div class="section-header">
        <h2 class="section-title">{{ $t('dashboard.topRulesChart') }}</h2>
      </div>
      <div class="xs-card chart-container">
        <TopRulesChart :rules="topRules" />
      </div>
    </div>

    <!-- Node detail dialog -->
    <NodeDetail
      v-model="nodeDetailVisible"
      :node="selectedNode"
    />
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted, watch } from 'vue'
import { statsApi, nodesApi, rulesApi } from '../api'
import TrafficChart from '../components/TrafficChart.vue'
import TrafficGauge from '../components/TrafficGauge.vue'
import NodeCard from '../components/NodeCard.vue'
import TopRulesChart from '../components/TopRulesChart.vue'
import NodeDetail from '../components/NodeDetail.vue'

const loading = ref(false)
const refreshInterval = 5000
let refreshTimer = null

const stats = reactive({
  rulesCount: 0,
  whitelistCount: 0,
  nodesTotal: 0,
  nodesOnline: 0,
  totalPassedPPS: 0,
  totalDroppedPPS: 0
})

const animatedStats = reactive({
  rulesCount: 0,
  whitelistCount: 0,
  nodesTotal: 0,
  nodesOnline: 0,
  totalPassedPPS: 0,
  totalDroppedPPS: 0
})

const nodes = ref([])
const topRules = ref([])

// Traffic history — ring buffer of 60 data points (3 min at 3s interval)
const trafficHistory = ref([])
const MAX_HISTORY = 60

// Node detail dialog
const nodeDetailVisible = ref(false)
const selectedNode = ref(null)

const showNodeDetail = (node) => {
  selectedNode.value = node
  nodeDetailVisible.value = true
}

// Number animation
const animateNumber = (key, target) => {
  const start = animatedStats[key]
  const diff = target - start
  const duration = 300
  const startTime = Date.now()

  const animate = () => {
    const elapsed = Date.now() - startTime
    const progress = Math.min(elapsed / duration, 1)
    const eased = 1 - (1 - progress) * (1 - progress)
    animatedStats[key] = Math.round(start + diff * eased)

    if (progress < 1) {
      requestAnimationFrame(animate)
    }
  }

  requestAnimationFrame(animate)
}

watch(() => stats.rulesCount, (val) => animateNumber('rulesCount', val))
watch(() => stats.whitelistCount, (val) => animateNumber('whitelistCount', val))
watch(() => stats.nodesTotal, (val) => animateNumber('nodesTotal', val))
watch(() => stats.nodesOnline, (val) => animateNumber('nodesOnline', val))
watch(() => stats.totalPassedPPS, (val) => animateNumber('totalPassedPPS', val))
watch(() => stats.totalDroppedPPS, (val) => animateNumber('totalDroppedPPS', val))

// Independent fetch functions
const fetchStats = async () => {
  try {
    const data = await statsApi.getGlobal()
    stats.rulesCount = data.rules_count || 0
    stats.whitelistCount = data.whitelist_count || 0
    stats.nodesTotal = data.nodes_count || 0
    stats.nodesOnline = data.online_nodes || 0
    stats.totalPassedPPS = data.total_passed_pps || 0
    stats.totalDroppedPPS = data.total_dropped_pps || 0
    const point = { passedPPS: stats.totalPassedPPS, droppedPPS: stats.totalDroppedPPS }
    const history = [...trafficHistory.value, point]
    if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY)
    trafficHistory.value = history
  } catch (e) {
    console.error('Failed to fetch stats:', e)
  }
}

const fetchNodes = async () => {
  try {
    const data = await nodesApi.list()
    nodes.value = data.nodes || []
  } catch (e) {
    console.error('Failed to fetch nodes:', e)
  }
}

const fetchTopRules = async () => {
  try {
    const data = await rulesApi.top(10)
    topRules.value = data.rules || []
  } catch (e) {
    console.error('Failed to fetch top rules:', e)
  }
}

const doRefresh = (includeTopRules = false) => {
  fetchStats()
  fetchNodes()
  if (includeTopRules) fetchTopRules()
}

const refresh = async () => {
  loading.value = true
  doRefresh(true)
  try {
    await statsApi.getGlobal()
  } catch (_) {}
  loading.value = false
}

const softRefresh = () => {
  doRefresh(false)
}

const formatPPS = (pps) => {
  if (!pps || pps === 0) return '0'
  if (pps >= 1000000) return (pps / 1000000).toFixed(1) + 'M'
  if (pps >= 1000) return (pps / 1000).toFixed(1) + 'K'
  return Math.round(pps).toString()
}

onMounted(() => {
  doRefresh(true)
  refreshTimer = setInterval(softRefresh, refreshInterval)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 28px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 20px;
}

@media (max-width: 1400px) {
  .stats-grid { grid-template-columns: repeat(3, 1fr); }
}
@media (max-width: 1000px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 600px) {
  .stats-grid { grid-template-columns: 1fr; }
}

/* Stat cards — xSight unified style */
.xs-stat-card {
  background: var(--xs-card-bg);
  border: 1px solid var(--xs-card-border);
  border-radius: var(--xs-radius-lg);
  padding: 20px 24px;
  position: relative;
  cursor: default;
  transition: all 0.2s;
  box-shadow: var(--xs-shadow);
}
.xs-stat-card:hover {
  border-color: var(--xs-card-hover-border);
  box-shadow: var(--xs-shadow-lg);
  transform: translateY(-1px);
}

.xs-stat-value {
  font-size: 32px;
  font-weight: 700;
  letter-spacing: -0.03em;
  color: var(--xs-stat-color);
  line-height: 1.1;
}
.xs-stat-value .divider {
  color: var(--xs-text-secondary);
  opacity: 0.5;
  font-weight: 400;
  margin: 0 1px;
}

.xs-stat-label {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--xs-text-secondary);
  margin-top: 8px;
}

.xs-stat-icon {
  position: absolute;
  right: 20px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 3rem;
  opacity: 0.06;
  color: var(--xs-accent);
}

.xs-stat-success .xs-stat-value { color: var(--xs-success); }
.xs-stat-success .xs-stat-icon { color: var(--xs-success); }
.xs-stat-danger .xs-stat-value { color: var(--xs-danger); }
.xs-stat-danger .xs-stat-icon { color: var(--xs-danger); }

/* Generic card */
.xs-card {
  background: var(--xs-card-bg);
  border: 1px solid var(--xs-card-border);
  border-radius: var(--xs-radius-lg);
  padding: 20px 24px;
  box-shadow: var(--xs-shadow);
  transition: border-color 0.2s, box-shadow 0.2s;
}

/* Charts row */
.charts-row {
  display: grid;
  grid-template-columns: 3fr 2fr;
  gap: 20px;
}
@media (max-width: 1000px) {
  .charts-row { grid-template-columns: 1fr; }
}

/* Nodes section */
.nodes-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.nodes-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}
.no-nodes {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px;
  color: var(--xs-text-secondary);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}
.section-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--xs-text-primary);
}
.section-actions {
  display: flex;
  align-items: center;
  gap: 16px;
}
.refresh-hint {
  font-size: 12px;
  color: var(--xs-text-secondary);
}

/* Top rules section */
.top-rules-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.chart-container {
  padding: 20px;
}
</style>
