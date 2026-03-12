<template>
  <div class="node-card glass-card" @click="$emit('click', node)">
    <div class="card-header">
      <div class="node-name-row">
        <span class="status-dot" :class="node.status"></span>
        <span class="node-name">{{ node.name }}</span>
      </div>
      <el-tag :type="node.status === 'online' ? 'success' : 'danger'" size="small">
        {{ node.status === 'online' ? $t('nodes.status.online') : $t('nodes.status.offline') }}
      </el-tag>
    </div>

    <div class="card-metrics">
      <div class="metric">
        <span class="metric-label">{{ $t('dashboard.stats.passedPPS') }}</span>
        <span class="metric-value success">{{ formatPPS(node.stats?.passed_pps) }}</span>
      </div>
      <div class="metric">
        <span class="metric-label">{{ $t('dashboard.stats.droppedPPS') }}</span>
        <span class="metric-value danger">{{ formatPPS(node.stats?.dropped_pps) }}</span>
      </div>
      <div class="metric">
        <span class="metric-label">{{ $t('nodes.rulesCount') }}</span>
        <span class="metric-value">{{ node.stats?.rules_count ?? 0 }}</span>
      </div>
    </div>

    <div class="card-system" v-if="node.stats?.system">
      <div class="sys-item">
        <span class="sys-label">CPU</span>
        <el-progress
          :percentage="Math.round(node.stats.system.cpu_percent)"
          :stroke-width="6"
          :color="progressColor(node.stats.system.cpu_percent)"
          :show-text="false"
          style="flex: 1"
        />
        <span class="sys-pct" :style="{ color: progressColor(node.stats.system.cpu_percent) }">
          {{ node.stats.system.cpu_percent.toFixed(1) }}%
        </span>
      </div>
      <div class="sys-item">
        <span class="sys-label">MEM</span>
        <el-progress
          :percentage="Math.round(node.stats.system.mem_percent)"
          :stroke-width="6"
          :color="progressColor(node.stats.system.mem_percent)"
          :show-text="false"
          style="flex: 1"
        />
        <span class="sys-pct" :style="{ color: progressColor(node.stats.system.mem_percent) }">
          {{ node.stats.system.mem_percent.toFixed(1) }}%
        </span>
      </div>
    </div>
    <div class="card-system" v-else>
      <span class="no-data">--</span>
    </div>

    <div class="card-footer">
      <span class="last-seen">{{ formatTime(node.last_seen) }}</span>
    </div>
  </div>
</template>

<script setup>
defineProps({
  node: { type: Object, required: true }
})

defineEmits(['click'])

function formatPPS(pps) {
  if (!pps || pps === 0) return '0'
  if (pps >= 1000000) return (pps / 1000000).toFixed(1) + 'M'
  if (pps >= 1000) return (pps / 1000).toFixed(1) + 'K'
  return Math.round(pps).toString()
}

function formatTime(time) {
  if (!time) return '-'
  return new Date(time).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

function progressColor(percent) {
  if (percent > 80) return '#ef4444'
  if (percent > 60) return '#f59e0b'
  return '#22c55e'
}
</script>

<style scoped>
.node-card {
  padding: 20px;
  cursor: pointer;
  transition: transform 0.2s, box-shadow 0.2s;
}

.node-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.node-name-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--danger);
  flex-shrink: 0;
}

.status-dot.online {
  background: var(--success);
  box-shadow: 0 0 8px var(--success);
}

.node-name {
  font-weight: 600;
  font-size: 1rem;
  color: var(--text);
}

.card-metrics {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 16px;
}

.metric {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.metric-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.metric-value {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text);
}

.metric-value.success {
  color: #22c55e;
}

.metric-value.danger {
  color: var(--danger);
}

.card-system {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 12px;
}

.sys-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.sys-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
  width: 32px;
  flex-shrink: 0;
}

.sys-pct {
  font-size: 0.75rem;
  font-weight: 600;
  width: 40px;
  text-align: right;
  flex-shrink: 0;
}

.no-data {
  font-size: 0.85rem;
  color: var(--text-secondary);
  opacity: 0.5;
}

.card-footer {
  border-top: 1px solid rgba(200, 200, 200, 0.15);
  padding-top: 8px;
}

.last-seen {
  font-size: 0.75rem;
  color: var(--text-secondary);
}
</style>
