<template>
  <el-dialog
    v-model="visible"
    :title="node?.name || ''"
    width="600px"
  >
    <div class="detail-content" v-if="node">
      <!-- Status -->
      <div class="detail-section">
        <h4>{{ $t('nodes.statusLabel') }}</h4>
        <div class="detail-grid">
          <div class="detail-item">
            <span class="detail-label">{{ $t('nodes.statusLabel') }}</span>
            <el-tag :type="node.status === 'online' ? 'success' : 'danger'" size="small">
              {{ node.status === 'online' ? $t('nodes.status.online') : $t('nodes.status.offline') }}
            </el-tag>
          </div>
          <div class="detail-item">
            <span class="detail-label">{{ $t('nodes.endpoint') }}</span>
            <span class="detail-value mono">{{ node.endpoint }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">{{ $t('nodes.lastSeen') }}</span>
            <span class="detail-value">{{ formatTime(node.last_seen) }}</span>
          </div>
        </div>
      </div>

      <!-- XDP Interfaces -->
      <div class="detail-section" v-if="node.stats?.xdp_info">
        <h4>XDP</h4>
        <div class="detail-grid">
          <div class="detail-item">
            <span class="detail-label">Mode</span>
            <el-tag size="small" :type="node.stats.xdp_info.mode === 'fast_forward' ? 'warning' : 'info'">
              {{ node.stats.xdp_info.mode === 'fast_forward' ? 'Fast Forward' : 'Traditional' }}
            </el-tag>
          </div>
          <div class="detail-item" v-for="iface in node.stats.xdp_info.interfaces" :key="iface.name">
            <span class="detail-label">{{ iface.role }}</span>
            <span class="detail-value mono">{{ iface.name }}</span>
          </div>
        </div>
      </div>

      <!-- Traffic Stats -->
      <div class="detail-section" v-if="node.stats">
        <h4>{{ $t('dashboard.trafficStats') || 'Traffic' }}</h4>
        <div class="detail-grid">
          <div class="detail-item">
            <span class="detail-label">{{ $t('dashboard.stats.passedPPS') }}</span>
            <span class="detail-value success">{{ formatPPS(node.stats.passed_pps) }} pps</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">{{ $t('dashboard.stats.droppedPPS') }}</span>
            <span class="detail-value danger">{{ formatPPS(node.stats.dropped_pps) }} pps</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Total PPS</span>
            <span class="detail-value">{{ formatPPS(node.stats.total_pps) }} pps</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">{{ $t('nodes.rulesCount') }}</span>
            <span class="detail-value">{{ node.stats.rules_count ?? 0 }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">{{ $t('dashboard.stats.whitelist') }}</span>
            <span class="detail-value">{{ node.stats.whitelist_count ?? 0 }}</span>
          </div>
        </div>
      </div>

      <!-- System Stats -->
      <div class="detail-section" v-if="node.stats?.system">
        <h4>{{ $t('dashboard.systemStats') || 'System' }}</h4>
        <div class="detail-grid">
          <div class="detail-item">
            <span class="detail-label">CPU</span>
            <span class="detail-value">{{ node.stats.system.cpu_percent.toFixed(1) }}%</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">{{ $t('dashboard.memory') || 'Memory' }}</span>
            <span class="detail-value">
              {{ node.stats.system.mem_used_mb }} / {{ node.stats.system.mem_total_mb }} MB
              ({{ node.stats.system.mem_percent.toFixed(1) }}%)
            </span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Load Avg</span>
            <span class="detail-value">
              {{ node.stats.system.load_avg_1 }} / {{ node.stats.system.load_avg_5 }} / {{ node.stats.system.load_avg_15 }}
            </span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Uptime</span>
            <span class="detail-value">{{ formatUptime(node.stats.system.uptime_seconds) }}</span>
          </div>
        </div>
      </div>

      <!-- Agent State -->
      <div class="detail-section" v-if="node.stats?.agent_state">
        <h4>{{ $t('dashboard.agentState') || 'Agent State' }}</h4>
        <div class="detail-grid">
          <div class="detail-item">
            <span class="detail-label">Exact Rules</span>
            <span class="detail-value">{{ node.stats.agent_state.exact_rules }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">CIDR Rules</span>
            <span class="detail-value">{{ node.stats.agent_state.cidr_rules }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Whitelist</span>
            <span class="detail-value">{{ node.stats.agent_state.whitelist_entries }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Active Slot</span>
            <span class="detail-value mono">{{ node.stats.agent_state.active_slot }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Rule Map Sel</span>
            <span class="detail-value mono">{{ node.stats.agent_state.rule_map_selector }}</span>
          </div>
        </div>
      </div>
    </div>
  </el-dialog>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  node: { type: Object, default: null }
})

const emit = defineEmits(['update:modelValue'])

// v-model on el-dialog drives visible directly; setter propagates the change
// back to the parent so close button / mask click both work correctly.
const visible = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v)
})

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

function formatUptime(seconds) {
  if (!seconds) return '-'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  if (days > 0) return `${days}d ${hours}h`
  const mins = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${mins}m`
}
</script>

<style scoped>
.detail-content {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.detail-section h4 {
  margin: 0 0 12px 0;
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--text);
  border-bottom: 1px solid rgba(200, 200, 200, 0.15);
  padding-bottom: 8px;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.detail-value {
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--text);
}

.detail-value.mono {
  font-family: 'SF Mono', monospace;
}

.detail-value.success {
  color: #22c55e;
}

.detail-value.danger {
  color: var(--danger);
}
</style>
