<template>
  <div class="top-rules-chart">
    <v-chart v-if="topRules.length > 0" :option="chartOption" autoresize style="height: 300px" />
    <div v-else class="no-data">
      <span>{{ $t('dashboard.noDropData') || 'No drop data' }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import VChart from 'vue-echarts'
import '../charts/setup'

const props = defineProps({
  // Full rules array — component sorts by drop_pps internally
  rules: { type: Array, default: () => [] }
})

const emit = defineEmits(['ruleClick'])

const topRules = computed(() => {
  return [...props.rules]
    .filter(r => r.stats && r.stats.drop_pps > 0)
    .sort((a, b) => (b.stats?.drop_pps || 0) - (a.stats?.drop_pps || 0))
    .slice(0, 10)
})

const chartOption = computed(() => {
  const rules = topRules.value
  const labels = rules.map(r => {
    const src = r.src_ip || r.src_cidr || '*'
    const dst = r.dst_ip || r.dst_cidr || '*'
    const srcPort = r.src_port ? `:${r.src_port}` : ''
    const dstPort = r.dst_port ? `:${r.dst_port}` : ''
    const proto = r.protocol && r.protocol !== 'all' ? r.protocol.toUpperCase() : ''
    let label = `${src}${srcPort} → ${dst}${dstPort}`
    if (proto) label += ` [${proto}]`
    return label.length > 38 ? label.substring(0, 35) + '…' : label
  })

  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: 'rgba(30,30,30,0.9)',
      borderColor: 'transparent',
      textStyle: { color: '#fff', fontSize: 12 },
      formatter: (params) => {
        const p = params[0]
        const rule = rules[rules.length - 1 - p.dataIndex]
        const src = rule.src_ip || rule.src_cidr || '*'
        const dst = rule.dst_ip || rule.dst_cidr || '*'
        const srcPort = rule.src_port ? `:${rule.src_port}` : ''
        const dstPort = rule.dst_port ? `:${rule.dst_port}` : ''
        const proto = rule.protocol && rule.protocol !== 'all' ? rule.protocol.toUpperCase() : 'ALL'
        return `<div style="font-size:10px;color:#888;margin-bottom:2px">${rule.id}</div>` +
          `<div style="font-size:11px;color:#ccc;margin-bottom:4px">${src}${srcPort} → ${dst}${dstPort} [${proto}]</div>` +
          `<div>Drop PPS: <b>${formatPPS(rule.stats?.drop_pps)}</b></div>` +
          `<div>Drop Count: <b>${formatCount(rule.stats?.drop_count)}</b></div>`
      }
    },
    grid: {
      left: 180,
      right: 40,
      top: 8,
      bottom: 8
    },
    xAxis: {
      type: 'value',
      axisLabel: {
        fontSize: 10,
        formatter: (v) => formatPPS(v)
      },
      splitLine: { lineStyle: { color: 'rgba(200,200,200,0.15)' } }
    },
    yAxis: {
      type: 'category',
      data: labels.reverse(),
      axisLabel: {
        fontSize: 11,
        width: 160,
        overflow: 'truncate'
      },
      axisTick: { show: false }
    },
    series: [
      {
        type: 'bar',
        data: rules.map(r => r.stats?.drop_pps || 0).reverse(),
        barMaxWidth: 20,
        itemStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 1, y2: 0,
            colorStops: [
              { offset: 0, color: 'rgba(239,68,68,0.7)' },
              { offset: 1, color: 'rgba(239,68,68,1)' }
            ]
          },
          borderRadius: [0, 4, 4, 0]
        }
      }
    ]
  }
})

function formatPPS(pps) {
  if (!pps || pps === 0) return '0'
  if (pps >= 1000000) return (pps / 1000000).toFixed(1) + 'M'
  if (pps >= 1000) return (pps / 1000).toFixed(1) + 'K'
  return Math.round(pps).toString()
}

function formatCount(count) {
  if (!count || count === 0) return '0'
  if (count >= 1000000) return (count / 1000000).toFixed(1) + 'M'
  if (count >= 1000) return (count / 1000).toFixed(1) + 'K'
  return count.toString()
}
</script>

<style scoped>
.top-rules-chart {
  width: 100%;
}

.no-data {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 200px;
  color: var(--text-secondary);
  opacity: 0.5;
  font-size: 0.9rem;
}
</style>
