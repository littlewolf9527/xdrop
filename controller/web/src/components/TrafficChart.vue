<template>
  <div class="traffic-chart">
    <v-chart :option="chartOption" autoresize style="height: 280px" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import VChart from 'vue-echarts'
import '../charts/setup'

const props = defineProps({
  // Array of { passedPPS, droppedPPS } — max 60 points (3 min at 3s interval)
  history: {
    type: Array,
    default: () => []
  }
})

const chartOption = computed(() => {
  const labels = props.history.map((_, i) => {
    const secsAgo = (props.history.length - 1 - i) * 3
    return secsAgo === 0 ? 'now' : `-${secsAgo}s`
  })

  return {
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(30,30,30,0.9)',
      borderColor: 'transparent',
      textStyle: { color: '#fff', fontSize: 12 },
      formatter: (params) => {
        let html = `<div style="font-size:11px;color:#aaa">${params[0].axisValue}</div>`
        params.forEach(p => {
          html += `<div>${p.marker} ${p.seriesName}: <b>${formatPPS(p.value)}</b> pps</div>`
        })
        return html
      }
    },
    legend: {
      data: ['Passed', 'Dropped'],
      right: 16,
      top: 4,
      textStyle: { fontSize: 12 }
    },
    grid: {
      left: 50,
      right: 16,
      top: 36,
      bottom: 24
    },
    xAxis: {
      type: 'category',
      data: labels,
      boundaryGap: false,
      axisLabel: {
        fontSize: 10,
        interval: Math.max(Math.floor(labels.length / 6) - 1, 0)
      },
      axisLine: { lineStyle: { color: '#ddd' } }
    },
    yAxis: {
      type: 'value',
      axisLabel: {
        fontSize: 10,
        formatter: (v) => formatPPS(v)
      },
      splitLine: { lineStyle: { color: 'rgba(200,200,200,0.2)' } }
    },
    series: [
      {
        name: 'Passed',
        type: 'line',
        data: props.history.map(h => h.passedPPS),
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: '#22c55e' },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(34,197,94,0.25)' },
              { offset: 1, color: 'rgba(34,197,94,0.02)' }
            ]
          }
        },
        itemStyle: { color: '#22c55e' }
      },
      {
        name: 'Dropped',
        type: 'line',
        data: props.history.map(h => h.droppedPPS),
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: '#ef4444' },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(239,68,68,0.25)' },
              { offset: 1, color: 'rgba(239,68,68,0.02)' }
            ]
          }
        },
        itemStyle: { color: '#ef4444' }
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
</script>

<style scoped>
.traffic-chart {
  width: 100%;
}
</style>
