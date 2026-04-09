<template>
  <div class="traffic-chart">
    <v-chart :option="chartOption" autoresize style="height: 280px" />
  </div>
</template>

<script setup>
import { computed, inject } from 'vue'
import VChart from 'vue-echarts'
import '../charts/setup'
import { themeKey } from '../composables/useTheme'

const { theme } = inject(themeKey)

const props = defineProps({
  history: { type: Array, default: () => [] }
})

const colors = computed(() => {
  const isAmber = theme.value === 'amber'
  return {
    passed: isAmber ? '#2ecc40' : '#15be53',
    passedArea: isAmber ? 'rgba(46,204,64,0.2)' : 'rgba(21,190,83,0.2)',
    dropped: isAmber ? '#d63031' : '#ef4444',
    droppedArea: isAmber ? 'rgba(214,48,49,0.2)' : 'rgba(239,68,68,0.2)',
    axis: isAmber ? '#d8d2c0' : '#e2e8f0',
    split: isAmber ? 'rgba(216,210,192,0.3)' : 'rgba(200,200,200,0.2)',
    text: isAmber ? '#7a7560' : '#64748d'
  }
})

const chartOption = computed(() => {
  const c = colors.value
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
      textStyle: { fontSize: 12, color: c.text }
    },
    grid: { left: 50, right: 16, top: 36, bottom: 24 },
    xAxis: {
      type: 'category',
      data: labels,
      boundaryGap: false,
      axisLabel: { fontSize: 10, color: c.text, interval: Math.max(Math.floor(labels.length / 6) - 1, 0) },
      axisLine: { lineStyle: { color: c.axis } }
    },
    yAxis: {
      type: 'value',
      axisLabel: { fontSize: 10, color: c.text, formatter: (v) => formatPPS(v) },
      splitLine: { lineStyle: { color: c.split } }
    },
    series: [
      {
        name: 'Passed',
        type: 'line',
        data: props.history.map(h => h.passedPPS),
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: c.passed },
        areaStyle: {
          color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [
            { offset: 0, color: c.passedArea },
            { offset: 1, color: 'rgba(0,0,0,0)' }
          ]}
        },
        itemStyle: { color: c.passed }
      },
      {
        name: 'Dropped',
        type: 'line',
        data: props.history.map(h => h.droppedPPS),
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: c.dropped },
        areaStyle: {
          color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [
            { offset: 0, color: c.droppedArea },
            { offset: 1, color: 'rgba(0,0,0,0)' }
          ]}
        },
        itemStyle: { color: c.dropped }
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
.traffic-chart { width: 100%; }
</style>
