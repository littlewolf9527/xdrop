<template>
  <div class="traffic-gauge">
    <v-chart :option="gaugeOption" autoresize style="height: 280px" />
  </div>
</template>

<script setup>
import { computed, inject } from 'vue'
import VChart from 'vue-echarts'
import '../charts/setup'
import { themeKey } from '../composables/useTheme'

const { theme } = inject(themeKey)

const props = defineProps({
  droppedPPS: { type: Number, default: 0 },
  totalPPS: { type: Number, default: 0 }
})

const dropRate = computed(() => {
  return props.totalPPS > 0 ? (props.droppedPPS / props.totalPPS * 100) : 0
})

const gaugeColor = computed(() => {
  const isAmber = theme.value === 'amber'
  const rate = dropRate.value
  if (rate > 50) return isAmber ? '#d63031' : '#ef4444'
  if (rate > 10) return isAmber ? '#e6a23c' : '#f59e0b'
  return isAmber ? '#2ecc40' : '#15be53'
})

const gaugeOption = computed(() => ({
  series: [
    {
      type: 'gauge',
      startAngle: 220,
      endAngle: -40,
      min: 0,
      max: 100,
      radius: '90%',
      progress: {
        show: true,
        width: 14,
        roundCap: true,
        itemStyle: { color: gaugeColor.value }
      },
      pointer: { show: false },
      axisLine: {
        lineStyle: {
          width: 14,
          color: [[1, theme.value === 'amber' ? 'rgba(216,210,192,0.2)' : 'rgba(200,200,200,0.15)']]
        }
      },
      axisTick: { show: false },
      splitLine: { show: false },
      axisLabel: { show: false },
      title: {
        offsetCenter: [0, '70%'],
        fontSize: 13,
        color: theme.value === 'amber' ? '#7a7560' : '#999'
      },
      detail: {
        valueAnimation: true,
        offsetCenter: [0, '20%'],
        fontSize: 28,
        fontWeight: 700,
        formatter: (v) => v.toFixed(1) + '%',
        color: gaugeColor.value
      },
      data: [
        {
          value: Math.round(dropRate.value * 10) / 10,
          name: 'Drop Rate'
        }
      ]
    }
  ]
}))
</script>

<style scoped>
.traffic-gauge {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
}
</style>
