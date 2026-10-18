<script setup lang="ts">
import {
  computed
} from 'vue'
import {
  useI18n
} from 'vue-i18n'
import {
  use
} from 'echarts/core'
import {
  LineChart
} from 'echarts/charts'
import {
  GridComponent, TooltipComponent, LegendComponent
} from 'echarts/components'
import {
  CanvasRenderer
} from 'echarts/renderers'
import VChart from 'vue-echarts'
import {
  state
} from '../state'
import {
  gapPoints, bits, integerAxis, metric
} from '../metrics'
use([LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])
const props = defineProps<{
  bytes: boolean
}>(), {
  t, locale
} = useI18n()
const option = computed(() => {
  void state.theme;
  void state.now;
  void locale.value
  const style = getComputedStyle(document.documentElement), color = (k: string) => style.getPropertyValue(k).trim()
  const points = gapPoints(state.history), drop = props.bytes ? 'dropped_bytes_ps' : 'dropped_pps', pass = props.bytes ?
    'passed_bytes_ps' : 'passed_pps'
  const convert = (v: number) => props.bytes ? bits(v) : v
  const max = Math.max(0, ...state.history.points.flatMap(p => [convert(p[drop]), convert(p[pass])]))
  const axis = integerAxis(max), unit = props.bytes ? 'bps' : 'pps'
  const series = ([['drop', drop, '--drop'], ['forward', pass, '--fwd']] as const).map(([name, key, token]) => ({
    name: t(name), type: 'line', showSymbol: false, connectNulls: false, animation: false,
    data: points.map(p => [p.t * 1000, 'gap' in p ? null : convert(p[key]) / axis.scale]),
    lineStyle: {
      color: color(token), width: 1.5, opacity: props.bytes ? .72 : 1
    }, itemStyle: {
      color: color(token)
    },

  }))
  return {
    animation: false, grid: {
      left: 48, right: 14, top: 32, bottom: 28
    },
    textStyle: {
      fontFamily: 'IBM Plex Sans', color: color('--muted')
    },
    legend: {
      top: 0, right: 10, itemWidth: 12, itemHeight: 2, icon: 'rect', textStyle: {
        color: color('--muted'), fontSize: 11
      }
    },
    tooltip: {
      trigger: 'axis', confine: true, backgroundColor: color('--panel'), borderColor: color('--line'), textStyle: {
        color: color('--ink'), fontSize: 12
      },
      valueFormatter: (v: unknown) => v == null ? '—' : metric(Number(v) * axis.scale, unit),
      axisPointer: {
        type: 'line', lineStyle: {
          color: color('--muted'), type: 'dashed'
        }
      }
    },
    xAxis: {
      type: 'time', axisLine: {
        lineStyle: {
          color: color('--line')
        }
      }, axisLabel: {
        color: color('--muted'), hideOverlap: true, fontSize: 10, formatter: (v: number) => new Intl.DateTimeFormat(locale.value, ['7d',
          '30d'].includes(state.range) ? {
          month: '2-digit', day: '2-digit'
        } : {
          hour: '2-digit', minute: '2-digit', hour12: false
        }).format(v)
      }, splitLine: {
        show: false
      }
    },
    yAxis: {
      type: 'value', min: 0, max: axis.max, interval: axis.interval, axisLabel: {
        color: color('--muted'), fontSize: 10, formatter: (v: number) => v === 0 ? '0' : `${v}${axis.suffix}`
      }, splitLine: {
        lineStyle: {
          color: color('--line')
        }
      }
    }, series,
    media: [{
      query: { maxWidth: 400 },
      option: { xAxis: { splitNumber: 2, minInterval: state.history.step_s * 1000, axisLabel: { padding: [0, 4] } } }
    }, {
      option: { xAxis: { splitNumber: 6, minInterval: 0, axisLabel: { padding: 0 } } }
    }],

  }
})
</script>
<template>
  <VChart
    class="chartbox"
    :option="option"
    autoresize
   />
</template>
