<script setup lang="ts">
import { ElTooltip } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import {
  useI18n
} from 'vue-i18n'
import {
  state
} from '../state'
import {
  bits, metric, percent
} from '../metrics'
import type {
  Rule
} from '../api/types'
defineProps<{
  rules: boolean
}>()
const {
  t
} = useI18n()
function description(rule: Rule | undefined, target: string) {
  if (!rule) return target
  const conditions = [rule.ttl && `TTL ${rule.ttl}`, rule.dscp && `DSCP ${rule.dscp}`, rule.icmp_type && `ICMP ${rule.icmp_type}`,
    rule.icmp_code && `ICMP ${rule.icmp_code}`, rule.fragment, rule.pkt_len && `LEN ${rule.pkt_len}`, rule.tcp_flags, rule.match_anomaly ?
      `0x${rule.match_anomaly.toString(16)}` : ''].filter(Boolean).join(' ')
  return `#${rule.logical_id} ${rule.dst_ip || rule.dst_cidr || rule.src_ip || rule.src_cidr || target} ${rule.protocol.toUpperCase()}:${
    rule.dst_port || rule.src_port || '*'} ${conditions}`
}
</script>
<template>
  <div
    class="tbl-wrap"
  >
    <table
      class="top-table"
    >
      <colgroup><col style="width: var(--top-rank)"><col><col style="width: var(--top-rate)"><col style="width: var(--top-rate)"><col style="width: var(--top-share)"><col style="width: var(--top-action)"></colgroup>
      <thead>
        <tr>
          <th>#</th>
          <th>{{ t('target') }}</th>
          <th
            class="r"
          >pps</th>
          <th
            class="r"
          >bps</th>
          <th
            class="r"
          ><ElTooltip :content="t('shareHelp')" :trigger="['hover', 'click']" popper-class="rule-help-popover"><button type="button" class="rule-help" :aria-label="t('share') + ' ' + t('explanation')"><QuestionFilled aria-hidden="true" /></button></ElTooltip>{{ t('share') }}</th>
          <th />
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="(row, index) in (rules ? state.top.rules : state.top.targets).slice(0, 5)"
          :key="'rule_id' in row ? String(row.rule_id) : row.target"
        >
          <td
            class="rk"
          >{{ index + 1 }}</td>
          <td
            class="heat mono"
            :style="{ '--w': Math.min(100, Math.max(0, (row.share ?? 0) * 100)) + '%' }"
          >
            <span
              :title="rules && 'rule_id' in row ? description(state.rules[String(row.rule_id)], row.target) : row.target"
            >{{ rules && 'rule_id' in row ? description(state.rules[String(row.rule_id)], row.target) : row.target }}</span>
          </td>
          <td
            class="r num c-drop"
          >{{ metric(row.dropped_pps) }}</td>
          <td
            class="r num c-drop b"
          >{{ metric(bits(row.dropped_bytes_ps)) }}</td>
          <td
            class="r num muted"
          >{{ percent(row.share) }}</td>
          <td>
            <span
              v-if="rules && 'rule_id' in row && state.rules[String(row.rule_id)]"
              class="tag"
              :class="state.rules[String(row.rule_id)]?.action === 'drop' ? 'drop' : 'rate'"
            >{{ t(state.rules[String(row.rule_id)]?.action === 'drop' ? 'dropAction' : 'rateAction') }}</span>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
