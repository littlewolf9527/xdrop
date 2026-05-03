<template>
  <div class="rules-page">
    <!-- Toolbar -->
    <div class="toolbar xs-card fade-in">
      <div class="toolbar-left">
        <el-input
          v-model="search"
          :placeholder="$t('rules.searchPlaceholder')"
          clearable
          class="search-input"
        >
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
      </div>
      <div class="toolbar-right">
        <span class="refresh-hint" v-if="!loading">{{ $t('dashboard.autoRefresh', { n: refreshInterval/1000 }) }}</span>
        <el-button type="primary" @click="showAddDialog" round>
          <el-icon><Plus /></el-icon>
          {{ $t('rules.addRule') }}
        </el-button>
        <el-button @click="showBatchDialog" round>
          <el-icon><DocumentAdd /></el-icon>
          {{ $t('rules.batchAdd') }}
        </el-button>
        <el-button
          type="danger"
          @click="batchDelete"
          :disabled="!selectedIds.length"
          round
        >
          <el-icon><Delete /></el-icon>
          {{ $t('rules.deleteSelected', { n: selectedIds.length }) }}
        </el-button>
      </div>
    </div>

    <!-- Rule list -->
    <div class="table-container xs-card fade-in" style="animation-delay: 0.1s">
      <el-table
        :data="rules"
        v-loading="loading"
        @selection-change="handleSelectionChange"
      >
        <el-table-column type="selection" width="50" />
        <el-table-column prop="id" :label="$t('table.id')" width="130">
          <template #default="{ row }">
            <span class="rule-id">{{ row.id }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.source')" min-width="160">
          <template #default="{ row }">
            <div class="ip-cell">
              <el-tag v-if="row.src_cidr" type="info" size="small" class="cidr-tag">CIDR</el-tag>
              <span class="ip">{{ row.src_cidr || row.src_ip || '*' }}</span>
              <span class="port" v-if="row.src_port">:{{ row.src_port }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.destination')" min-width="160">
          <template #default="{ row }">
            <div class="ip-cell">
              <el-tag v-if="row.dst_cidr" type="info" size="small" class="cidr-tag">CIDR</el-tag>
              <span class="ip">{{ row.dst_cidr || row.dst_ip || '*' }}</span>
              <span class="port" v-if="row.dst_port">:{{ row.dst_port }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="protocol" :label="$t('table.protocol')" width="80" align="center">
          <template #default="{ row }">
            <span class="protocol-badge">{{ row.protocol || 'ALL' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="action" :label="$t('table.action')" width="100" align="center">
          <template #default="{ row }">
            <el-tag :type="row.action === 'drop' ? 'danger' : 'warning'" size="small">
              {{ row.action === 'drop' ? 'DROP' : 'LIMIT' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.pktLen')" width="120" align="center">
          <template #default="{ row }">
            <span v-if="row.pkt_len_min || row.pkt_len_max" class="pkt-len">
              {{ row.pkt_len_min || '*' }} - {{ row.pkt_len_max || '*' }}
            </span>
            <span v-else class="no-filter">-</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.tcpFlags')" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.tcp_flags" size="small" type="info">{{ row.tcp_flags }}</el-tag>
            <span v-else class="no-filter">-</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.decoder')" width="130">
          <template #default="{ row }">
            <template v-if="row.match_anomaly">
              <el-tag v-if="row.match_anomaly & 1" size="small" type="danger" effect="dark" style="margin-right:2px">bad_frag</el-tag>
              <el-tag v-if="row.match_anomaly & 2" size="small" type="warning" effect="dark">invalid</el-tag>
            </template>
            <span v-else class="no-filter">-</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.matchCount')" width="140">
          <template #default="{ row }">
            <!--
              v2.6.3 stats column rendering:
                - row.stats present → show the number, optionally with a
                  per-row badge that mirrors the cluster-level statsStatus.
                - row.stats missing → show the contextual placeholder for
                  the current cluster status, NOT a bare "-".
              The cluster status drives whether a missing row.stats means
              "loading", "disabled", "stuck", etc. Without that context the
              UI would be ambiguous (round-2 P2-3).
            -->
            <div v-if="row.stats" class="stats-cell match-stats">
              <span class="match-count">{{ formatCount(row.stats.match_count) }}</span>
              <span v-if="statsRowBadge" class="row-badge" :class="statsRowBadgeClass">{{ $t(statsRowBadge) }}</span>
            </div>
            <span v-else class="no-stats" :class="missingStatsClass">{{ $t(missingStatsKey) }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.dropPPS')" width="160">
          <template #default="{ row }">
            <div v-if="row.stats" class="stats-cell">
              <span class="pps">{{ formatPPS(row.stats.drop_pps) }} pps</span>
              <span class="total">({{ formatCount(row.stats.drop_count) }})</span>
            </div>
            <span v-else class="no-stats" :class="missingStatsClass">{{ $t(missingStatsKey) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="comment" :label="$t('table.comment')" min-width="150">
          <template #default="{ row }">
            <span class="comment-text">{{ row.comment || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.operations')" width="130" fixed="right" align="center">
          <template #default="{ row }">
            <el-button
              type="primary"
              size="small"
              @click="showEditDialog(row)"
              circle
              style="margin-right:4px"
            >
              <el-icon><Edit /></el-icon>
            </el-button>
            <el-button
              type="danger"
              size="small"
              @click="deleteRule(row.id)"
              circle
            >
              <el-icon><Delete /></el-icon>
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- Pagination -->
      <div class="pagination-container" v-if="totalRules > 0">
        <span class="pagination-total">{{ $t('rules.totalRules', { n: totalRules }) }}</span>
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[20, 50, 100, 200]"
          :total="totalRules"
          layout="sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="handlePageChange"
        />
      </div>
    </div>

    <!-- Add rule dialog -->
    <el-dialog v-model="dialogVisible" :title="$t('dialog.addRule')" width="520px" center>
      <el-form :model="form" label-width="80px">
        <el-form-item :label="$t('table.source')">
          <div class="addr-field">
            <el-radio-group v-model="form.src_mode" size="small" class="addr-mode-toggle">
              <el-radio-button value="ip">IP</el-radio-button>
              <el-radio-button value="cidr">CIDR</el-radio-button>
            </el-radio-group>
            <el-input
              v-if="form.src_mode === 'ip'"
              v-model="form.src_ip"
              :placeholder="$t('placeholder.leaveEmptyForAny')"
              class="addr-input"
            />
            <el-input
              v-else
              v-model="form.src_cidr"
              :placeholder="$t('placeholder.cidrExample')"
              class="addr-input"
            />
          </div>
        </el-form-item>
        <el-form-item :label="$t('table.destination')">
          <div class="addr-field">
            <el-radio-group v-model="form.dst_mode" size="small" class="addr-mode-toggle">
              <el-radio-button value="ip">IP</el-radio-button>
              <el-radio-button value="cidr">CIDR</el-radio-button>
            </el-radio-group>
            <el-input
              v-if="form.dst_mode === 'ip'"
              v-model="form.dst_ip"
              :placeholder="$t('placeholder.leaveEmptyForAny')"
              class="addr-input"
            />
            <el-input
              v-else
              v-model="form.dst_cidr"
              :placeholder="$t('placeholder.cidrExample')"
              class="addr-input"
            />
          </div>
        </el-form-item>
        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item :label="$t('rules.form.srcPort')">
              <el-input-number v-model="form.src_port" :min="0" :max="65535" style="width: 100%"
                               :disabled="isPortlessProtocol(form.protocol)" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="$t('rules.form.dstPort')">
              <el-input-number v-model="form.dst_port" :min="0" :max="65535" style="width: 100%"
                               :disabled="isPortlessProtocol(form.protocol)" />
            </el-form-item>
          </el-col>
        </el-row>
        <div v-if="isPortlessProtocol(form.protocol)" class="form-hint" style="margin-top: -8px; margin-bottom: 12px; color: var(--xs-warning, #e6a23c);">
          {{ $t('messages.portlessProtocolNoPort') }}
        </div>
        <el-form-item :label="$t('rules.form.protocol')">
          <el-select v-model="form.protocol" :placeholder="$t('rules.protocols.all')" style="width: 100%"
                     :disabled="!!form.decoder">
            <el-option :label="$t('rules.protocols.all')" value="" />
            <el-option :label="$t('rules.protocols.tcp')" value="tcp" />
            <el-option :label="$t('rules.protocols.udp')" value="udp" />
            <el-option :label="$t('rules.protocols.icmp')" value="icmp" />
            <el-option :label="$t('rules.protocols.icmpv6')" value="icmpv6" />
            <el-option :label="$t('rules.protocols.igmp')" value="igmp" />
            <el-option :label="$t('rules.protocols.gre')" value="gre" />
            <el-option :label="$t('rules.protocols.esp')" value="esp" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('rules.form.decoder')">
          <el-select v-model="form.decoder" :placeholder="$t('rules.decoders.none')" clearable style="width: 100%">
            <el-option :label="$t('rules.decoders.none')" value="" />
            <el-option label="tcp_ack" value="tcp_ack" />
            <el-option label="tcp_rst" value="tcp_rst" />
            <el-option label="tcp_fin" value="tcp_fin" />
            <el-option label="bad_fragment" value="bad_fragment" />
            <el-option label="invalid" value="invalid" />
          </el-select>
          <div class="form-hint">{{ $t('messages.decoderHint') }}</div>
        </el-form-item>
        <el-form-item :label="$t('rules.form.action')">
          <el-radio-group v-model="form.action">
            <el-radio-button value="drop">{{ $t('rules.actions.drop') }}</el-radio-button>
            <el-radio-button value="rate_limit"
              :disabled="form.decoder === 'bad_fragment' || form.decoder === 'invalid'">
              {{ $t('rules.actions.rateLimit') }}
            </el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.action === 'rate_limit'" :label="$t('rules.form.rateLimit')">
          <el-input-number v-model="form.rate_limit" :min="1" :max="1000000" /> pps
        </el-form-item>
        <el-form-item :label="$t('rules.form.pktLenRange')">
          <el-row :gutter="10" align="middle">
            <el-col :span="10">
              <el-input-number v-model="form.pkt_len_min" :min="0" :max="65535" placeholder="Min" controls-position="right" style="width: 100%" />
            </el-col>
            <el-col :span="4" style="text-align: center; color: var(--xs-text-secondary);">-</el-col>
            <el-col :span="10">
              <el-input-number v-model="form.pkt_len_max" :min="0" :max="65535" placeholder="Max" controls-position="right" style="width: 100%" />
            </el-col>
          </el-row>
          <div class="form-hint">{{ $t('messages.pktLenHint') }}</div>
        </el-form-item>
        <el-form-item v-if="form.protocol === 'tcp' && !form.decoder" :label="$t('rules.form.tcpFlags')">
          <el-input v-model="form.tcp_flags" placeholder="e.g. SYN,!ACK" />
          <div class="form-hint">{{ $t('messages.tcpFlagsHint') }}</div>
        </el-form-item>
        <el-form-item :label="$t('rules.form.comment')">
          <el-input v-model="form.comment" :placeholder="$t('placeholder.optional')" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false" round>{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="addRule" :loading="submitting" round>{{ $t('common.add') }}</el-button>
      </template>
    </el-dialog>

    <!-- Edit rule dialog -->
    <el-dialog v-model="editDialogVisible" :title="$t('dialog.editRule')" width="520px" center>
      <el-form :model="editForm" label-width="80px">
        <!-- Read-only key fields -->
        <el-form-item :label="$t('table.source')">
          <span class="edit-readonly">{{ editRow.src_cidr || editRow.src_ip || '*' }}{{ editRow.src_port ? ':' + editRow.src_port : '' }}</span>
        </el-form-item>
        <el-form-item :label="$t('table.destination')">
          <span class="edit-readonly">{{ editRow.dst_cidr || editRow.dst_ip || '*' }}{{ editRow.dst_port ? ':' + editRow.dst_port : '' }}</span>
        </el-form-item>
        <el-form-item :label="$t('table.protocol')">
          <span class="edit-readonly">{{ editRow.protocol || 'ALL' }}</span>
        </el-form-item>
        <el-divider />
        <!-- Editable fields -->
        <el-form-item :label="$t('rules.form.decoder')">
          <el-select v-model="editForm.decoder" :placeholder="$t('rules.decoders.none')" clearable style="width: 100%">
            <el-option :label="$t('rules.decoders.none')" value="" />
            <!-- R6-002: tcp_* decoders disabled when existing rule is anomaly-typed.
                 match_anomaly's int schema can't be explicit-cleared via PUT, so the
                 backend would reject. Force the user to delete+recreate. -->
            <el-option label="tcp_ack" value="tcp_ack" :disabled="editRow.protocol !== 'tcp' || !!editRow.match_anomaly" />
            <el-option label="tcp_rst" value="tcp_rst" :disabled="editRow.protocol !== 'tcp' || !!editRow.match_anomaly" />
            <el-option label="tcp_fin" value="tcp_fin" :disabled="editRow.protocol !== 'tcp' || !!editRow.match_anomaly" />
            <el-option label="bad_fragment" value="bad_fragment" />
            <el-option label="invalid" value="invalid" />
          </el-select>
          <div class="form-hint">{{ $t('messages.decoderHint') }}</div>
          <div v-if="editRow.match_anomaly" class="form-hint" style="color: var(--xs-warning, #e6a23c);">
            {{ $t('messages.anomalyToTcpRequiresRecreate') }}
          </div>
        </el-form-item>
        <el-form-item :label="$t('rules.form.action')">
          <el-radio-group v-model="editForm.action">
            <el-radio-button value="drop">{{ $t('rules.actions.drop') }}</el-radio-button>
            <el-radio-button value="rate_limit"
              :disabled="editForm.decoder === 'bad_fragment' || editForm.decoder === 'invalid'">
              {{ $t('rules.actions.rateLimit') }}
            </el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="editForm.action === 'rate_limit'" :label="$t('rules.form.rateLimit')">
          <el-input-number v-model="editForm.rate_limit" :min="1" :max="1000000" /> pps
        </el-form-item>
        <el-form-item :label="$t('rules.form.pktLenRange')">
          <el-row :gutter="10" align="middle">
            <el-col :span="10">
              <el-input-number v-model="editForm.pkt_len_min" :min="0" :max="65535" controls-position="right" style="width: 100%" />
            </el-col>
            <el-col :span="4" style="text-align: center; color: var(--xs-text-secondary);">-</el-col>
            <el-col :span="10">
              <el-input-number v-model="editForm.pkt_len_max" :min="0" :max="65535" controls-position="right" style="width: 100%" />
            </el-col>
          </el-row>
          <div class="form-hint">{{ $t('messages.pktLenHint') }} {{ $t('messages.pktLenEditHint') }}</div>
        </el-form-item>
        <el-form-item v-if="editRow.protocol === 'tcp' && !editForm.decoder" :label="$t('rules.form.tcpFlags')">
          <el-input v-model="editForm.tcp_flags" :placeholder="$t('placeholder.clearToRemove')" />
          <div class="form-hint">{{ $t('messages.tcpFlagsHint') }}</div>
        </el-form-item>
        <el-form-item :label="$t('rules.form.comment')">
          <el-input v-model="editForm.comment" :placeholder="$t('placeholder.optional')" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editDialogVisible = false" round>{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="updateRule" :loading="submitting" round>{{ $t('common.save') }}</el-button>
      </template>
    </el-dialog>

    <!-- Batch add dialog -->
    <el-dialog v-model="batchDialogVisible" :title="$t('dialog.batchAddRule')" width="600px" center>
      <el-alert
        :title="$t('rules.batchHint')"
        type="info"
        :closable="false"
        style="margin-bottom: 16px"
      />
      <el-form :model="batchForm" label-width="100px">
        <el-form-item :label="$t('rules.ipList')">
          <el-input
            v-model="batchForm.ips"
            type="textarea"
            :rows="8"
            :placeholder="$t('placeholder.ipListHint')"
          />
        </el-form-item>
        <el-form-item :label="$t('rules.form.protocol')">
          <el-select v-model="batchForm.protocol" :placeholder="$t('rules.protocols.all')" style="width: 200px">
            <el-option :label="$t('rules.protocols.all')" value="" />
            <el-option :label="$t('rules.protocols.tcp')" value="tcp" />
            <el-option :label="$t('rules.protocols.udp')" value="udp" />
            <el-option :label="$t('rules.protocols.icmp')" value="icmp" />
            <el-option :label="$t('rules.protocols.icmpv6')" value="icmpv6" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('rules.form.ipType')">
          <el-radio-group v-model="batchForm.type">
            <el-radio-button value="src">{{ $t('rules.ipType.src') }}</el-radio-button>
            <el-radio-button value="dst">{{ $t('rules.ipType.dst') }}</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('rules.form.action')">
          <el-radio-group v-model="batchForm.action">
            <el-radio-button value="drop">{{ $t('rules.actions.drop') }}</el-radio-button>
            <el-radio-button value="rate_limit">{{ $t('rules.actions.rateLimit') }}</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="batchForm.action === 'rate_limit'" :label="$t('rules.form.rateLimit')">
          <el-input-number v-model="batchForm.rate_limit" :min="1" :max="1000000" /> pps
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="batchDialogVisible = false" round>{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="batchAdd" :loading="submitting" round>
          {{ $t('common.add') }} ({{ parsedIPs.length }})
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { rulesApi } from '../api'

const { t } = useI18n()

const loading = ref(false)
const submitting = ref(false)
const rules = ref([])
const search = ref('')
const selectedIds = ref([])
const dialogVisible = ref(false)
const batchDialogVisible = ref(false)
const editDialogVisible = ref(false)
const editRow = ref({})
const editForm = ref({ decoder: '', action: 'drop', rate_limit: 1000, pkt_len_min: 0, pkt_len_max: 0, tcp_flags: '', comment: '' })
const refreshInterval = 5000 // refresh every 5 seconds
let refreshTimer = null

// Pagination state
const currentPage = ref(1)
const pageSize = ref(50)
const totalRules = ref(0)

// v2.6.3: cluster-level stats meta from /api/v1/rules?page=... response.
// Drives the table's "loading / disabled / stuck" placeholders so a missing
// per-row .stats no longer shows a bare "-" when the meaning is actually
// "stats cache hasn't refreshed yet". See D.4 contract table.
const statsMeta = ref({
  status: '',
  freshnessMs: null,
  nodeFailures: {},
  offlineNodes: [],
  unknownNodes: [],
  syncingNodes: []
})

// Missing-stats placeholder: when row.stats is undefined, what should the
// cell show? Maps the cluster stats_status to an i18n key. Defaults back
// to "-" (legacy "stats.noStats") for older Controllers that don't return
// stats_status, or for the rare case the meta hasn't loaded yet.
//
// Note partial / partial_stale are intentional cases here: backend now
// (after round-N P2 fix) omits stats for rules whose only data was a
// zero-value entry from a succeeded node, because under partial we can't
// tell if absent nodes had hits. Falling back to a bare "-" would hide
// that nuance — operators can't distinguish "rule has no data because we
// haven't heard from it yet" from "rule had hits we couldn't aggregate".
const missingStatsKey = computed(() => {
  switch (statsMeta.value.status) {
    case 'initializing':       return 'stats.initializing'
    case 'waiting_for_health': return 'stats.waitingForHealth'
    case 'no_nodes':           return 'stats.noNodes'
    case 'failed_no_snapshot': return 'stats.failedNoSnapshot'
    case 'disabled':           return 'stats.disabled'
    case 'partial':            return 'stats.partialMissingShort'
    case 'partial_stale':      return 'stats.partialStaleMissingShort'
    case 'stale':              return 'stats.staleMissingShort'
    case 'failed':             return 'stats.failedMissingShort'
    default:                   return 'stats.noStats'
  }
})

const missingStatsClass = computed(() => {
  switch (statsMeta.value.status) {
    case 'failed_no_snapshot':
    case 'failed':
    case 'partial_stale':      return 'is-error'
    case 'disabled':
    case 'no_nodes':           return 'is-muted'
    case 'partial':
    case 'stale':              return 'is-warn'
    default:                   return ''
  }
})

// Per-row badge: when the cluster is partial/stale we tag every visible
// row so users don't read "match=10" as "definitely 10 across the cluster".
const statsRowBadge = computed(() => {
  switch (statsMeta.value.status) {
    case 'partial':       return 'stats.badgePartialShort'
    case 'partial_stale': return 'stats.badgePartialStaleShort'
    case 'stale':         return 'stats.badgeStaleShort'
    case 'failed':        return 'stats.badgeFailedShort'
    default:              return ''
  }
})

const statsRowBadgeClass = computed(() => {
  switch (statsMeta.value.status) {
    case 'partial':       return 'badge-warn'
    case 'partial_stale': return 'badge-error'
    case 'stale':         return 'badge-warn'
    case 'failed':        return 'badge-error'
    default:              return ''
  }
})

// captureStatsMeta extracts the 6 v2.6.3 meta fields from any rules-list
// response. Used by both refresh() and refreshStatsOnly() so the meta
// stays in sync regardless of which code path landed last.
const captureStatsMeta = (data) => {
  statsMeta.value = {
    status: data?.stats_status || '',
    freshnessMs: data?.stats_freshness_ms ?? null,
    nodeFailures: data?.stats_node_failures || {},
    offlineNodes: data?.stats_offline_nodes || [],
    unknownNodes: data?.stats_unknown_nodes || [],
    syncingNodes: data?.stats_syncing_nodes || []
  }
}

// Search debounce
let searchDebounceTimer = null

const form = ref({
  src_mode: 'ip',
  dst_mode: 'ip',
  src_ip: '',
  dst_ip: '',
  src_cidr: '',
  dst_cidr: '',
  src_port: 0,
  dst_port: 0,
  protocol: '',
  decoder: '',
  action: 'drop',
  rate_limit: 1000,
  pkt_len_min: 0,
  pkt_len_max: 0,
  tcp_flags: '',
  comment: ''
})

const batchForm = ref({
  ips: '',
  protocol: '',
  type: 'src',
  action: 'drop',
  rate_limit: 1000
})

const parsedIPs = computed(() => {
  return batchForm.value.ips
    .split('\n')
    .map(ip => ip.trim())
    .filter(ip => ip.length > 0)
})

// Build paginated request params
const buildListParams = () => {
  const params = { page: currentPage.value, limit: pageSize.value }
  if (search.value) params.search = search.value
  return params
}

const refresh = async () => {
  loading.value = true
  try {
    const data = await rulesApi.list(buildListParams())
    rules.value = data.rules || []
    totalRules.value = data.count || 0
    captureStatsMeta(data)
  } catch (e) {
    console.error('Failed to load rules:', e)
  } finally {
    loading.value = false
  }
}

// Lightweight refresh: update stats only, preserve selection state.
//
// v2.6.3 fix (round-3 P2-4): the previous version only mutated rule.stats
// when the new response carried a stats key. That meant transitions like
// ok → disabled or ok → failed_no_snapshot left the OLD stat numbers
// visible — the row would show "match=42" while the cluster was actually
// "stats disabled". Now we ALWAYS overwrite (or delete) rule.stats so the
// table accurately reflects the current cluster state.
const refreshStatsOnly = async () => {
  if (rules.value.length === 0) {
    await refresh()
    return
  }

  try {
    const data = await rulesApi.list(buildListParams())
    const newRules = data.rules || []
    const newCount = data.count || 0
    captureStatsMeta(data)

    const currentIds = rules.value.map(r => r.id).join(',')
    const newIds = newRules.map(r => r.id).join(',')

    if (newCount !== totalRules.value || currentIds !== newIds) {
      rules.value = newRules
      totalRules.value = newCount
      return
    }

    // Reconcile stats UNCONDITIONALLY: if the new response omits .stats
    // for a rule (e.g. cluster flipped to disabled), strip the stale
    // numbers from our cached row.
    const newRulesMap = new Map(newRules.map(r => [r.id, r]))
    rules.value.forEach(rule => {
      const newRule = newRulesMap.get(rule.id)
      if (!newRule) return
      if (newRule.stats) {
        rule.stats = newRule.stats
      } else if (rule.stats) {
        delete rule.stats
      }
    })
  } catch (e) {
    console.error('Failed to refresh stats:', e)
  }
}

// Pagination event handlers
const handlePageChange = (page) => {
  currentPage.value = page
  refresh()
}

const handleSizeChange = (size) => {
  pageSize.value = size
  currentPage.value = 1
  refresh()
}

// B-10: portless protocols (icmp/icmpv6/igmp/gre/esp) cannot carry ports —
// the BPF datapath only fills key.src_port/dst_port for TCP/UDP. Disable
// port inputs and auto-clear when one of these is selected. Backend also
// rejects the request for safety.
const PORTLESS_PROTOCOLS = ['icmp', 'icmpv6', 'igmp', 'gre', 'esp']
const isPortlessProtocol = (proto) => PORTLESS_PROTOCOLS.includes(proto)

watch(() => form.value.protocol, (newVal) => {
  if (isPortlessProtocol(newVal)) {
    form.value.src_port = 0
    form.value.dst_port = 0
  }
})

// B-4: decoder selection clears and locks coupled fields
watch(() => form.value.decoder, (newVal) => {
  if (!newVal) return
  // All decoders: clear tcp_flags (backend mutual-exclusion rejects decoder + tcp_flags)
  form.value.tcp_flags = ''
  if (newVal === 'tcp_ack' || newVal === 'tcp_rst' || newVal === 'tcp_fin') {
    // tcp_* sugar maps to protocol=tcp; lock visually
    form.value.protocol = 'tcp'
  } else {
    // anomaly sugar (bad_fragment / invalid): backend also rejects decoder + protocol
    form.value.protocol = ''
  }
  // B-5: anomaly decoders do not support rate_limit
  if ((newVal === 'bad_fragment' || newVal === 'invalid') && form.value.action === 'rate_limit') {
    form.value.action = 'drop'
  }
})

// B-9: same decoder watcher for edit dialog
watch(() => editForm.value.decoder, (newVal) => {
  if (!newVal) return
  editForm.value.tcp_flags = ''
  if (newVal === 'tcp_ack' || newVal === 'tcp_rst' || newVal === 'tcp_fin') {
    // tcp_* only valid on tcp rules; protocol is read-only in edit, so
    // this option is already disabled when editRow.protocol !== 'tcp'
  } else {
    // anomaly sugar: clear tcp_flags only (protocol is read-only in edit)
  }
  if ((newVal === 'bad_fragment' || newVal === 'invalid') && editForm.value.action === 'rate_limit') {
    editForm.value.action = 'drop'
  }
})

// Helpers for anomaly target validation
const isWildcardIP = (s) => !s || s === '0.0.0.0' || s === '::'
// Match default routes including non-canonical forms: 0.0.0.0/0, 0.0.0.0/00, ::/0, ::/00, etc.
const isDefaultRouteCIDR = (s) => {
  if (!s) return true
  const trimmed = s.trim()
  const slashIdx = trimmed.lastIndexOf('/')
  if (slashIdx < 0) return false
  const prefix = trimmed.slice(slashIdx + 1).trim()
  return Number(prefix) === 0
}

// Search debounce: reset to page 1 and fetch after 300ms
watch(search, () => {
  if (searchDebounceTimer) clearTimeout(searchDebounceTimer)
  searchDebounceTimer = setTimeout(() => {
    currentPage.value = 1
    refresh()
  }, 300)
})

const showEditDialog = (row) => {
  editRow.value = row
  // Pre-populate with current values; decoder is not returned by API (it's sugar),
  // so leave decoder empty — user can optionally re-apply sugar on save.
  editForm.value = {
    decoder: '',
    action: row.action || 'drop',
    rate_limit: row.rate_limit || 1000,
    pkt_len_min: row.pkt_len_min || 0,
    pkt_len_max: row.pkt_len_max || 0,
    tcp_flags: row.tcp_flags || '',
    comment: row.comment || ''
  }
  editDialogVisible.value = true
}

const updateRule = async () => {
  const f = editForm.value
  const row = editRow.value

  // P3: Pre-validate anomaly constraints based on existing target (key fields are read-only).
  // Equivalent to addRule's B-5/B-6/B-7 checks; spares user a round-trip on common errors.
  const isAnomaly = f.decoder === 'bad_fragment' || f.decoder === 'invalid'
  if (isAnomaly && f.action === 'rate_limit') {
    ElMessage.error(t('messages.anomalyNoRateLimit'))
    return
  }
  if (isAnomaly) {
    const srcTarget = row.src_cidr || row.src_ip
    const dstTarget = row.dst_cidr || row.dst_ip
    const srcWild = !srcTarget || (row.src_cidr ? isDefaultRouteCIDR(srcTarget) : isWildcardIP(srcTarget))
    const dstWild = !dstTarget || (row.dst_cidr ? isDefaultRouteCIDR(dstTarget) : isWildcardIP(dstTarget))
    if (srcWild && dstWild) {
      ElMessage.error(t('messages.anomalyRequiresTarget'))
      return
    }
    if (f.decoder === 'bad_fragment') {
      const v6Like = (s) => s && s.includes(':')
      if (v6Like(srcTarget) || v6Like(dstTarget)) {
        ElMessage.error(t('messages.badFragmentNoIPv6'))
        return
      }
    }
  }

  const data = {}

  // Only send fields that actually changed or are explicitly being set
  data.action = f.action
  if (f.action === 'rate_limit') data.rate_limit = f.rate_limit

  // Always send pkt_len fields so the backend pointer tri-state can
  // distinguish "clear to 0" from "omit/keep". Sending 0 clears an
  // existing filter; sending >0 sets a new one.
  data.pkt_len_min = f.pkt_len_min
  data.pkt_len_max = f.pkt_len_max

  if (f.decoder) {
    data.decoder = f.decoder
    // R6-001: when applying any decoder we must explicitly clear tcp_flags so
    // backend Update doesn't preserve the existing value. The decoder will
    // re-apply its own tcp_flags expansion (tcp_*) or leave empty (anomaly).
    // normalizeDecoder allows decoder + tcp_flags="" (only non-empty triggers
    // mutual-exclusion).
    data.tcp_flags = ''
  } else {
    // tcp_flags: send empty string to clear, or value to set
    // Only send if protocol is tcp (backend validates)
    if (editRow.value.protocol === 'tcp') {
      data.tcp_flags = f.tcp_flags  // "" = clear, "RST" = set
    }
  }

  if (f.comment !== (editRow.value.comment || '')) {
    data.comment = f.comment
  }

  submitting.value = true
  try {
    const resp = await rulesApi.update(editRow.value.id, data)
    if (resp.sync && resp.sync.failed > 0) {
      const nodes = Object.keys(resp.sync.errors || {}).join(', ')
      ElMessage.warning(t('messages.partialSync', {
        failed: resp.sync.failed, total: resp.sync.total, nodes
      }))
    } else {
      ElMessage.success(t('messages.updateSuccess'))
    }
    editDialogVisible.value = false
    refresh()
  } catch (e) {
    ElMessage.error(t('messages.updateFailed') + ': ' + (e.response?.data?.error || e.message))
  } finally {
    submitting.value = false
  }
}

const showAddDialog = () => {
  form.value = {
    src_mode: 'ip', dst_mode: 'ip',
    src_ip: '', dst_ip: '', src_cidr: '', dst_cidr: '',
    src_port: 0, dst_port: 0, protocol: '', decoder: '', action: 'drop',
    rate_limit: 1000, pkt_len_min: 0, pkt_len_max: 0, tcp_flags: '', comment: ''
  }
  dialogVisible.value = true
}

const showBatchDialog = () => {
  batchForm.value = { ips: '', protocol: '', type: 'src', action: 'drop', rate_limit: 1000 }
  batchDialogVisible.value = true
}

const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^[0-9a-fA-F:]+\/\d{1,3}$/

const addRule = async () => {
  const f = form.value

  // Validate CIDR format
  if (f.src_mode === 'cidr' && f.src_cidr && !cidrRegex.test(f.src_cidr)) {
    ElMessage.error(t('messages.invalidCIDR'))
    return
  }
  if (f.dst_mode === 'cidr' && f.dst_cidr && !cidrRegex.test(f.dst_cidr)) {
    ElMessage.error(t('messages.invalidCIDR'))
    return
  }

  // Frontend validation: pure-length rules are not allowed
  const hasLengthFilter = f.pkt_len_min > 0 || f.pkt_len_max > 0
  const has5Tuple = (f.src_mode === 'ip' ? f.src_ip : f.src_cidr) ||
                    (f.dst_mode === 'ip' ? f.dst_ip : f.dst_cidr) ||
                    f.src_port || f.dst_port ||
                    (f.protocol && f.protocol !== 'all')

  if (hasLengthFilter && !has5Tuple) {
    ElMessage.error(t('messages.pktLenOnlyNotAllowed'))
    return
  }

  // Validate length range
  if (f.pkt_len_min > 0 && f.pkt_len_max > 0 && f.pkt_len_min > f.pkt_len_max) {
    ElMessage.error(t('messages.invalidLenRange'))
    return
  }

  // B-7: reject CIDR written into IP field
  const srcVal = f.src_mode === 'ip' ? f.src_ip : ''
  const dstVal = f.dst_mode === 'ip' ? f.dst_ip : ''
  if ((srcVal && srcVal.includes('/')) || (dstVal && dstVal.includes('/'))) {
    ElMessage.error(t('messages.cidrInIPField'))
    return
  }

  const isAnomaly = f.decoder === 'bad_fragment' || f.decoder === 'invalid'
  const srcTarget = f.src_mode === 'ip' ? f.src_ip : f.src_cidr
  const dstTarget = f.dst_mode === 'ip' ? f.dst_ip : f.dst_cidr

  // B-6: anomaly rules need a bounded (non-wildcard) target
  const srcIsWild = f.src_mode === 'ip' ? isWildcardIP(srcTarget) : isDefaultRouteCIDR(srcTarget)
  const dstIsWild = f.dst_mode === 'ip' ? isWildcardIP(dstTarget) : isDefaultRouteCIDR(dstTarget)
  if (isAnomaly && (!srcTarget && !dstTarget)) {
    ElMessage.error(t('messages.anomalyRequiresTarget'))
    return
  }
  if (isAnomaly && ((srcTarget && srcIsWild) || (dstTarget && dstIsWild))) {
    ElMessage.error(t('messages.anomalyRequiresTarget'))
    return
  }

  // B-5: anomaly + rate_limit (belt-and-suspenders, watcher already prevents this)
  if (isAnomaly && f.action === 'rate_limit') {
    ElMessage.error(t('messages.anomalyNoRateLimit'))
    return
  }

  // B-7: bad_fragment + IPv6 target
  const isIPv6 = (s) => s && s.includes(':')
  if (f.decoder === 'bad_fragment' && (isIPv6(srcTarget) || isIPv6(dstTarget))) {
    ElMessage.error(t('messages.badFragmentNoIPv6'))
    return
  }

  submitting.value = true
  try {
    const data = {}
    // Address fields: pick IP or CIDR based on mode
    if (f.src_mode === 'ip') { if (f.src_ip) data.src_ip = f.src_ip }
    else { if (f.src_cidr) data.src_cidr = f.src_cidr }
    if (f.dst_mode === 'ip') { if (f.dst_ip) data.dst_ip = f.dst_ip }
    else { if (f.dst_cidr) data.dst_cidr = f.dst_cidr }
    // Other fields
    if (f.src_port) data.src_port = f.src_port
    if (f.dst_port) data.dst_port = f.dst_port
    if (f.decoder) {
      // Decoder is syntactic sugar — Controller expands it into protocol /
      // tcp_flags / match_anomaly. Do NOT also send raw protocol/tcp_flags
      // (Controller would reject as mutually exclusive, §7.4.1).
      data.decoder = f.decoder
    } else {
      if (f.protocol) data.protocol = f.protocol
      if (f.tcp_flags) data.tcp_flags = f.tcp_flags
    }
    data.action = f.action
    if (f.action === 'rate_limit') data.rate_limit = f.rate_limit
    if (f.pkt_len_min) data.pkt_len_min = f.pkt_len_min
    if (f.pkt_len_max) data.pkt_len_max = f.pkt_len_max
    if (f.comment) data.comment = f.comment

    // B-2: sync field is always present; show warning if any node failed
    const resp = await rulesApi.create(data)
    if (resp.sync && resp.sync.failed > 0) {
      const nodes = Object.keys(resp.sync.errors || {}).join(', ')
      ElMessage.warning(t('messages.partialSync', {
        failed: resp.sync.failed, total: resp.sync.total, nodes
      }))
    } else {
      ElMessage.success(t('messages.addSuccess'))
    }
    dialogVisible.value = false
    refresh()
  } catch (e) {
    ElMessage.error(t('messages.addFailed') + ': ' + (e.response?.data?.error || e.message))
  } finally {
    submitting.value = false
  }
}

const batchAdd = async () => {
  if (parsedIPs.value.length === 0) {
    ElMessage.warning(t('messages.atLeastOneIP'))
    return
  }

  submitting.value = true

  try {
    // Build batch rules array, auto-detect IP vs CIDR (entries containing '/' are CIDR)
    const rules = parsedIPs.value.map(addr => {
      const rule = { action: batchForm.value.action }
      const isCIDR = addr.includes('/')
      if (batchForm.value.type === 'src') {
        if (isCIDR) rule.src_cidr = addr
        else rule.src_ip = addr
      } else {
        if (isCIDR) rule.dst_cidr = addr
        else rule.dst_ip = addr
      }
      if (batchForm.value.protocol) {
        rule.protocol = batchForm.value.protocol
      }
      if (batchForm.value.action === 'rate_limit') {
        rule.rate_limit = batchForm.value.rate_limit
      }
      return rule
    })

    // Submit all at once via batch API
    const result = await rulesApi.batchCreate(rules)
    const added = result.added || 0
    const failed = result.failed || 0
    // rev15 codex round 14 P2: B-2 — must surface sync.failed for batch create.
    // sync.failed counts items the Controller stored but couldn't sync to nodes.
    const syncFailed = (result.sync && result.sync.failed) || 0

    // rev16 codex round 15 P2: mixed-failure branch must NOT hide syncFailed.
    // batchResult only carries (success, fail); when sync is also failing the
    // user needs to see the data-plane gap too.
    if (failed === 0 && syncFailed === 0) {
      ElMessage.success(t('messages.batchSuccess', { n: added }))
    } else if (failed === 0 && syncFailed > 0) {
      const nodes = Object.keys((result.sync && result.sync.errors) || {}).join(', ')
      ElMessage.warning(t('messages.partialSync', {
        failed: syncFailed, total: result.sync.total, nodes
      }))
    } else if (failed > 0 && syncFailed === 0) {
      ElMessage.warning(t('messages.batchResult', { success: added, fail: failed }))
    } else {
      // Mixed: validation failed + sync failed — surface all three numbers.
      ElMessage.warning(t('messages.batchMixed', {
        success: added, fail: failed, syncFailed: syncFailed,
      }))
    }
    batchDialogVisible.value = false
    refresh()  // full refresh after batch add
  } catch (e) {
    ElMessage.error(t('messages.addFailed') + ': ' + (e.response?.data?.error || e.message))
  } finally {
    submitting.value = false
  }
}

const deleteRule = async (id) => {
  try {
    await ElMessageBox.confirm(t('messages.confirmDelete'), t('dialog.confirmDelete'), { type: 'warning' })
    // rev15 codex round 14 P2: B-2 — single delete must surface sync.failed.
    const resp = await rulesApi.delete(id)
    if (resp && resp.sync && resp.sync.failed > 0) {
      const nodes = Object.keys(resp.sync.errors || {}).join(', ')
      ElMessage.warning(t('messages.partialSync', {
        failed: resp.sync.failed, total: resp.sync.total, nodes
      }))
    } else {
      ElMessage.success(t('messages.deleteSuccess'))
    }
    refresh()  // full refresh after delete
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(t('messages.deleteFailed'))
  }
}

const batchDelete = async () => {
  try {
    await ElMessageBox.confirm(t('messages.confirmBatchDelete', { n: selectedIds.value.length }), t('dialog.batchDelete'), { type: 'warning' })
    // rev15 codex round 14 P2: B-2 — batch delete must surface sync.failed too.
    const resp = await rulesApi.batchDelete(selectedIds.value)
    const syncFailed = (resp && resp.sync && resp.sync.failed) || 0
    if (syncFailed > 0) {
      const nodes = Object.keys((resp.sync && resp.sync.errors) || {}).join(', ')
      ElMessage.warning(t('messages.partialSync', {
        failed: syncFailed, total: resp.sync.total, nodes
      }))
    } else {
      ElMessage.success(t('messages.deleteSuccess'))
    }
    selectedIds.value = []
    refresh()  // full refresh after batch delete
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(t('messages.batchDeleteFailed'))
  }
}

const handleSelectionChange = (selection) => {
  selectedIds.value = selection.map(r => r.id)
}

const formatPPS = (pps) => {
  if (!pps || pps === 0) return '0'
  if (pps >= 1000) return (pps / 1000).toFixed(1) + 'K'
  return Math.round(pps).toString()
}

const formatCount = (count) => {
  if (!count || count === 0) return '0'
  if (count >= 1000000) return (count / 1000000).toFixed(1) + 'M'
  if (count >= 1000) return (count / 1000).toFixed(1) + 'K'
  return count.toString()
}

onMounted(() => {
  refresh()  // full refresh on initial load
  refreshTimer = setInterval(refreshStatsOnly, refreshInterval)  // auto-refresh updates stats only
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.rules-page {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 24px;
}

.toolbar-left {
  flex: 1;
  max-width: 400px;
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.search-input {
  width: 100%;
}

.refresh-hint {
  font-size: 0.8rem;
  color: var(--xs-text-secondary);
  opacity: 0.7;
}

.table-container {
  padding: 0;
  overflow: hidden;
}

.rule-id {
  font-family: 'SF Mono', monospace;
  font-size: 0.85rem;
  color: var(--xs-text-secondary);
}

.ip-cell {
  display: flex;
  align-items: center;
}

.ip-cell .ip {
  font-weight: 500;
}

.ip-cell .port {
  color: var(--xs-accent);
  font-size: 0.9rem;
}

.protocol-badge {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--xs-text-secondary);
}

.stats-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.stats-cell .pps {
  color: var(--xs-danger);
  font-weight: 600;
}

.stats-cell .total {
  color: var(--xs-text-secondary);
  font-size: 0.8rem;
}

.stats-cell.match-stats .match-count {
  color: var(--xs-accent);
  font-weight: 600;
  font-size: 0.95rem;
}

.no-stats,
.no-filter {
  color: var(--xs-text-secondary);
  opacity: 0.5;
  font-size: 12px;
}
.no-stats.is-error {
  color: var(--xs-danger, #ef4444);
  opacity: 0.85;
}
.no-stats.is-muted {
  opacity: 0.35;
}
.no-stats.is-warn {
  color: var(--xs-warning, #b45309);
  opacity: 0.85;
}

/* v2.6.3 stats-row badges — small color-coded label rendered inside each
   stats cell when the cluster is in a degraded state. Keeps "100" from
   reading as "definitely 100 across all nodes" when only some succeeded. */
.row-badge {
  display: inline-block;
  margin-left: 6px;
  padding: 1px 6px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.04em;
  border-radius: 6px;
}
.row-badge.badge-warn {
  background: rgba(245, 158, 11, 0.12);
  color: #b45309;
}
.row-badge.badge-error {
  background: rgba(239, 68, 68, 0.12);
  color: #b91c1c;
}

.edit-readonly {
  color: var(--xs-text-secondary);
  font-family: 'SF Mono', monospace;
  font-size: 0.85rem;
  background: var(--xs-bg-secondary, #f5f5f5);
  padding: 2px 8px;
  border-radius: 4px;
}

.pkt-len {
  font-family: 'SF Mono', monospace;
  font-size: 0.85rem;
  color: var(--xs-text-secondary);
}

.form-hint {
  font-size: 0.75rem;
  color: var(--xs-text-secondary);
  margin-top: 4px;
  opacity: 0.7;
}

.addr-field {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
}

.addr-mode-toggle {
  flex-shrink: 0;
}

.addr-input {
  flex: 1;
}

.cidr-tag {
  flex-shrink: 0;
  font-size: 0.7rem;
  padding: 0 4px;
  height: 18px;
  line-height: 18px;
  vertical-align: middle;
  margin-right: 4px;
}

.comment-text {
  color: var(--xs-text-secondary);
  font-size: 0.9rem;
}

.pagination-container {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 24px;
  border-top: 1px solid var(--border-color, #ebeef5);
}

.pagination-total {
  font-size: 0.85rem;
  color: var(--xs-text-secondary);
}
</style>
