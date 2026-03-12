<template>
  <div class="rules-page">
    <!-- Toolbar -->
    <div class="toolbar glass-card fade-in">
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
    <div class="table-container glass-card fade-in" style="animation-delay: 0.1s">
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
        <el-table-column :label="$t('table.matchCount')" width="120">
          <template #default="{ row }">
            <div class="stats-cell match-stats" v-if="row.stats">
              <span class="match-count">{{ formatCount(row.stats.match_count) }}</span>
            </div>
            <span class="no-stats" v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.dropPPS')" width="140">
          <template #default="{ row }">
            <div class="stats-cell" v-if="row.stats">
              <span class="pps">{{ formatPPS(row.stats.drop_pps) }} pps</span>
              <span class="total">({{ formatCount(row.stats.drop_count) }})</span>
            </div>
            <span class="no-stats" v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column prop="comment" :label="$t('table.comment')" min-width="150">
          <template #default="{ row }">
            <span class="comment-text">{{ row.comment || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.operations')" width="100" fixed="right" align="center">
          <template #default="{ row }">
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
              <el-input-number v-model="form.src_port" :min="0" :max="65535" style="width: 100%" />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item :label="$t('rules.form.dstPort')">
              <el-input-number v-model="form.dst_port" :min="0" :max="65535" style="width: 100%" />
            </el-form-item>
          </el-col>
        </el-row>
        <el-form-item :label="$t('rules.form.protocol')">
          <el-select v-model="form.protocol" :placeholder="$t('rules.protocols.all')" style="width: 100%">
            <el-option :label="$t('rules.protocols.all')" value="" />
            <el-option :label="$t('rules.protocols.tcp')" value="tcp" />
            <el-option :label="$t('rules.protocols.udp')" value="udp" />
            <el-option :label="$t('rules.protocols.icmp')" value="icmp" />
            <el-option :label="$t('rules.protocols.icmpv6')" value="icmpv6" />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('rules.form.action')">
          <el-radio-group v-model="form.action">
            <el-radio-button value="drop">{{ $t('rules.actions.drop') }}</el-radio-button>
            <el-radio-button value="rate_limit">{{ $t('rules.actions.rateLimit') }}</el-radio-button>
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
            <el-col :span="4" style="text-align: center; color: var(--text-secondary);">-</el-col>
            <el-col :span="10">
              <el-input-number v-model="form.pkt_len_max" :min="0" :max="65535" placeholder="Max" controls-position="right" style="width: 100%" />
            </el-col>
          </el-row>
          <div class="form-hint">{{ $t('messages.pktLenHint') }}</div>
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
const refreshInterval = 5000 // refresh every 5 seconds
let refreshTimer = null

// Pagination state
const currentPage = ref(1)
const pageSize = ref(50)
const totalRules = ref(0)

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
  action: 'drop',
  rate_limit: 1000,
  pkt_len_min: 0,
  pkt_len_max: 0,
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
  } catch (e) {
    console.error('Failed to load rules:', e)
  } finally {
    loading.value = false
  }
}

// Lightweight refresh: update stats only, preserve selection state
const refreshStatsOnly = async () => {
  if (rules.value.length === 0) {
    await refresh()
    return
  }

  try {
    const data = await rulesApi.list(buildListParams())
    const newRules = data.rules || []
    const newCount = data.count || 0

    // Detect changes: count changed or current-page rule ID list changed
    const currentIds = rules.value.map(r => r.id).join(',')
    const newIds = newRules.map(r => r.id).join(',')

    if (newCount !== totalRules.value || currentIds !== newIds) {
      // Rules changed: replace entire page data
      rules.value = newRules
      totalRules.value = newCount
      return
    }

    // Update stats only
    const newRulesMap = new Map(newRules.map(r => [r.id, r]))
    rules.value.forEach(rule => {
      const newRule = newRulesMap.get(rule.id)
      if (newRule && newRule.stats) {
        rule.stats = newRule.stats
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

// Search debounce: reset to page 1 and fetch after 300ms
watch(search, () => {
  if (searchDebounceTimer) clearTimeout(searchDebounceTimer)
  searchDebounceTimer = setTimeout(() => {
    currentPage.value = 1
    refresh()
  }, 300)
})

const showAddDialog = () => {
  form.value = {
    src_mode: 'ip', dst_mode: 'ip',
    src_ip: '', dst_ip: '', src_cidr: '', dst_cidr: '',
    src_port: 0, dst_port: 0, protocol: '', action: 'drop',
    rate_limit: 1000, pkt_len_min: 0, pkt_len_max: 0, comment: ''
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
    if (f.protocol) data.protocol = f.protocol
    data.action = f.action
    if (f.action === 'rate_limit') data.rate_limit = f.rate_limit
    if (f.pkt_len_min) data.pkt_len_min = f.pkt_len_min
    if (f.pkt_len_max) data.pkt_len_max = f.pkt_len_max
    if (f.comment) data.comment = f.comment

    await rulesApi.create(data)
    ElMessage.success(t('messages.addSuccess'))
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

    if (failed === 0) {
      ElMessage.success(t('messages.batchSuccess', { n: added }))
    } else {
      ElMessage.warning(t('messages.batchResult', { success: added, fail: failed }))
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
    await rulesApi.delete(id)
    ElMessage.success(t('messages.deleteSuccess'))
    refresh()  // full refresh after delete
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(t('messages.deleteFailed'))
  }
}

const batchDelete = async () => {
  try {
    await ElMessageBox.confirm(t('messages.confirmBatchDelete', { n: selectedIds.value.length }), t('dialog.batchDelete'), { type: 'warning' })
    await rulesApi.batchDelete(selectedIds.value)
    ElMessage.success(t('messages.deleteSuccess'))
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
  color: var(--text-secondary);
  opacity: 0.7;
}

.table-container {
  padding: 0;
  overflow: hidden;
}

.rule-id {
  font-family: 'SF Mono', monospace;
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.ip-cell {
  display: flex;
  align-items: center;
}

.ip-cell .ip {
  font-weight: 500;
}

.ip-cell .port {
  color: var(--primary);
  font-size: 0.9rem;
}

.protocol-badge {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-secondary);
}

.stats-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.stats-cell .pps {
  color: var(--danger);
  font-weight: 600;
}

.stats-cell .total {
  color: var(--text-secondary);
  font-size: 0.8rem;
}

.stats-cell.match-stats .match-count {
  color: var(--primary);
  font-weight: 600;
  font-size: 0.95rem;
}

.no-stats,
.no-filter {
  color: var(--text-secondary);
  opacity: 0.5;
}

.pkt-len {
  font-family: 'SF Mono', monospace;
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.form-hint {
  font-size: 0.75rem;
  color: var(--text-secondary);
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
  color: var(--text-secondary);
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
  color: var(--text-secondary);
}
</style>
