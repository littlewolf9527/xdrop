<template>
  <div class="whitelist-page">
    <!-- Toolbar -->
    <div class="toolbar xs-card fade-in">
      <div class="toolbar-left">
        <el-input
          v-model="search"
          :placeholder="$t('whitelist.searchPlaceholder')"
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
          {{ $t('whitelist.addEntry') }}
        </el-button>
        <el-button @click="showBatchDialog" round>
          <el-icon><DocumentAdd /></el-icon>
          {{ $t('whitelist.batchAdd') }}
        </el-button>
        <el-button
          type="danger"
          @click="batchDelete"
          :disabled="!selectedIds.length"
          round
        >
          <el-icon><Delete /></el-icon>
          {{ $t('whitelist.deleteSelected', { n: selectedIds.length }) }}
        </el-button>
      </div>
    </div>

    <div class="table-container xs-card fade-in" style="animation-delay: 0.1s">
      <el-table :data="filteredEntries" v-loading="loading" @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="50" />
        <el-table-column prop="id" :label="$t('table.id')" width="140">
          <template #default="{ row }">
            <span class="entry-id">{{ row.id }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.source')" min-width="150">
          <template #default="{ row }">
            <div class="ip-cell">
              <span class="ip">{{ row.src_ip || '*' }}</span>
              <span class="port" v-if="row.src_port">:{{ row.src_port }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.destination')" min-width="150">
          <template #default="{ row }">
            <div class="ip-cell">
              <span class="ip">{{ row.dst_ip || '*' }}</span>
              <span class="port" v-if="row.dst_port">:{{ row.dst_port }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="protocol" :label="$t('table.protocol')" width="100" align="center">
          <template #default="{ row }">
            <span class="protocol-badge">{{ (row.protocol || 'ALL').toUpperCase() }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="comment" :label="$t('table.comment')" min-width="150">
          <template #default="{ row }">
            <span class="comment-text">{{ row.comment || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.operations')" width="100" fixed="right" align="center">
          <template #default="{ row }">
            <el-button type="danger" size="small" @click="deleteEntry(row.id)" circle>
              <el-icon><Delete /></el-icon>
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Single entry add dialog -->
    <el-dialog v-model="dialogVisible" :title="$t('dialog.addWhitelist')" width="500px" center>
      <el-form :model="form" label-width="100px">
        <el-form-item :label="$t('rules.form.srcIp')">
          <el-input v-model="form.src_ip" :placeholder="$t('placeholder.leaveEmptyForAny')" />
        </el-form-item>
        <el-form-item :label="$t('rules.form.dstIp')">
          <el-input v-model="form.dst_ip" :placeholder="$t('placeholder.leaveEmptyForAny')" />
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
        <el-form-item :label="$t('rules.form.protocol')">
          <el-select v-model="form.protocol" :placeholder="$t('rules.protocols.all')" style="width: 100%">
            <el-option :label="$t('rules.protocols.all')" value="" />
            <el-option :label="$t('rules.protocols.tcp')" value="tcp" />
            <el-option :label="$t('rules.protocols.udp')" value="udp" />
            <el-option :label="$t('rules.protocols.icmp')" value="icmp" />
            <el-option :label="$t('rules.protocols.icmpv6')" value="icmpv6" />
            <!-- rev11 codex round 10 P3: align UI with backend support -->
            <el-option :label="$t('rules.protocols.igmp')" value="igmp" />
            <el-option :label="$t('rules.protocols.gre')" value="gre" />
            <el-option :label="$t('rules.protocols.esp')" value="esp" />
          </el-select>
          <div v-if="isPortlessProtocol(form.protocol)" class="form-hint" style="color: var(--xs-warning, #e6a23c);">
            {{ $t('messages.portlessProtocolNoPort') }}
          </div>
        </el-form-item>
        <el-form-item :label="$t('rules.form.comment')">
          <el-input v-model="form.comment" :placeholder="$t('placeholder.optional')" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false" round>{{ $t('common.cancel') }}</el-button>
        <el-button type="primary" @click="addEntry" :loading="submitting" round>{{ $t('common.add') }}</el-button>
      </template>
    </el-dialog>

    <!-- Batch add dialog -->
    <el-dialog v-model="batchDialogVisible" :title="$t('dialog.batchAddWhitelist')" width="600px" center>
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
        <el-form-item :label="$t('rules.form.action')">
          <el-radio-group v-model="batchForm.type">
            <el-radio-button value="src">{{ $t('rules.ipType.src') }}</el-radio-button>
            <el-radio-button value="dst">{{ $t('rules.ipType.dst') }}</el-radio-button>
          </el-radio-group>
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
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { whitelistApi } from '../api'

const { t } = useI18n()

const loading = ref(false)
const submitting = ref(false)
const entries = ref([])
const selectedIds = ref([])
const search = ref('')
const dialogVisible = ref(false)
const batchDialogVisible = ref(false)
const refreshInterval = 5000
let refreshTimer = null

const form = ref({ src_ip: '', dst_ip: '', src_port: 0, dst_port: 0, protocol: '', comment: '' })
const batchForm = ref({ ips: '', protocol: '', type: 'src' })

// B-10: portless protocols can't carry ports — disable + auto-clear on selection.
// Shared with Rules.vue; kept inline here to avoid pulling a util file just for this.
const PORTLESS_PROTOCOLS = ['icmp', 'icmpv6', 'igmp', 'gre', 'esp']
const isPortlessProtocol = (proto) => PORTLESS_PROTOCOLS.includes(proto)

watch(() => form.value.protocol, (newVal) => {
  if (isPortlessProtocol(newVal)) {
    form.value.src_port = 0
    form.value.dst_port = 0
  }
})

const parsedIPs = computed(() => {
  return batchForm.value.ips
    .split('\n')
    .map(ip => ip.trim())
    .filter(ip => ip.length > 0)
})

const filteredEntries = computed(() => {
  if (!search.value) return entries.value
  const s = search.value.toLowerCase()
  return entries.value.filter(e =>
    (e.src_ip && e.src_ip.includes(s)) ||
    (e.dst_ip && e.dst_ip.includes(s)) ||
    (e.id && e.id.includes(s))
  )
})

const refresh = async () => {
  loading.value = true
  try {
    const data = await whitelistApi.list()
    entries.value = data.entries || []
  } catch (e) {
    ElMessage.error(t('messages.loadFailed'))
  } finally {
    loading.value = false
  }
}

const showAddDialog = () => {
  form.value = { src_ip: '', dst_ip: '', src_port: 0, dst_port: 0, protocol: '', comment: '' }
  dialogVisible.value = true
}

const showBatchDialog = () => {
  batchForm.value = { ips: '', protocol: '', type: 'src' }
  batchDialogVisible.value = true
}

const addEntry = async () => {
  submitting.value = true
  try {
    const data = { ...form.value }
    if (data.src_port === 0) delete data.src_port
    if (data.dst_port === 0) delete data.dst_port
    if (!data.src_ip) delete data.src_ip
    if (!data.dst_ip) delete data.dst_ip
    if (!data.protocol) delete data.protocol
    if (!data.comment) delete data.comment

    // rev14 codex round 13 P2: consume B-2 sync.failed — Controller DB success
    // ≠ data plane success. Show partial-sync warning when any node failed.
    const resp = await whitelistApi.create(data)
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
    ElMessage.error(t('messages.addFailed'))
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
  let successCount = 0
  let failCount = 0
  let syncFailedCount = 0  // rev14: partial-sync items (DB success but data plane failed)

  try {
    for (const ip of parsedIPs.value) {
      try {
        const data = {}
        if (batchForm.value.type === 'src') {
          data.src_ip = ip
        } else {
          data.dst_ip = ip
        }
        if (batchForm.value.protocol) {
          data.protocol = batchForm.value.protocol
        }

        // rev14 codex round 13 P2: count partial-sync as a failure mode separately
        // from HTTP error. DB-success-but-sync-failed is a quiet ghost-rule risk.
        const resp = await whitelistApi.create(data)
        if (resp && resp.sync && resp.sync.failed > 0) {
          syncFailedCount++
        }
        successCount++
      } catch (e) {
        failCount++
      }
    }

    // rev15 codex round 14 P2: don't hide syncFailedCount when there are also
    // HTTP failures. When both happen, surface all three numbers so the user
    // sees both validation/network failures and data-plane sync failures.
    if (failCount === 0 && syncFailedCount === 0) {
      ElMessage.success(t('messages.batchSuccess', { n: successCount }))
    } else if (failCount === 0 && syncFailedCount > 0) {
      ElMessage.warning(t('messages.batchPartialSync', {
        success: successCount, syncFailed: syncFailedCount,
      }))
    } else if (failCount > 0 && syncFailedCount === 0) {
      ElMessage.warning(t('messages.batchResult', { success: successCount, fail: failCount }))
    } else {
      ElMessage.warning(t('messages.batchMixed', {
        success: successCount, fail: failCount, syncFailed: syncFailedCount,
      }))
    }
    batchDialogVisible.value = false
    refresh()
  } finally {
    submitting.value = false
  }
}

const deleteEntry = async (id) => {
  try {
    await ElMessageBox.confirm(t('messages.confirmDelete'), t('dialog.confirmDelete'), { type: 'warning' })
    // rev14 codex round 13 P2: consume B-2 sync.failed on whitelist delete.
    const resp = await whitelistApi.delete(id)
    if (resp && resp.sync && resp.sync.failed > 0) {
      const nodes = Object.keys(resp.sync.errors || {}).join(', ')
      ElMessage.warning(t('messages.partialSync', {
        failed: resp.sync.failed, total: resp.sync.total, nodes
      }))
    } else {
      ElMessage.success(t('messages.deleteSuccess'))
    }
    refresh()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(t('messages.deleteFailed'))
  }
}

const batchDelete = async () => {
  if (selectedIds.value.length === 0) return
  try {
    await ElMessageBox.confirm(t('messages.confirmBatchDelete', { n: selectedIds.value.length }), t('dialog.batchDelete'), { type: 'warning' })
    let successCount = 0
    let failCount = 0
    let syncFailedCount = 0
    for (const id of selectedIds.value) {
      try {
        // rev14 codex round 13 P2: track partial-sync separately from HTTP error.
        // rev15 codex round 14 P2: also count HTTP failures (was silently dropped).
        const resp = await whitelistApi.delete(id)
        if (resp && resp.sync && resp.sync.failed > 0) {
          syncFailedCount++
        }
        successCount++
      } catch (e) {
        failCount++
      }
    }
    if (failCount === 0 && syncFailedCount === 0) {
      ElMessage.success(t('messages.deleteSuccess'))
    } else if (failCount === 0 && syncFailedCount > 0) {
      ElMessage.warning(t('messages.batchPartialSync', {
        success: successCount, syncFailed: syncFailedCount,
      }))
    } else if (failCount > 0 && syncFailedCount === 0) {
      ElMessage.warning(t('messages.batchResult', { success: successCount, fail: failCount }))
    } else {
      ElMessage.warning(t('messages.batchMixed', {
        success: successCount, fail: failCount, syncFailed: syncFailedCount,
      }))
    }
    selectedIds.value = []
    refresh()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(t('messages.batchDeleteFailed'))
  }
}

const handleSelectionChange = (selection) => {
  selectedIds.value = selection.map(e => e.id)
}

// Soft refresh: replace array only when count changes, preserve selection state
const softRefresh = async () => {
  try {
    const data = await whitelistApi.list()
    const newEntries = data.entries || []
    // Replace only when count changes
    if (newEntries.length !== entries.value.length) {
      entries.value = newEntries
    }
  } catch (e) {
    // Fail silently to avoid interrupting the user
    console.error('Soft refresh failed:', e)
  }
}

onMounted(() => {
  refresh()
  refreshTimer = setInterval(softRefresh, refreshInterval)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.whitelist-page {
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

.search-input {
  width: 100%;
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: 12px;
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

.entry-id {
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
  color: var(--xs-text-primary);
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
</style>
