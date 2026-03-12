<template>
  <div class="whitelist-page">
    <!-- Toolbar -->
    <div class="toolbar glass-card fade-in">
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

    <div class="table-container glass-card fade-in" style="animation-delay: 0.1s">
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
import { ref, computed, onMounted, onUnmounted } from 'vue'
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

    await whitelistApi.create(data)
    ElMessage.success(t('messages.addSuccess'))
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

        await whitelistApi.create(data)
        successCount++
      } catch (e) {
        failCount++
      }
    }

    if (failCount === 0) {
      ElMessage.success(t('messages.batchSuccess', { n: successCount }))
    } else {
      ElMessage.warning(t('messages.batchResult', { success: successCount, fail: failCount }))
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
    await whitelistApi.delete(id)
    ElMessage.success(t('messages.deleteSuccess'))
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
    for (const id of selectedIds.value) {
      try {
        await whitelistApi.delete(id)
        successCount++
      } catch (e) {
        // ignore individual failures
      }
    }
    ElMessage.success(t('messages.deleteSuccess'))
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
  color: var(--text-secondary);
  opacity: 0.7;
}

.table-container {
  padding: 0;
  overflow: hidden;
}

.entry-id {
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
  color: var(--text);
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
</style>
