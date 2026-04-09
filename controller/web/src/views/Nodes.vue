<template>
  <div class="nodes-page">
    <!-- Read-only notice -->
    <el-alert
      :title="$t('nodes.readOnlyMode')"
      type="info"
      :closable="false"
      style="margin-bottom: 16px"
      class="fade-in"
    >
      {{ $t('nodes.description') }}
    </el-alert>

    <div class="toolbar xs-card fade-in">
      <div class="toolbar-left">
        <h3 class="page-subtitle">{{ $t('nodes.title') }}</h3>
      </div>
      <div class="toolbar-right">
        <!-- Add node button hidden (read-only mode) -->
        <el-button @click="refresh" :loading="loading" round>
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </div>
    </div>

    <div class="table-container xs-card fade-in" style="animation-delay: 0.1s">
      <el-table :data="nodes" v-loading="loading">
        <el-table-column prop="name" :label="$t('nodes.name')" min-width="150">
          <template #default="{ row }">
            <div class="node-name">
              <span class="status-dot" :class="row.status"></span>
              {{ row.name }}
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="endpoint" :label="$t('nodes.endpoint')" min-width="200">
          <template #default="{ row }">
            <span class="endpoint-text">{{ row.endpoint }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="status" :label="$t('nodes.statusLabel')" width="100" align="center">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : 'danger'" size="small">
              {{ row.status === 'online' ? $t('nodes.status.online') : $t('nodes.status.offline') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="$t('nodes.rulesCount')" width="100" align="center">
          <template #default="{ row }">
            <span class="count-text">{{ row.stats?.rules_count ?? 0 }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen" :label="$t('nodes.lastSeen')" width="180">
          <template #default="{ row }">
            <span class="time-text">{{ formatTime(row.last_seen) }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="$t('table.operations')" width="200" fixed="right" align="center">
          <template #default="{ row }">
            <el-button
              size="small"
              @click="showDetail(row)"
              round
            >
              <el-icon><View /></el-icon>
              {{ $t('nodes.detail') }}
            </el-button>
            <el-button
              type="primary"
              size="small"
              @click="syncNode(row.id)"
              :loading="syncing[row.id]"
              round
            >
              <el-icon><Refresh /></el-icon>
              {{ $t('nodes.sync') }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Node detail dialog -->
    <NodeDetail
      v-model="detailVisible"
      :node="selectedNode"
    />

    <!-- Add node dialog disabled (read-only mode)
    <el-dialog v-model="dialogVisible" title="Add Node" width="500px" center>
      <el-form :model="form" label-width="80px">
        <el-form-item label="Name" required>
          <el-input v-model="form.name" placeholder="e.g. node-us-01" />
        </el-form-item>
        <el-form-item label="Endpoint" required>
          <el-input v-model="form.endpoint" placeholder="e.g. http://10.0.1.10:8080" />
        </el-form-item>
        <el-form-item label="API Key">
          <el-input v-model="form.api_key" placeholder="Node API Key (optional)" type="password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false" round>Cancel</el-button>
        <el-button type="primary" @click="addNode" :loading="submitting" round>Add</el-button>
      </template>
    </el-dialog>
    -->
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { nodesApi } from '../api'
import NodeDetail from '../components/NodeDetail.vue'

const { t } = useI18n()

const loading = ref(false)
const submitting = ref(false)
const nodes = ref([])
const dialogVisible = ref(false)
const syncing = reactive({})
const form = ref({ name: '', endpoint: '', api_key: '' })
const detailVisible = ref(false)
const selectedNode = ref(null)

const showDetail = (node) => {
  selectedNode.value = node
  detailVisible.value = true
}

const refresh = async () => {
  loading.value = true
  try {
    const data = await nodesApi.list()
    nodes.value = data.nodes || []
  } catch (e) {
    ElMessage.error(t('messages.loadFailed'))
  } finally {
    loading.value = false
  }
}

const showAddDialog = () => {
  form.value = { name: '', endpoint: '', api_key: '' }
  dialogVisible.value = true
}

const addNode = async () => {
  if (!form.value.name || !form.value.endpoint) {
    ElMessage.warning('Please fill in all required fields')
    return
  }
  submitting.value = true
  try {
    await nodesApi.register(form.value)
    ElMessage.success('Added successfully')
    dialogVisible.value = false
    refresh()
  } catch (e) {
    ElMessage.error('Failed to add: ' + (e.response?.data?.error || e.message))
  } finally {
    submitting.value = false
  }
}

const syncNode = async (id) => {
  syncing[id] = true
  try {
    await nodesApi.sync(id)
    ElMessage.success(t('messages.syncSuccess'))
    setTimeout(refresh, 2000)
  } catch (e) {
    ElMessage.error(t('messages.syncFailed'))
  } finally {
    syncing[id] = false
  }
}

const deleteNode = async (id) => {
  try {
    await ElMessageBox.confirm('Delete this node?', 'Confirm Delete', { type: 'warning' })
    await nodesApi.delete(id)
    ElMessage.success('Deleted successfully')
    refresh()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error('Failed to delete')
  }
}

const formatTime = (time) => {
  if (!time) return '-'
  return new Date(time).toLocaleString('en-US', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

onMounted(refresh)
</script>

<style scoped>
.nodes-page {
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

.page-subtitle {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--xs-text-primary);
}

.toolbar-right {
  display: flex;
  gap: 12px;
}

.table-container {
  padding: 0;
  overflow: hidden;
}

.node-name {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--xs-text-primary);
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--xs-danger);
  flex-shrink: 0;
}

.status-dot.online {
  background: var(--xs-success);
  box-shadow: 0 0 8px var(--xs-success);
}

.endpoint-text {
  color: var(--xs-text-secondary);
  font-family: 'SF Mono', monospace;
  font-size: 0.875rem;
}

.count-text {
  color: var(--xs-text-primary);
  font-weight: 500;
}

.time-text {
  color: var(--xs-text-secondary);
  font-size: 0.875rem;
}
</style>
