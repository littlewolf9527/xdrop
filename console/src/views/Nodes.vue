<script setup lang="ts">
import {
  ref
} from 'vue'
import {
  useI18n
} from 'vue-i18n'
import {
  ElButton, ElTooltip
} from 'element-plus'
import {
  state
} from '../state'
import NodeTable from '../components/NodeTable.vue'
import Meter from '../components/Meter.vue'
const {
  t
} = useI18n(), table = ref<InstanceType<typeof NodeTable>>(), busy = ref(false)
async function all() {
  busy.value = true;
  try {
    await table.value?.all()
  } finally {
    busy.value = false
  }
}
</script>
<template>
  <section
    class="page"
  >
    <header
      class="page-head"
    >
      <h1>{{ t('nodes') }}</h1>
      <ElButton
        size="small"
        :disabled="busy"
        @click="all"
      >{{ t('resyncAll') }}</ElButton>
    </header>
    <NodeTable
      ref="table"
      :nodes="state.nodes"
      actions
     />
    <section
      class="panel"
    >
      <header
        class="panel-head"
      >
        <h2>{{ t('capacity') }}</h2>
      </header>
      <div
        class="tbl-wrap"
      >
        <table>
          <thead>
            <tr>
              <th>{{ t('item') }}</th>
              <th
                class="r"
              >{{ t('used') }}</th>
              <th
                class="r"
              >{{ t('limit') }}</th>
              <th>{{ t('usage') }}</th>
              <th>{{ t('tightestNode') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="dim in state.capacity?.dimensions"
              :key="dim.name"
            >
              <td>
                <ElTooltip
                  :content="dim.name"
                >
                  <span>{{ t('dimensions.' + dim.name) }}</span>
                </ElTooltip>
              </td>
              <td
                class="r num"
              >{{ dim.used }}</td>
              <td
                class="r num"
              >{{ dim.admission_limit }}</td>
              <td>
                <Meter
                  :ratio="dim.ratio"
                  :exhausted="dim.exhausted"
                 />
              </td>
              <td
                class="mono"
              >{{ dim.limit_source }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </section>
</template>
