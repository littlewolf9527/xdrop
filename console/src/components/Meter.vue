<script setup lang="ts">
import {
  level, percent
} from '../metrics'
defineProps<{
  ratio: number | null;
  exhausted?: boolean
}>()
</script>
<template>
  <span
    class="meter-wrap"
  >
    <span
      v-if="ratio !== null"
      class="capmeter"
    >
      <b
        :class="level({ ratio, exhausted: !!exhausted })"
        :style="{ width: Math.min(100, Math.max(0, ratio * 100)) + '%' }"
       />
    </span>
    <span
      class="num"
    >{{ percent(ratio) }}</span>
  </span>
</template>
