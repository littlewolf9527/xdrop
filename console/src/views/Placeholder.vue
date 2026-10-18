<script setup lang="ts">
import { useI18n } from 'vue-i18n'
defineProps<{ page: string }>()
const { t } = useI18n()
</script>
<template>
  <section class="page"><h1>{{ t(page) }}</h1><div class="panel empty-panel" /></section>
</template>
