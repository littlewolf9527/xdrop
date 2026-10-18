<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { errorText, errorRules, batchLine } from '../errors'
defineProps<{ error: unknown; lineNumbers?: number[] }>()
const emit = defineEmits<{ search: [id: string] }>(), { t } = useI18n()
</script>
<template>
  <div class="error-text rule-error" role="alert">
    {{ errorText(error) }}
    <template v-if="errorRules(error).length">
      <span>{{ t('involved') }}</span>
      <template v-for="id in errorRules(error)" :key="id">
        <button v-if="id.startsWith('rule_')" type="button" class="text-btn" :title="id" @click="emit('search', id)">{{ t('viewRule') }}</button>
        <span v-else>{{ batchLine(id, lineNumbers) === undefined ? t('batchItem') : t('importLex.line', { n: batchLine(id, lineNumbers) }) }}</span>
      </template>
    </template>
  </div>
</template>
