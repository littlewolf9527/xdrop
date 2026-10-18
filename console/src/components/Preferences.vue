<script setup lang="ts">
import {
  useI18n
} from 'vue-i18n'
import {
  state, setLanguage, setTheme
} from '../state'
import {
  themes, languages
} from '../preferences'
const {
  t
} = useI18n()
</script>
<template>
  <div
    class="preferences"
  >
    <div
      class="seg"
      :aria-label="t('appearance')"
    >
      <button
        type="button"
        v-for="theme in themes"
        :key="theme"
        :aria-pressed="state.theme === theme"
        @click="setTheme(theme)"
      >{{ t(theme) }}</button>
    </div>
    <div
      class="seg"
      :aria-label="t('language')"
    >
      <button
        type="button"
        v-for="lang in languages"
        :key="lang"
        :aria-pressed="state.lang === lang"
        @click="setLanguage(lang)"
      >{{ { 'zh-CN': '中', 'ja-JP': '日', 'en-US': 'EN' }[lang] }}</button>
    </div>
  </div>
</template>
