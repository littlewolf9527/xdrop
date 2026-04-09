<template>
  <!-- Login page: full-screen, no layout -->
  <router-view v-if="$route.meta.public" />

  <!-- Authenticated pages: MainLayout -->
  <MainLayout v-else />
</template>

<script setup>
import { provide } from 'vue'
import { useTheme, themeKey } from './composables/useTheme'
import MainLayout from './layouts/MainLayout.vue'

// Provide reactive theme to all descendants (charts, components, etc.)
provide(themeKey, useTheme())
</script>
