<template>
  <div class="settings-page">
    <!-- API Key Configuration -->
    <div class="setting-section glass-card fade-in">
      <div class="section-icon">
        <el-icon size="24"><Key /></el-icon>
      </div>
      <div class="section-content">
        <h3 class="section-title">{{ $t('settings.apiKey.title') }}</h3>
        <p class="section-desc">{{ $t('settings.apiKey.description') }}</p>

        <div class="api-key-info">
          <div class="info-item">
            <span class="info-label">{{ $t('settings.apiKey.externalKey') }}</span>
            <span class="info-value">{{ $t('settings.apiKey.externalKeyDesc') }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">{{ $t('settings.apiKey.internalKey') }}</span>
            <span class="info-value">{{ $t('settings.apiKey.internalKeyDesc') }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">{{ $t('settings.apiKey.nodeKey') }}</span>
            <span class="info-value">{{ $t('settings.apiKey.nodeKeyDesc') }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Language Settings -->
    <div class="setting-section glass-card fade-in" style="animation-delay: 0.1s">
      <div class="section-icon">
        <el-icon size="24"><ChatLineSquare /></el-icon>
      </div>
      <div class="section-content">
        <h3 class="section-title">{{ $t('settings.language.title') }}</h3>
        <p class="section-desc">{{ $t('settings.language.description') }}</p>

        <el-select v-model="currentLocale" @change="changeLocale" class="language-select">
          <el-option
            v-for="locale in availableLocales"
            :key="locale.code"
            :label="`${locale.flag} ${locale.name}`"
            :value="locale.code"
          />
        </el-select>
      </div>
    </div>

    <!-- Appearance Settings -->
    <div class="setting-section glass-card fade-in" style="animation-delay: 0.2s">
      <div class="section-icon">
        <el-icon size="24"><Brush /></el-icon>
      </div>
      <div class="section-content">
        <h3 class="section-title">{{ $t('settings.theme.title') }}</h3>
        <p class="section-desc">{{ $t('settings.theme.description') }}</p>

        <div class="theme-selector">
          <div
            class="theme-option"
            :class="{ active: !isDark }"
            @click="setTheme(false)"
          >
            <div class="theme-preview light-preview">
              <el-icon><Sunny /></el-icon>
            </div>
            <span>{{ $t('settings.theme.light') }}</span>
          </div>
          <div
            class="theme-option"
            :class="{ active: isDark }"
            @click="setTheme(true)"
          >
            <div class="theme-preview dark-preview">
              <el-icon><Moon /></el-icon>
            </div>
            <span>{{ $t('settings.theme.dark') }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- About -->
    <div class="setting-section glass-card fade-in" style="animation-delay: 0.3s">
      <div class="section-icon">
        <el-icon size="24"><InfoFilled /></el-icon>
      </div>
      <div class="section-content">
        <h3 class="section-title">{{ $t('settings.about.title') }}</h3>
        <p class="section-desc">{{ $t('settings.about.description') }}</p>

        <div class="about-info">
          <div class="info-row">
            <span class="info-label">{{ $t('settings.about.version') }}</span>
            <span class="info-value">v1.4.0</span>
          </div>
          <div class="info-row">
            <span class="info-label">{{ $t('settings.about.name') }}</span>
            <span class="info-value">XDrop Controller</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { availableLocales, setLocale, getCurrentLocale } from '../locales'

const isDark = ref(true)
const currentLocale = ref(getCurrentLocale())

const setTheme = (dark) => {
  isDark.value = dark
  document.documentElement.classList.toggle('light', !dark)
  localStorage.setItem('theme', dark ? 'dark' : 'light')
}

const changeLocale = (code) => {
  setLocale(code)
}

onMounted(() => {
  const savedTheme = localStorage.getItem('theme')
  isDark.value = savedTheme !== 'light'
})
</script>

<style scoped>
.settings-page {
  display: flex;
  flex-direction: column;
  gap: 24px;
  max-width: 800px;
}

.setting-section {
  display: flex;
  gap: 24px;
  padding: 28px;
}

.section-icon {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--primary), var(--primary-dark));
  border-radius: 12px;
  color: white;
  flex-shrink: 0;
}

.section-content {
  flex: 1;
}

.section-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 4px;
}

.section-desc {
  font-size: 0.875rem;
  color: var(--text-secondary);
  margin-bottom: 20px;
}

.language-select {
  width: 250px;
}

.theme-selector {
  display: flex;
  gap: 16px;
}

.theme-option {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  padding: 12px;
  border-radius: 12px;
  transition: var(--transition);
}

.theme-option:hover {
  background: var(--bg-hover);
}

.theme-option.active .theme-preview {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
}

.theme-preview {
  width: 80px;
  height: 60px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 2px solid var(--border);
  transition: var(--transition);
  font-size: 1.5rem;
}

.light-preview {
  background: #f8fafc;
  color: #f59e0b;
}

.dark-preview {
  background: #0a0a0f;
  color: #60a5fa;
}

.theme-option span {
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.theme-option.active span {
  color: var(--primary);
  font-weight: 500;
}

.about-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.info-row {
  display: flex;
  gap: 16px;
}

.info-label {
  min-width: 80px;
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.info-value {
  color: var(--text);
  font-size: 0.875rem;
}

.api-key-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.api-key-info .info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.api-key-info .info-label {
  font-weight: 600;
  color: var(--primary);
  font-size: 0.875rem;
}

.api-key-info .info-value {
  color: var(--text-secondary);
  font-size: 0.8rem;
}
</style>
