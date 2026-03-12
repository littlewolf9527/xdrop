<template>
  <!-- Login page: full-screen, no layout -->
  <router-view v-if="$route.meta.public" />

  <!-- Other pages: normal layout -->
  <el-container v-else class="app-container">
    <!-- Sidebar -->
    <el-aside :width="sidebarWidth" class="sidebar">
      <div class="logo">
        <div class="logo-icon">
          <el-icon size="28"><Aim /></el-icon>
        </div>
        <span class="logo-text">XDrop</span>
      </div>

      <el-menu
        :default-active="$route.path"
        router
        class="sidebar-menu"
      >
        <el-menu-item v-for="r in menuRoutes" :key="r.path" :index="r.path">
          <el-icon><component :is="r.meta.icon" /></el-icon>
          <span>{{ $t(`nav.${r.meta.titleKey}`) }}</span>
        </el-menu-item>
      </el-menu>

      <!-- Footer -->
      <div class="sidebar-footer">
        <div class="footer-btn" @click="toggleTheme" :title="isDark ? 'Light mode' : 'Dark mode'">
          <el-icon size="20"><Sunny v-if="isDark" /><Moon v-else /></el-icon>
        </div>
        <div class="footer-btn logout-btn" @click="handleLogout" :title="$t('nav.logout')">
          <el-icon size="20"><SwitchButton /></el-icon>
        </div>
      </div>
    </el-aside>

    <!-- Main Content -->
    <el-container class="main-container">
      <!-- Header -->
      <el-header class="header">
        <div class="header-left">
          <h1 class="page-title">{{ currentTitle }}</h1>
        </div>
        <div class="header-right">
          <!-- Language Switcher -->
          <el-dropdown @command="changeLocale" trigger="click">
            <el-button text class="locale-btn">
              <span class="locale-flag">{{ currentLocaleFlag }}</span>
              <el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item
                  v-for="locale in availableLocales"
                  :key="locale.code"
                  :command="locale.code"
                  :class="{ 'is-active': locale.code === currentLocale }"
                >
                  <span class="locale-option">
                    <span class="locale-flag">{{ locale.flag }}</span>
                    <span>{{ locale.name }}</span>
                  </span>
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <!-- Content -->
      <el-main class="main">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { availableLocales, setLocale, getCurrentLocale } from './locales'
import { authApi } from './api/auth'
import { setAuthenticated, isAuthEnabled } from './router'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()

const sidebarWidth = '240px'
const menuRoutes = router.options.routes.filter(r => !r.meta?.public)

const currentTitle = computed(() => {
  const titleKey = route.meta?.titleKey
  return titleKey ? t(`nav.${titleKey}`) : 'XDrop Controller'
})

// Language
const currentLocale = ref(getCurrentLocale())

const currentLocaleFlag = computed(() => {
  const locale = availableLocales.find(l => l.code === currentLocale.value)
  return locale?.flag || '🌐'
})

const changeLocale = (code) => {
  setLocale(code)
  currentLocale.value = code
}

// Theme
const isDark = ref(true)

const toggleTheme = () => {
  isDark.value = !isDark.value
  document.documentElement.classList.toggle('light', !isDark.value)
  localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
}

// Logout — no-op when auth is disabled
const handleLogout = async () => {
  if (!isAuthEnabled()) return
  try { await authApi.logout() } catch {}
  setAuthenticated(false)
  router.push({ name: 'Login' })
}

onMounted(() => {
  // Load saved theme
  const savedTheme = localStorage.getItem('theme')
  if (savedTheme === 'light') {
    isDark.value = false
    document.documentElement.classList.add('light')
  }
})
</script>

<style scoped>
.app-container {
  height: 100vh;
  background: var(--bg);
}

.sidebar {
  display: flex;
  flex-direction: column;
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-right: 1px solid var(--border);
}

.logo {
  height: 72px;
  display: flex;
  align-items: center;
  padding: 0 20px;
  gap: 12px;
  border-bottom: 1px solid var(--border);
}

.logo-icon {
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--primary), var(--primary-dark));
  border-radius: 10px;
  color: white;
}

.logo-text {
  font-size: 1.5rem;
  font-weight: 700;
  background: linear-gradient(135deg, var(--primary), var(--primary-light));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.sidebar-menu {
  flex: 1;
  padding: 12px 0;
}

.sidebar-footer {
  padding: 16px;
  border-top: 1px solid var(--border);
  display: flex;
  justify-content: center;
  gap: 8px;
}

.footer-btn {
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  border-radius: 10px;
  color: var(--text-secondary);
  transition: var(--transition);
}

.footer-btn:hover {
  background: var(--bg-hover);
  color: var(--primary);
}

.logout-btn:hover {
  color: var(--danger);
}

.main-container {
  background: var(--bg);
}

.header {
  height: 72px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 32px;
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
}

.page-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--text);
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 20px;
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.status-indicator.online {
  border-color: rgba(34, 197, 94, 0.3);
}

.status-indicator.online .status-dot {
  background: var(--success);
  box-shadow: 0 0 8px var(--success);
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--danger);
}

.main {
  padding: 32px;
  background: var(--bg);
  overflow-y: auto;
}

/* Page transition animation */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.fade-enter-from {
  opacity: 0;
  transform: translateY(10px);
}

.fade-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}

/* Language switcher */
.locale-btn {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 8px 12px;
  color: var(--text);
  font-size: 1rem;
}

.locale-btn:hover {
  background: var(--bg-hover);
}

.locale-flag {
  font-size: 1.25rem;
  line-height: 1;
}

.locale-option {
  display: flex;
  align-items: center;
  gap: 8px;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
</style>
