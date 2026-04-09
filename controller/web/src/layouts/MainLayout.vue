<template>
  <el-container style="height: 100vh">
    <!-- Sidebar -->
    <el-aside :width="sidebarCollapsed ? '64px' : '240px'" class="xs-sidebar">
      <div class="xs-sidebar-brand" v-show="!sidebarCollapsed">
        <span class="xs-brand-icon">◆</span>
        <span class="xs-brand-text">XDrop</span>
      </div>
      <div class="xs-sidebar-brand" v-show="sidebarCollapsed">
        <span class="xs-brand-icon">◆</span>
      </div>

      <el-menu
        :default-active="$route.path"
        :collapse="sidebarCollapsed"
        background-color="transparent"
        text-color="var(--xs-text-sidebar)"
        active-text-color="var(--xs-text-sidebar-active)"
        router
        class="xs-nav-menu"
      >
        <!-- Firewall -->
        <div class="xs-nav-group" v-show="!sidebarCollapsed">{{ $t('nav.groupFirewall') }}</div>
        <el-menu-item index="/">
          <el-icon><Odometer /></el-icon>
          <template #title>{{ $t('nav.dashboard') }}</template>
        </el-menu-item>
        <el-menu-item index="/rules">
          <el-icon><List /></el-icon>
          <template #title>{{ $t('nav.blacklist') }}</template>
        </el-menu-item>
        <el-menu-item index="/whitelist">
          <el-icon><CircleCheck /></el-icon>
          <template #title>{{ $t('nav.whitelist') }}</template>
        </el-menu-item>
        <el-menu-item index="/nodes">
          <el-icon><Monitor /></el-icon>
          <template #title>{{ $t('nav.nodes') }}</template>
        </el-menu-item>

        <!-- System -->
        <div class="xs-nav-group" v-show="!sidebarCollapsed">{{ $t('nav.groupSystem') }}</div>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <template #title>{{ $t('nav.settings') }}</template>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <!-- Header -->
      <el-header class="xs-header">
        <div style="display: flex; align-items: center; gap: 12px;">
          <el-icon @click="sidebarCollapsed = !sidebarCollapsed" style="cursor: pointer; font-size: 18px; color: var(--xs-text-secondary);"><Fold /></el-icon>
        </div>
        <div style="display: flex; align-items: center; gap: 20px;">
          <!-- Theme selector -->
          <el-dropdown @command="handleThemeChange" trigger="click">
            <span class="xs-header-action">
              <span :style="{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: 'var(--xs-accent)' }"></span>
              {{ theme === 'amber' ? $t('theme.amber') : $t('theme.classic') }}
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="classic">{{ $t('theme.classic') }}</el-dropdown-item>
                <el-dropdown-item command="amber">{{ $t('theme.amber') }}</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <!-- Language -->
          <el-dropdown @command="changeLocale" trigger="click">
            <span class="xs-header-action">
              {{ currentLocaleLabel }} <el-icon style="margin-left: 2px;"><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item
                  v-for="locale in availableLocales"
                  :key="locale.code"
                  :command="locale.code"
                >
                  {{ locale.name }}
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <!-- Logout -->
          <span class="xs-header-action xs-logout" @click="handleLogout">
            <el-icon><SwitchButton /></el-icon>
          </span>
        </div>
      </el-header>

      <!-- Main content -->
      <el-main class="xs-main">
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
import { ref, computed, inject } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { themeKey } from '../composables/useTheme'
import { availableLocales, setLocale, getCurrentLocale } from '../locales'
import { authApi } from '../api/auth'
import { setAuthenticated, isAuthEnabled } from '../router'

const router = useRouter()
const { t } = useI18n()
const { theme, setTheme } = inject(themeKey)

const sidebarCollapsed = ref(false)
const currentLocale = ref(getCurrentLocale())

const currentLocaleLabel = computed(() => {
  const locale = availableLocales.find(l => l.code === currentLocale.value)
  return locale?.flag || 'EN'
})

function handleThemeChange(t) {
  setTheme(t)
}

function changeLocale(code) {
  setLocale(code)
  currentLocale.value = code
}

async function handleLogout() {
  if (!isAuthEnabled()) return
  try { await authApi.logout() } catch {}
  setAuthenticated(false)
  router.push({ name: 'Login' })
}
</script>

<style scoped>
.xs-sidebar {
  background: var(--xs-bg-sidebar);
  transition: width 0.3s;
  overflow-y: auto;
  overflow-x: hidden;
}

.xs-sidebar-brand {
  padding: 20px 20px 12px;
  display: flex;
  align-items: center;
  gap: 10px;
  white-space: nowrap;
  overflow: hidden;
}
.xs-brand-icon {
  color: var(--xs-accent);
  font-size: 18px;
}
.xs-brand-text {
  color: #ffffff;
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 1px;
}

.xs-nav-group {
  padding: 20px 20px 6px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.08em;
  color: rgba(255, 255, 255, 0.3);
  text-transform: uppercase;
}

.xs-nav-menu {
  border-right: none !important;
}

.xs-header {
  background: var(--xs-header-bg);
  border-bottom: 1px solid var(--xs-header-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
  padding: 0 24px;
}

.xs-header-action {
  cursor: pointer;
  color: var(--xs-text-secondary);
  font-size: 13px;
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: color 0.2s;
}
.xs-header-action:hover {
  color: var(--xs-text-primary);
}
.xs-logout:hover {
  color: var(--xs-danger) !important;
}

.xs-main {
  background: var(--xs-bg-primary);
  padding: 24px 28px;
  overflow: auto;
  position: relative;
}

/* Page transition */
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
</style>
