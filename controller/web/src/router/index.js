import { createRouter, createWebHistory } from 'vue-router'
import { authApi } from '../api/auth'

const routes = [
    {
        path: '/login',
        name: 'Login',
        component: () => import('../views/Login.vue'),
        meta: { public: true }
    },
    {
        path: '/',
        name: 'Dashboard',
        component: () => import('../views/Dashboard.vue'),
        meta: { titleKey: 'dashboard', icon: 'Odometer' }
    },
    {
        path: '/rules',
        name: 'Rules',
        component: () => import('../views/Rules.vue'),
        meta: { titleKey: 'rules', icon: 'List' }
    },
    {
        path: '/whitelist',
        name: 'Whitelist',
        component: () => import('../views/Whitelist.vue'),
        meta: { titleKey: 'whitelist', icon: 'CircleCheck' }
    },
    {
        path: '/nodes',
        name: 'Nodes',
        component: () => import('../views/Nodes.vue'),
        meta: { titleKey: 'nodes', icon: 'Monitor' }
    },
    {
        path: '/settings',
        name: 'Settings',
        component: () => import('../views/Settings.vue'),
        meta: { titleKey: 'settings', icon: 'Setting' }
    }
]

const router = createRouter({
    history: createWebHistory(),
    routes
})

// Auth state — checked once on app bootstrap, cached in memory
let authChecked = false
let isAuthenticated = false
let authEnabled = true // assume enabled until proven otherwise

// Export for Login.vue to set after successful login
export function setAuthenticated(value) {
    authChecked = true
    isAuthenticated = value
}

// Export for App.vue to check if logout should be a no-op
export function isAuthEnabled() {
    return authEnabled
}

router.beforeEach(async (to) => {
    if (to.meta.public) return true

    if (!authChecked) {
        try {
            const data = await authApi.check()
            isAuthenticated = true
            if (data.auth_enabled === false) {
                authEnabled = false
            }
        } catch {
            isAuthenticated = false
        }
        authChecked = true
    }

    return isAuthenticated ? true : { name: 'Login' }
})

export default router
