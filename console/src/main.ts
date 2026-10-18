import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import { i18n } from './i18n'
import { initialize, guard, state } from './state'
import App from './App.vue'
import Login from './views/Login.vue'
import Overview from './views/Overview.vue'
import Nodes from './views/Nodes.vue'
import Rules from './views/Rules.vue'
import Whitelist from './views/Whitelist.vue'
import About from './views/About.vue'
import Audit from './views/Audit.vue'
import Settings from './views/Settings.vue'
import '@fontsource/ibm-plex-sans/latin-400.css'
import '@fontsource/ibm-plex-sans/latin-500.css'
import '@fontsource/ibm-plex-sans/latin-600.css'
import '@fontsource/ibm-plex-mono/latin-400.css'
import '@fontsource/ibm-plex-mono/latin-500.css'
import '@fontsource/ibm-plex-mono/latin-600.css'
import 'element-plus/theme-chalk/el-button.css'
import 'element-plus/theme-chalk/el-input.css'
import 'element-plus/theme-chalk/el-tooltip.css'
import 'element-plus/theme-chalk/el-popper.css'
import 'element-plus/theme-chalk/el-dropdown.css'
import 'element-plus/theme-chalk/el-dialog.css'
import 'element-plus/theme-chalk/el-overlay.css'
import 'element-plus/theme-chalk/el-icon.css'
import './tokens.css'
import './style.css'
const router = createRouter({ history: createWebHistory(), routes: [
  { path: '/', redirect: '/overview' }, { path: '/login', component: Login },
  { path: '/overview', component: Overview }, { path: '/nodes', component: Nodes },
  { path: '/rules', component: Rules }, { path: '/about', component: About },
  { path: '/whitelist', component: Whitelist },
  { path: '/audit', component: Audit },
  { path: '/settings', component: Settings },
] })
await initialize(router)
router.beforeEach(to => guard(to.path, to.fullPath))
createApp(App).use(i18n).use(router).mount('#app')
setInterval(() => { state.now = Date.now() }, 1000)
