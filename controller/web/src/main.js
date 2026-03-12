import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import router from './router'
import { i18n } from './locales'
import App from './App.vue'
import './style.css'

// Tree-shaken icon imports (24 icons used)
import {
    Aim, ArrowDown, Brush, ChatLineSquare, CircleCheck,
    CircleCloseFilled, Delete, DocumentAdd, InfoFilled, Key,
    List, Lock, Monitor, Moon, Odometer, Plus, Promotion,
    Refresh, Search, Setting, Sunny, SwitchButton, User, View
} from '@element-plus/icons-vue'

const app = createApp(App)

// Register only used icons
const icons = {
    Aim, ArrowDown, Brush, ChatLineSquare, CircleCheck,
    CircleCloseFilled, Delete, DocumentAdd, InfoFilled, Key,
    List, Lock, Monitor, Moon, Odometer, Plus, Promotion,
    Refresh, Search, Setting, Sunny, SwitchButton, User, View
}
for (const [name, component] of Object.entries(icons)) {
    app.component(name, component)
}

app.use(ElementPlus)
app.use(router)
app.use(i18n)
app.mount('#app')
