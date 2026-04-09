<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-logo">
        <div class="logo-icon">
          <el-icon size="32"><Aim /></el-icon>
        </div>
        <h1 class="logo-text">XDrop</h1>
      </div>

      <p class="login-subtitle">{{ $t('login.welcome') }}</p>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        @submit.prevent="handleLogin"
        class="login-form"
      >
        <el-form-item prop="username">
          <el-input
            v-model="form.username"
            :placeholder="$t('login.username')"
            size="large"
            :prefix-icon="User"
            @keyup.enter="handleLogin"
          />
        </el-form-item>

        <el-form-item prop="password">
          <el-input
            v-model="form.password"
            type="password"
            :placeholder="$t('login.password')"
            size="large"
            :prefix-icon="Lock"
            show-password
            @keyup.enter="handleLogin"
          />
        </el-form-item>

        <el-button
          type="primary"
          size="large"
          :loading="loading"
          @click="handleLogin"
          class="login-btn"
        >
          {{ $t('login.submit') }}
        </el-button>
      </el-form>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { authApi } from '../api/auth'
import { setAuthenticated } from '../router'

const { t } = useI18n()
const router = useRouter()

const formRef = ref(null)
const loading = ref(false)

const form = reactive({
  username: '',
  password: ''
})

const rules = {
  username: [{ required: true, message: () => t('login.username'), trigger: 'blur' }],
  password: [{ required: true, message: () => t('login.password'), trigger: 'blur' }]
}

const handleLogin = async () => {
  if (!formRef.value) return
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  loading.value = true
  try {
    await authApi.login(form.username, form.password)
    setAuthenticated(true)
    router.push('/')
  } catch (err) {
    ElMessage.error(t('login.error'))
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--xs-bg-primary);
}

.login-card {
  width: 400px;
  padding: 48px 40px;
  background: var(--xs-card-bg);
  border: 1px solid var(--xs-border);
  border-radius: var(--radius-lg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
}

.login-logo {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  margin-bottom: 8px;
}

.logo-icon {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--xs-accent), var(--primary-dark));
  border-radius: 12px;
  color: white;
}

.logo-text {
  font-size: 2rem;
  font-weight: 700;
  background: linear-gradient(135deg, var(--xs-accent), var(--primary-light));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.login-subtitle {
  text-align: center;
  color: var(--xs-text-secondary);
  font-size: 0.9rem;
  margin-bottom: 32px;
}

.login-form {
  display: flex;
  flex-direction: column;
}

.login-btn {
  width: 100%;
  margin-top: 8px;
  height: 44px;
  font-size: 1rem;
  font-weight: 600;
  border-radius: var(--xs-radius);
}
</style>
