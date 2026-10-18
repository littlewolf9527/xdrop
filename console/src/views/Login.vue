<script setup lang="ts">
import {
  ref, onBeforeUnmount
} from 'vue'
import {
  useRouter, useRoute
} from 'vue-router'
import {
  useI18n
} from 'vue-i18n'
import {
  ElButton, ElInput
} from 'element-plus'
import {
  login, state
} from '../state'
import {
  loginError
} from '../api/client'
const {
  t
} = useI18n(), router = useRouter(), route = useRoute()
const username = ref(''), password = ref(''), error = ref(''), busy = ref(false)
onBeforeUnmount(() => { state.notice = '' })
async function submit() {
  if (busy.value) return
  state.notice = '';
  busy.value = true;
  error.value = ''
  try {
    if (await login(username.value, password.value) === false) { error.value = 'operationFailed'; return }
    const next = route.query.next;
    await router.replace(typeof next === 'string' && /^\/(?!\/)/.test(next) && next !== '/login' ? next : '/overview')
  }
  catch (e) {
    error.value = loginError(e)
  } finally {
    busy.value = false
  }
}
</script>
<template>
  <div
    class="login-wrap"
  >
    <form
      class="login panel"
      @submit.prevent="submit"
    >
      <div
        class="login-brand"
      >
        <span
          class="logo-full"
          role="img"
          aria-label="XDROP"
         />
      </div>
      <p v-if="state.notice" class="password-notice" role="status">{{ t(state.notice) }}</p>
      <label
        for="username"
      >{{ t('username') }}</label>
      <ElInput
        id="username"
        v-model="username"
        autocomplete="username"
       />
      <label
        for="password"
      >{{ t('password') }}</label>
      <ElInput
        id="password"
        v-model="password"
        type="password"
        autocomplete="current-password"
       />
      <p
        v-if="error"
        class="error-text"
        role="alert"
      >{{ t(error) }}</p>
      <ElButton
        native-type="submit"
        type="primary"
        :loading="busy"
      >{{ t('login') }}</ElButton>
    </form>
    <p class="login-copyright">© 2026 LittleWolf</p>
  </div>
</template>

<style scoped>
.password-notice { margin: 0; overflow-wrap: anywhere; }
</style>
