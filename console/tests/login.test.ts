import {
  it, expect, vi
} from 'vitest'
import {
  mount, flushPromises
} from '@vue/test-utils'
import {
  createRouter, createMemoryHistory
} from 'vue-router'
import {
  createI18n
} from 'vue-i18n'
import {
  ApiError
} from '../src/api/client'
import {
  messages
} from '../src/i18n'
import {
  loginLanguage, resolveTheme
} from '../src/preferences'
const {
  login
} = vi.hoisted(() => ({
  login: vi.fn()
}))
vi.mock('../src/state', () => ({
  login, state: {
    theme: 'auto', lang: 'zh-CN'
  }, setLanguage: vi.fn(), setTheme: vi.fn()
}))
import Login from '../src/views/Login.vue'
it('V2 login 401 and 429 display the same message without retry seconds in all languages', async () => {
  for (const locale of ['zh-CN', 'ja-JP', 'en-US'] as const) {
    const texts = []
    for (const status of [401, 429]) {
      login.mockRejectedValueOnce(new ApiError(status, {
        code: status === 401 ? 'invalid_credentials' : 'login_throttled', message: 'private implementation detail'
      }, new Headers({
        'Retry-After': '60'
      })))
      const router = createRouter({
        history: createMemoryHistory(), routes: [{
          path: '/login', component: {
            template: '<div />'
          }
        }]
      });
      await router.push('/login');
      await router.isReady()
      const wrapper = mount(Login, {
        global: {
          plugins: [router, createI18n({
            legacy: false, locale, messages
          })]
        }
      })
      await wrapper.get('form').trigger('submit');
      await flushPromises()
      const text = wrapper.get('[role="alert"]').text();
      texts.push(text)
      expect(text).toBe(messages[locale].loginFailed);
      expect(text).not.toMatch(/60|Retry|private|稍后|锁定/);
      wrapper.unmount()

    }
    expect(texts[0]).toBe(texts[1])

  }
})

it('preloaded login preferences and credential entry never submit credentials', async () => {
  login.mockClear()
  const router = createRouter({
    history: createMemoryHistory(), routes: [{
      path: '/login', component: {
        template: '<div />'
      }
    }]
  });
  await router.push('/login');
  await router.isReady()
  localStorage.setItem('xd.lang', 'ja-JP');
  localStorage.setItem('xd.theme', 'dark')
  const locale = loginLanguage(['en-US']);
  expect(locale).toBe('ja-JP');
  expect(resolveTheme(null, localStorage.getItem('xd.theme'))).toBe('dark')
  const wrapper = mount(Login, {
    attachTo: document.body, global: {
      plugins: [router, createI18n({
        legacy: false, locale, messages
      })]
    }
  })
  await wrapper.get('input[autocomplete="username"]').setValue('admin');
  await wrapper.get('input[autocomplete="current-password"]').setValue('example-password-1')
  await flushPromises()
  expect(wrapper.findAll('.preferences button')).toHaveLength(0)
  expect(login).not.toHaveBeenCalled()
  expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  expect(wrapper.findAll('input')).toHaveLength(2)
  expect(wrapper.findAll('button')).toHaveLength(1)
  expect(wrapper.get('button').attributes('type')).toBe('submit')
  wrapper.unmount();
  localStorage.clear()
})


it('V-r6 login has no appearance or language controls', async () => {
  const router = createRouter({
    history: createMemoryHistory(), routes: [{
      path: '/login', component: {
        template: '<div />'
      }
    }]
  });
  await router.push('/login');
  await router.isReady()
  const wrapper = mount(Login, {
    global: {
      plugins: [router, createI18n({
        legacy: false, locale: 'zh-CN', messages
      })]
    }
  })
  expect(wrapper.find('.preferences').exists()).toBe(false)
  expect(wrapper.find('[aria-label="外观"]').exists()).toBe(false)
  expect(wrapper.find('[aria-label="语言"]').exists()).toBe(false)
  expect(wrapper.findAll('button')).toHaveLength(1)
  expect(wrapper.get('button').text()).toBe(messages['zh-CN'].login)
  expect(wrapper.get('.logo-full').attributes('aria-label')).toBe('XDROP')
  expect(wrapper.findAll('input')).toHaveLength(2)
  wrapper.unmount()
})

it('P2-4 login initialization failure displays existing operationFailed text', async () => {
  login.mockResolvedValueOnce(false)
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/login', component: { template: '<div />' } }] })
  await router.push('/login'); await router.isReady()
  const wrapper = mount(Login, { global: { plugins: [router, createI18n({ legacy: false, locale: 'zh-CN', messages })] } })
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(wrapper.get('[role="alert"]').text()).toBe(messages['zh-CN'].operationFailed)
  expect(router.currentRoute.value.path).toBe('/login')
  wrapper.unmount()
})
