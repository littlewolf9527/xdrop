import { it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
let app:typeof import('../src/state'),w:VueWrapper
it('G2 V29b real expire preserves login next=/settings instead of overview',async()=>{
  vi.resetModules();localStorage.clear();vi.stubGlobal('matchMedia',()=>({matches:false,addEventListener:vi.fn()}));vi.stubGlobal('EventSource',class{readyState=1;addEventListener(){}close(){}})
  vi.stubGlobal('fetch',vi.fn(async(input:string)=>{
    if(input.endsWith('/auth/me'))return Response.json({name:'admin',role:'admin'})
    if(input.endsWith('/settings'))return Response.json({default_language:'zh-CN'})
    if(input.endsWith('/capacity'))return Response.json({tightest:{name:'cond',ratio:0,exhausted:false},dimensions:[]})
    return Response.json({})
  }))
  app=await import('../src/state');const i18n=(await import('../src/i18n')).i18n,Settings=(await import('../src/views/Settings.vue')).default
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/settings',component:Settings},{path:'/login',component:{template:'<div>Login</div>'}},{path:'/overview',component:{template:'<div>Overview</div>'}}]})
  await router.push('/settings');await router.isReady();await app.initialize(router);router.beforeEach(to=>app.guard(to.path,to.fullPath))
  w=mount({template:'<router-view />'},{global:{plugins:[router,i18n]}});await flushPromises();expect(w.find('[role="tablist"]').exists()).toBe(true)
  app.expire();await flushPromises();expect(router.currentRoute.value.path).toBe('/login');expect(router.currentRoute.value.query.next).toBe('/settings');expect(w.text()).toBe('Login')
})
afterEach(()=>{w?.unmount();app?.expire();vi.unstubAllGlobals()})
