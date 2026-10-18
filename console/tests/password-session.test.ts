import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { createRouter, createMemoryHistory, type Router } from 'vue-router'
let app: typeof import('../src/state'), open: typeof import('../src/password'), i18n: typeof import('../src/i18n')['i18n'], router: Router, w: VueWrapper
let intercept: (path:string)=>Promise<Response>|undefined, account='admin'
const defer=()=>{let resolve!:(v:Response)=>void;const promise=new Promise<Response>(r=>{resolve=r});return{resolve,promise}}
beforeEach(async()=>{
  vi.resetModules();localStorage.clear();localStorage.setItem('xd.lang','zh-CN');account='admin';intercept=()=>undefined
  vi.stubGlobal('matchMedia',()=>({matches:false,addEventListener:vi.fn()}));vi.stubGlobal('EventSource',class{readyState=1;addEventListener(){}close(){}})
  vi.stubGlobal('fetch',vi.fn(async(input:string,init?:RequestInit)=>{
    const path=input.replace('/api/v1',''), pending=intercept(path);if(pending)return pending
    if(path==='/auth/me')return Response.json({name:account,role:'admin'})
    if(path==='/auth/me/prefs')return init?.method==='PUT'?new Response(null,{status:204}):Response.json({lang:'zh-CN'})
    if(path==='/settings')return Response.json({default_language:'zh-CN'})
    if(path==='/auth/me/password')return new Response(null,{status:204})
    if(path==='/capacity')return Response.json({tightest:{name:'cond',ratio:0,exhausted:false},dimensions:[]})
    return Response.json({})
  }))
  app=await import('../src/state');open=await import('../src/password');i18n=(await import('../src/i18n')).i18n
  const Login=(await import('../src/views/Login.vue')).default,App=(await import('../src/App.vue')).default
  router=createRouter({history:createMemoryHistory(),routes:[{path:'/login',component:Login},...['/overview','/nodes','/audit'].map(path=>({path,component:{template:'<div />'}}))]})
  await router.push('/audit');await router.isReady();await app.initialize(router);router.beforeEach(to=>app.guard(to.path,to.fullPath))
  w=mount(App,{attachTo:document.body,global:{plugins:[router,i18n]}});await flushPromises()
})
afterEach(()=>{w.unmount();app.expire();vi.unstubAllGlobals()})
async function submit(){await w.get('#own-current_password').setValue('example-password-1');await w.get('#own-password').setValue('example-password-2');await w.get('#own-confirmation').setValue('example-password-2');await w.get('#password-form').trigger('submit');await flushPromises()}
it('G2 sidebar and reusable openPassword focus first input; Esc restores trigger and resets fields',async()=>{
  const button=w.get('.password-trigger');(button.element as HTMLButtonElement).focus();await button.trigger('click');await flushPromises()
  expect(document.activeElement).toBe(w.get('#own-current_password').element);expect(w.findAll('[role=dialog]')).toHaveLength(1)
  await w.get('#own-current_password').setValue('example-password-1');document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));await flushPromises()
  expect(open.passwordOpen.value).toBe(false);expect(w.find('.password-drawer').exists()).toBe(false);expect(document.activeElement).toBe(button.element)
  open.openPassword();await flushPromises();expect(w.findAll('.password-drawer')).toHaveLength(1);expect((w.get('#own-current_password').element as HTMLInputElement).value).toBe('')
})
it('G2 V1 successful 204 expires and routes to login with one-time notice',async()=>{
  const expired=vi.spyOn(app,'expire');open.openPassword();await flushPromises();await submit()
  expect(expired).toHaveBeenCalledTimes(1);expect(app.state.user).toBeNull();expect(router.currentRoute.value.path).toBe('/login');expect(open.passwordOpen.value).toBe(false)
  expect(w.get('[role=status]').text()).toBe('密码已修改，请用新密码登录')
  await app.login('admin','example-password-1');await router.push('/overview');await flushPromises();app.state.user=null;await router.push('/login');await flushPromises()
  expect(w.find('[role=status]').exists()).toBe(false)
})
it('G2 V24 real expire unmounts drawer and resets open state before a late 400',async()=>{
  const pending=defer();intercept=p=>p==='/auth/me/password'?pending.promise:undefined;open.openPassword();await flushPromises();await submit()
  app.expire();await flushPromises();expect(open.passwordOpen.value).toBe(false);expect(w.find('.password-drawer').exists()).toBe(false)
  pending.resolve(Response.json({code:'invalid_field',field:'password',message:''},{status:400}));await flushPromises()
  expect(app.state.notice).toBe('');expect(app.state.error).toBe('');intercept=()=>undefined;await app.login('admin','example-password-1');await router.push('/audit');await flushPromises()
  expect(open.passwordOpen.value).toBe(false);expect(w.find('.password-drawer').exists()).toBe(false)
})
it('G2 V21a login submit clears notice while same login instance and request remain pending',async()=>{
  app.expire();await flushPromises();app.state.notice='passwordChanged';await flushPromises();const form=w.get('form').element,pending=defer()
  expect(w.get('[role=status]').text()).toContain('密码已修改');intercept=p=>p==='/auth/login'?pending.promise:undefined
  await w.get('form').trigger('submit');await flushPromises();expect(w.get('form').element).toBe(form);expect(w.find('[role=status]').exists()).toBe(false);expect(app.state.notice).toBe('')
  pending.resolve(Response.json({}));await flushPromises()
})
it('G2 V21b leaving and re-entering login clears notice independently of submit and expire',async()=>{
  app.expire();await flushPromises();app.state.notice='passwordChanged';await flushPromises();expect(w.find('[role=status]').exists()).toBe(true)
  app.state.user={name:'admin',role:'admin'};await router.push('/overview');await flushPromises();app.state.user=null;await router.push('/login');await flushPromises()
  expect(app.state.notice).toBe('');expect(w.find('[role=status]').exists()).toBe(false)
})
