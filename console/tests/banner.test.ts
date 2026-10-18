import { it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import { ApiError } from '../src/api/client'
import { genericKey } from '../src/errors'
const error=(code:string,extra={})=>new ApiError(400,{code,message:'private',...extra})
it.each(['bad_request','invalid_field','forbidden','admin_required','node_not_found','route_not_found','method_not_allowed','gen_epoch_mismatch','internal'])('G5 generic code %s',code=>expect(genericKey(error(code))).toBe('errors.'+code))
it.each(['not_found','rule_conflict','invalid_credentials','login_throttled','user_exists','unavailable'])('G5 V17 excluded code %s',code=>expect(genericKey(error(code))).toBe('operationFailed'))
it('G5 V15 TypeError and ordinary Error',()=>{expect(genericKey(new TypeError('offline'))).toBe('unreachable');expect(genericKey(new Error('private'))).toBe('operationFailed')})
it('G5 V16 field and table cannot select rule-specific messages',()=>{expect(genericKey(error('invalid_field',{field:'conditions'}))).toBe('errors.invalid_field');expect(genericKey(error('table_full',{table:'cond'}))).toBe('operationFailed')})
let app:typeof import('../src/state'),w:VueWrapper,intercept:(path:string)=>Promise<Response>|undefined
beforeEach(()=>{vi.stubGlobal('matchMedia',()=>({matches:false,addEventListener:vi.fn()}));vi.stubGlobal('EventSource',class{readyState=1;addEventListener(){}close(){}})})
afterEach(()=>{w?.unmount();app?.expire();vi.unstubAllGlobals()})
it('G5 V18 node sync and network banner store keys and retranslate; 401 ignored and expire clears',async()=>{
  vi.resetModules();localStorage.clear();localStorage.setItem('xd.lang','zh-CN');intercept=()=>undefined
  vi.stubGlobal('fetch',vi.fn(async(input:string,init?:RequestInit)=>{
    const path=input.replace('/api/v1',''),pending=intercept(path);if(pending)return pending
    if(path==='/auth/me')return Response.json({name:'admin',role:'admin'})
    if(path==='/auth/me/prefs')return init?.method==='PUT'?new Response(null,{status:204}):Response.json({lang:'zh-CN'})
    if(path==='/settings')return Response.json({default_language:'zh-CN'})
    if(path==='/capacity')return Response.json({tightest:{name:'cond',ratio:0},dimensions:[]})
    return Response.json({})
  }))
  app=await import('../src/state');const i18n=(await import('../src/i18n')).i18n,App=(await import('../src/App.vue')).default,Nodes=(await import('../src/views/Nodes.vue')).default
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/nodes',component:Nodes},{path:'/login',component:{template:'<div />'}}]});await router.push('/nodes');await router.isReady();await app.initialize(router)
  app.state.nodes=[{name:'edge-01',online:true,base_url: "http://192.0.2.1", key_unreadable: false, incompatible:false,rules:{state:'normal',reason:'',confirmed_gen:1,confirmable:true,rejected:[]},whitelist:{state:'normal',reason:'',confirmed_gen:1,confirmable:true,rejected:[]},health_at:'2026-10-17T00:00:05Z',health:{rules_synced:true,whitelist_synced:true},rates:null,stats:null}]
  w=mount(App,{global:{plugins:[router,i18n]}});await flushPromises();intercept=p=>p.endsWith('/sync')?Promise.resolve(Response.json({code:'node_not_found',message:''},{status:404})):undefined
  const sync=w.findAll('button').find(b=>b.text()==='重新同步')!;expect(sync).toBeDefined();await sync.trigger('click');await flushPromises()
  expect(app.state.error).toBe('errors.node_not_found');expect(w.get('.error-banner').text()).toContain('节点不存在')
  app.setLanguage('en-US');await flushPromises();expect(w.get('.error-banner').text()).toContain(i18n.global.t('errors.node_not_found'));expect(w.get('.error-banner').text()).not.toContain('节点不存在')
  app.setLanguage('zh-CN');intercept=p=>p.startsWith('/traffic/history')?Promise.reject(new TypeError('offline')):undefined;await app.loadHistory();await flushPromises()
  expect(app.state.error).toBe('unreachable');expect(w.get('.error-banner').text()).toContain('无法连接')
  app.state.error='';app.captureSession().report(new (await import('../src/api/client')).ApiError(401,{code:'invalid_credentials',message:''}));expect(app.state.error).toBe('')
  app.state.error='errors.node_not_found';app.expire();expect(app.state.error).toBe('')
})
it('G5 V18 isolated visible banner retranslation after language switch',async()=>{
  vi.resetModules();vi.stubGlobal('fetch',vi.fn(async(_path:string,init?:RequestInit)=>init?.method==='PUT'?new Response(null,{status:204}):Response.json({})))
  app=await import('../src/state');app.state.user={name:'admin',role:'admin'};app.state.lang='zh-CN';app.applyAppearance()
  const {i18n}=await import('../src/i18n'),App=(await import('../src/App.vue')).default
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/audit',component:{template:'<div />'}}]});await router.push('/audit');await router.isReady()
  w=mount(App,{global:{plugins:[router,i18n]}});app.captureSession().report(new TypeError('offline'));await flushPromises()
  expect(w.get('.error-banner').text()).toContain(i18n.global.t('unreachable'));const chinese=w.get('.error-banner').text()
  app.setLanguage('en-US');await flushPromises();expect(w.get('.error-banner').text()).toContain(i18n.global.t('unreachable'));expect(w.get('.error-banner').text()).not.toBe(chinese)
})
