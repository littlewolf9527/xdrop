import {
  reactive, computed
} from 'vue'
import type {
  Router
} from 'vue-router'
import {
  createClient, ApiError
} from './api/client'
import {
  subscribe, trailingThrottle
} from './api/events'
import type {
  Capacity, Identity, History, Nodes, Overview, Top, Preferences, Rule, Range, Language, Theme
} from './api/types'
import {
  createPreferencesWriter, loginLanguage, resolveLanguage, resolveTheme, stored, storeLocal, readLayout, clampSplit, defaultOrder
} from './preferences'
import {
  i18n
} from './i18n'
import { genericKey } from './errors'
export const state = reactive({
  user: null as Identity | null, ready: false, lang: loginLanguage() as Language, theme: resolveTheme(null, stored('xd.theme')) as Theme,
  nodes: [] as Nodes['nodes'], capacity: null as Capacity | null,
  overview: {
    dropped_pps: 0, passed_pps: 0, dropped_bytes_ps: 0, passed_bytes_ps: 0, nodes_online: 0, nodes_total: 0
  } as Overview,
  top: {
    targets: [], rules: [], updated_at: null, targets_total: 0
  } as Top,
  history: {
    step_s: 5, points: []
  } as History, range: '15m' as Range,
  layout: readLayout({
  }), rules: {
  } as Record<string, Rule>, now: Date.now(), error: '', notice: '',
})
let router: Router, closeStream: (() => void) | undefined, started = false, generation = 0, historyAt = -Infinity, seq: number | undefined
let layoutTimer: ReturnType<typeof setTimeout> | undefined
const scheme = matchMedia('(prefers-color-scheme: dark)')
export function applyAppearance() {
  document.documentElement.dataset.theme = state.theme === 'auto' ? scheme.matches ? 'dark' : 'light' : state.theme
  document.documentElement.lang = state.lang
  i18n.global.locale.value = state.lang
}
scheme.addEventListener('change', applyAppearance)
applyAppearance()
export const canSettings = computed(() => state.user?.role === 'admin')
export function expire() {
  const next = router?.currentRoute.value.fullPath || '/overview'
  generation++;
  started = false;
  closeStream?.();
  closeStream = undefined;
  capacityTrigger.cancel();
  clearTimeout(layoutTimer)
  state.user = null;
  state.overview = {
    dropped_pps: 0, passed_pps: 0, dropped_bytes_ps: 0, passed_bytes_ps: 0, nodes_online: 0, nodes_total: 0
  };
  state.nodes = [];
  state.rules = {
  };
  state.capacity = null;
  state.top = {
    targets: [], rules: [], updated_at: null, targets_total: 0
  };
  state.history = {
    step_s: 5, points: []
  }
  state.layout = readLayout({});
  state.error = '';
  state.notice = '';
  state.lang = loginLanguage();
  state.theme = resolveTheme(null, stored('xd.theme'));
  applyAppearance()
  if (state.ready && router && router.currentRoute.value.path !== '/login') void router.replace({
    path: '/login', query: {
      next
    }
  })
}
export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const current = generation
  return createClient({
    expired: () => { if (current === generation) expire() },
    demoted: async () => {
      if (current !== generation) return
      await refreshIdentity(current)
      if (current === generation) await router.replace('/overview')
    }
  })<T>(path, init)
}
export async function refreshIdentity(current = generation) {
  const user = await request<Identity>('/auth/me');
  if (current !== generation) return
  state.user = user;
  return user
}
const writePreferences = createPreferencesWriter(() => request<Preferences>('/auth/me/prefs'), body => request('/auth/me/prefs', {
  method: 'PUT', body
}))
function report(error: unknown, current: number) {
  if (current !== generation) return
  if (!(error instanceof ApiError && error.status === 401)) state.error = genericKey(error)
}
export function captureSession() {
  const current = generation
  return { isCurrent: () => current === generation, report: (error: unknown) => report(error, current) }
}
async function save(patch: Preferences) {
  const current = generation
  if (state.user) try {
    await writePreferences(patch, () => current === generation)
  } catch (error) {
    if (current === generation) report(error, current)
  }
}
export function setLanguage(value: Language) {
  state.lang = value;
  storeLocal('xd.lang', value);
  applyAppearance();
  void save({
    lang: value
  })
}
export function setTheme(value: Theme) {
  state.theme = value;
  storeLocal('xd.theme', value);
  applyAppearance();
  void save({
    theme: value
  })
}
export function saveLayout() {
  clearTimeout(layoutTimer);
  layoutTimer = setTimeout(() => {
    void save({
      overview: {
        order: [...state.layout.order], split: clampSplit(state.layout.split)
      }
    })
  }, 500)
}
export function setSplit(value: number) {
  state.layout.split = clampSplit(value);
  saveLayout()
}
export function swapPanels(from: number, to: number) {
  if (from === to) return;
  const order = [...state.layout.order];
  [order[from], order[to]] = [order[to]!, order[from]!];
  state.layout.order = order;
  saveLayout()
}
export function restoreLayout() {
  state.layout = {
    order: [...defaultOrder], split: 1.4
  };
  saveLayout()
}
export async function loadHistory() {
  const range = state.range, current = generation
  historyAt = Date.now()
  try {
    const result = await request<History>('/traffic/history?range=' + range);
    if (current === generation && range === state.range) state.history = result
  } catch (error) {
    report(error, current)
  }
}
export function setRange(value: Range) {
  state.range = value;
  void loadHistory()
}
async function loadCapacity() {
  const current = generation;
  try {
    const result = await request<Capacity>('/capacity');
    if (current === generation) state.capacity = result
  } catch (error) {
    report(error, current)
  }
}
const capacityTrigger = trailingThrottle(() => {
  if (state.user) void loadCapacity()
})
async function loadRules() {
  const current = generation, currentSeq = seq
  await Promise.all(state.top.rules.map(async ({
    rule_id
  }) => {
    if (state.rules[rule_id]) return
    try {
      const rule = await request<Rule>('/rules/' + encodeURIComponent(rule_id));
      if (current === generation && currentSeq === seq) state.rules[rule_id] = rule
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 404)) report(error, current)
    }

  }))
}
export function startData(current = generation) {
  if (current !== generation || !state.user || started) return
  started = true;
  historyAt = -Infinity;
  seq = undefined
  closeStream = subscribe({
    me: refreshIdentity,
    rules: signal => {
      if (seq !== signal.seq) {
        seq = signal.seq;
        state.rules = {
        };
        void loadRules()
      };
      capacityTrigger()
    },
    nodes: value => {
      state.nodes = value.nodes;
      capacityTrigger()
    },
    traffic: value => {
      state.overview = value.overview;
      state.top = value.top;
      void loadRules();
      if (Date.now() - historyAt >= state.history.step_s * 1000) void loadHistory()
    },

  })
  capacityTrigger()
}
export async function session() {
  const current = generation
  if (!await refreshIdentity(current) || current !== generation) return false
  const [prefs, settings] = await Promise.all([request<Preferences>('/auth/me/prefs'), request<{
    default_language: Language
  }>('/settings')])
  if (current !== generation) return false
  state.lang = resolveLanguage(prefs.lang, navigator.languages, settings.default_language)
  state.theme = resolveTheme(prefs.theme, stored('xd.theme'));
  state.layout = readLayout(prefs)
  applyAppearance();
  startData(current)
  return true
}
export async function initialize(r: Router) {
  router = r;
  try {
    await session()
  } catch {
    /* unauthenticated starts on login */
  } finally {
    state.ready = true
  }
}
export async function login(username: string, password: string) {
  const current = generation
  await request('/auth/login', {
    method: 'POST', body: JSON.stringify({
      username, password
    })
  });
  if (current !== generation) return false
  try { return await session() } catch (error) { report(error, current); return false }
}
export async function logout() {
  const current = generation
  try {
    await request('/auth/logout', {
      method: 'POST'
    })
  } finally {
    if (current === generation) expire()
  }
}
export async function guard(path: string, fullPath: string) {
  if (path === '/login') return state.user ? '/overview' : true
  if (!state.user) return {
    path: '/login', query: {
      next: fullPath
    }
  }
  if (path === '/settings') {
    const current = generation
    try {
      if (!await refreshIdentity()) return false
    } catch (error) {
      if (current !== generation) return false
      if (error instanceof ApiError && error.status === 401) return { path: '/login', query: { next: fullPath } }
      if (error instanceof ApiError && error.status === 403 && error.envelope.code === 'admin_required') return '/overview'
      report(error, current)
      return false
    };
    if (!canSettings.value) return '/overview'
  }
  return true
}
