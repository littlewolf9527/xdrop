import type {
  Nodes, Traffic, RuleSignal
} from './types'
export interface Stream {
  readyState: number;
  onerror: (() => void) | null;
  addEventListener(name: string, fn: (event: MessageEvent) => void): void;
  close(): void;

}
export function subscribe(hooks: {
  rules: (v: RuleSignal) => void;
  nodes: (v: Nodes) => void;
  traffic: (v: Traffic) => void;
  me: () => Promise<unknown>
}, create: () => Stream = () => new EventSource('/api/v1/events') as unknown as Stream) {
  let stream: Stream | undefined, timer: ReturnType<typeof setTimeout> | undefined, stopped = false, probing = false
  function open() {
    if (stopped) return
    stream = create()
    for (const name of ['rules', 'nodes', 'traffic'] as const) stream.addEventListener(name, event => {
      if (stopped) return
      try {
        (hooks[name] as (value: unknown) => void)(JSON.parse(event.data))
      } catch (error) {
        console.warn('Invalid event payload', error)
      }

    })
    stream.onerror = async () => {
      if (stream?.readyState !== 2 || probing || stopped) return
      probing = true
      try {
        await hooks.me()
      } catch {
        /* client handles authentication failures */
      }
      finally {
        probing = false
        if (!stopped) timer = setTimeout(open, 3000)

      }

    }

  }
  open()
  return () => {
    stopped = true;
    clearTimeout(timer);
    stream?.close()
  }
}
export function trailingThrottle(action: () => void, delay = 5000) {
  let last = -Infinity, timer: ReturnType<typeof setTimeout> | undefined
  const run = () => {
    timer = undefined;
    last = Date.now();
    action()
  }
  const trigger = () => {
    if (Date.now() - last >= delay) {
      clearTimeout(timer);
      run()
    } else if (!timer) timer = setTimeout(run, delay - (Date.now() - last))
  }
  trigger.cancel = () => { clearTimeout(timer); timer = undefined }
  return trigger
}
