import type {
  ErrorEnvelope
} from './types'
export class ApiError extends Error {
  constructor(public status: number, public envelope: ErrorEnvelope, public headers = new Headers()) {
    super(envelope.message)
  }
}
export function createClient(hooks: {
  expired: () => void;
  demoted: () => Promise<void>
}, transport: typeof fetch = (...args) => fetch(...args)) {
  return async function request<T>(path: string, init: RequestInit = {
  }): Promise<T> {
    const response = await transport('/api/v1' + path, {
      ...init, credentials: 'same-origin', headers: {
        ...(init.body ? {
          'Content-Type': 'application/json'
        } : {
        }), ...init.headers
      }
    })
    if (!response.ok) {
      const envelope = await response.json().catch(() => ({
        code: 'network', message: 'Request failed'
      })) as ErrorEnvelope
      if (response.status === 401 && envelope.code !== 'invalid_credentials') hooks.expired()
      if (response.status === 403 && envelope.code === 'admin_required') await hooks.demoted()
      throw new ApiError(response.status, envelope, response.headers)

    }
    if (response.status === 204) return undefined as T
    const body = await response.text()
    return (body === '' ? undefined : JSON.parse(body)) as T

  }
}
export function loginError(error: unknown): 'loginFailed' | 'unreachable' {
  return error instanceof ApiError ? 'loginFailed' : 'unreachable'
}
