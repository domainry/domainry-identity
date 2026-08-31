import type { IdentitySession } from '@domainry/identity-client'

export const RUNTIME_SESSION_KEY = 'identity-admin-runtime-session'

export type RuntimeUser = IdentitySession['user']
export type RuntimeRole = IdentitySession['roles'][number]

export interface Session {
  username: string
  displayName: string
  loginAt: string
  roleId: string
  accessToken: string
  expiresAt: string
  remember: boolean
  user: RuntimeUser
  roles: RuntimeRole[]
  permissions: string[]
  mustChangePassword: boolean
}

function storageFor(remember: boolean): Storage {
  return remember ? window.localStorage : window.sessionStorage
}

function readFrom(storage: Storage, remember: boolean): Session | null {
  const raw = storage.getItem(RUNTIME_SESSION_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Partial<Session>
    if (
      typeof parsed.expiresAt !== 'string' ||
      !parsed.user ||
      !Array.isArray(parsed.roles)
    ) {
      storage.removeItem(RUNTIME_SESSION_KEY)
      return null
    }
    return {
      ...parsed,
      accessToken: '',
      remember,
      mustChangePassword: parsed.mustChangePassword === true,
    } as Session
  } catch {
    storage.removeItem(RUNTIME_SESSION_KEY)
    return null
  }
}

export function readStoredSession(): Session | null {
  if (typeof window === 'undefined') return null
  return readFrom(window.sessionStorage, false) ?? readFrom(window.localStorage, true)
}

export function persistSession(session: Session) {
  const target = storageFor(session.remember)
  const other = storageFor(!session.remember)
  other.removeItem(RUNTIME_SESSION_KEY)
  // Authentication credentials never enter Web Storage. The short-lived
  // access token stays in IdentityClient memory; refresh is an HttpOnly cookie.
  target.setItem(RUNTIME_SESSION_KEY, JSON.stringify({ ...session, accessToken: undefined }))
}

export function clearStoredSessions() {
  window.localStorage.removeItem(RUNTIME_SESSION_KEY)
  window.sessionStorage.removeItem(RUNTIME_SESSION_KEY)
}
