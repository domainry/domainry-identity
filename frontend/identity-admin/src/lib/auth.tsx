import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { IdentityProvider, IdentityProviderChallenge, IdentitySession } from '@domainry/identity-client'
import {
  fetchRuntimeMe,
  changeRuntimePassword,
  createRuntimeRequestID,
} from './runtime-api'
import { identityClient } from './identity-client'
import {
  RUNTIME_SESSION_KEY,
  clearStoredSessions,
  persistSession,
  readStoredSession,
  type Session,
} from './runtime-session'

const REFRESH_LEEWAY_MS = 60 * 1000

interface AuthContextValue {
  session: Session | null
	providers: () => Promise<IdentityProvider[]>
  login: (username: string, password: string, options?: { remember?: boolean }) => Promise<Session>
	beginFederatedLogin: (provider: string) => Promise<never>
	beginOTP: (provider: string, phone: string) => Promise<IdentityProviderChallenge>
	verifyOTP: (provider: string, state: string, code: string) => Promise<Session>
	completeFederatedLoginFromLocation: (location: string) => Promise<Session>
  refreshSession: () => Promise<Session | null>
  changePassword: (currentPassword: string, newPassword: string) => Promise<Session>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

function sessionFromRuntime(
  response: IdentitySession,
  remember: boolean,
  permissions: string[] = [],
): Session {
  return {
    username: response.user.email || response.user.id,
    displayName: response.user.name || response.user.id,
    loginAt: new Date().toISOString(),
    roleId: response.default_role,
    accessToken: response.access_token,
    expiresAt: response.expires_at,
    remember,
    user: response.user,
    roles: response.roles,
    permissions,
    mustChangePassword: response.must_change_password === true,
  }
}

export { readStoredSession as getStoredSession }
export type { Session }

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(readStoredSession)
  const queryClient = useQueryClient()
	const providers = useCallback(() => identityClient.providers(), [])

  const login = useCallback(
    async (username: string, password: string, options?: { remember?: boolean }) => {
      const response = await identityClient.loginWithPassword(username.trim(), password)
      const remember = options?.remember ?? true
      const next = sessionFromRuntime(response, remember)
      queryClient.clear()
      persistSession(next)
      setSession(next)
      void fetchRuntimeMe(response.access_token)
        .then((me) => {
          if (identityClient.accessToken() !== response.access_token) return
          const enriched = sessionFromRuntime(
            response,
            remember,
            me.permissions,
          )
          enriched.mustChangePassword = me.must_change_password === true
          persistSession(enriched)
          setSession(enriched)
        })
        .catch(() => undefined)
      return next
    },
    [queryClient]
  )

	const beginFederatedLogin = useCallback((provider: string) => {
		const returnUrl = new URL('/auth/callback', window.location.origin).toString()
		return identityClient.beginFederatedLogin(provider, returnUrl)
	}, [])

	const beginOTP = useCallback((provider: string, phone: string) => (
		identityClient.beginProvider(provider, { phone: phone.trim() })
	), [])

	const acceptProviderSession = useCallback(async (response: IdentitySession) => {
		const me = await fetchRuntimeMe(response.access_token)
		const next = sessionFromRuntime(response, true, me.permissions)
		next.mustChangePassword = me.must_change_password === true
		queryClient.clear()
		persistSession(next)
		setSession(next)
		return next
	}, [queryClient])

	const verifyOTP = useCallback(async (provider: string, state: string, code: string) => {
		const response = await identityClient.verifyOTP(provider, state, code.trim())
		return acceptProviderSession(response)
	}, [acceptProviderSession])

	const completeFederatedLoginFromLocation = useCallback(async (location: string) => {
		const response = await identityClient.completeFederatedLoginFromLocation(location)
		return acceptProviderSession(response)
	}, [acceptProviderSession])

  const refreshSession = useCallback(async () => {
    if (!session) return null
    const response = await identityClient.refresh()
    const me = await fetchRuntimeMe(response.access_token)
    const next = sessionFromRuntime(
      response,
      session.remember,
      me.permissions,
    )
    next.mustChangePassword = me.must_change_password === true
    next.loginAt = session.loginAt
    persistSession(next)
    setSession(next)
    return next
  }, [session])

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    if (!session) throw new Error('auth.token_required')
    const response = await changeRuntimePassword(
      currentPassword,
      newPassword,
      createRuntimeRequestID(),
    )
    const me = await fetchRuntimeMe(response.access_token)
    const next = sessionFromRuntime(
      response,
      session.remember,
      me.permissions,
    )
    next.loginAt = session.loginAt
    next.mustChangePassword = me.must_change_password === true
    queryClient.clear()
    persistSession(next)
    setSession(next)
    return next
  }, [queryClient, session])

  const logout = useCallback(async () => {
    try {
      await identityClient.logout()
    } catch {
      // Local sign-out must still complete when the Runtime session is already
      // expired, unavailable, or rate-limited.
    } finally {
      clearStoredSessions()
      queryClient.clear()
      setSession(null)
    }
  }, [queryClient])

  useEffect(() => {
    const current = readStoredSession()
    const accessTokenBeforeHydration = identityClient.accessToken()
    void identityClient.refresh()
      .then(async (response) => {
        const me = await fetchRuntimeMe(response.access_token)
        const next = sessionFromRuntime(response, current?.remember ?? true, me.permissions)
        if (current?.loginAt) next.loginAt = current.loginAt
        next.mustChangePassword = me.must_change_password === true
        persistSession(next)
        setSession(next)
      })
      .catch(() => {
        if (identityClient.accessToken() !== accessTokenBeforeHydration) return
        clearStoredSessions()
        setSession(null)
      })
  }, []) // hydrate once from the HttpOnly refresh cookie

  useEffect(() => {
    function syncPersistentSession(event: StorageEvent) {
      if (event.key !== RUNTIME_SESSION_KEY || event.storageArea !== window.localStorage) return
      queryClient.clear()
      const stored = readStoredSession()
      setSession(stored)
      if (!stored) return
      void identityClient.refresh()
        .then(async (response) => {
          const me = await fetchRuntimeMe(response.access_token)
          const next = sessionFromRuntime(response, stored.remember, me.permissions)
          next.loginAt = stored.loginAt
          next.mustChangePassword = me.must_change_password === true
          setSession(next)
        })
        .catch(() => void logout())
    }
    window.addEventListener('storage', syncPersistentSession)
    return () => window.removeEventListener('storage', syncPersistentSession)
  }, [queryClient])

  useEffect(() => {
    if (!session) return
    const refreshIn = Math.max(0, Date.parse(session.expiresAt) - Date.now() - REFRESH_LEEWAY_MS)
    const timer = window.setTimeout(() => {
      void refreshSession().catch(() => void logout())
    }, refreshIn)
    return () => window.clearTimeout(timer)
  }, [session, refreshSession, logout])

  const value = useMemo(
    () => ({ session, providers, login, beginFederatedLogin, beginOTP, verifyOTP, completeFederatedLoginFromLocation, refreshSession, changePassword, logout }),
    [session, providers, login, beginFederatedLogin, beginOTP, verifyOTP, completeFederatedLoginFromLocation, refreshSession, changePassword, logout]
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}
