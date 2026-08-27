import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const auth = readFileSync(new URL('../../lib/auth.tsx', import.meta.url), 'utf8')
const runtimeApi = readFileSync(new URL('../../lib/runtime-api.ts', import.meta.url), 'utf8')
const session = readFileSync(new URL('../../lib/runtime-session.ts', import.meta.url), 'utf8')
const login = readFileSync(new URL('./login-page.tsx', import.meta.url), 'utf8')
const callback = readFileSync(new URL('./identity-callback-page.tsx', import.meta.url), 'utf8')
const router = readFileSync(new URL('../../router.tsx', import.meta.url), 'utf8')

describe('Identity browser SDK integration', () => {
  it('keeps both access and refresh credentials out of Web Storage', () => {
    expect(session).toContain('accessToken: undefined')
    expect(session).not.toContain('refreshToken:')
    expect(auth).not.toContain('refresh_token')
    expect(runtimeApi).not.toContain('readStoredSession()?.accessToken')
  })

  it('uses one SDK client for password, refresh, logout, and password rotation', () => {
    expect(auth).toContain('identityClient.loginWithPassword')
    expect(auth).toContain('identityClient.refresh()')
    expect(auth).toContain('identityClient.logout()')
    expect(runtimeApi).toContain('identityClient.changePassword')
  })

  it('exposes configured federated and OTP providers with a code callback', () => {
    expect(login).toContain('beginFederatedLogin(provider.key)')
    expect(login).toContain('verifyOTP(otpProvider.key')
    expect(router).toContain("path: '/auth/callback'")
    expect(callback).toContain('completeFederatedLoginFromLocation(window.location.href)')
  })
})
