import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const source = readFileSync(new URL('./login-page.tsx', import.meta.url), 'utf8')
const authSource = readFileSync(new URL('../../lib/auth.tsx', import.meta.url), 'utf8')

describe('Admin login error contract', () => {
  it('uses the credential message only for invalid credentials', () => {
    expect(source).toContain("code === 'auth.invalid_credentials'")
    expect(source).toContain("code === 'auth.account_locked'")
    expect(source).toContain("t('login.unavailable')")
  })

  it('persists the authenticated session before optional permission enrichment', () => {
    const loginStart = authSource.indexOf('const response = await identityClient.loginWithPassword')
    const persist = authSource.indexOf('persistSession(next)', loginStart)
    const enrichment = authSource.indexOf('void fetchRuntimeMe(response.access_token)', loginStart)
    expect(loginStart).toBeGreaterThanOrEqual(0)
    expect(persist).toBeGreaterThan(loginStart)
    expect(enrichment).toBeGreaterThan(persist)
    expect(authSource).toContain('.catch(() => undefined)')
  })
})
