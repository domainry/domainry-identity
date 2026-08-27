import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

describe('workforce directory ownership boundary', () => {
  it('loads the directory only from the Workforce Profile endpoint', () => {
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const start = api.indexOf('export const workforceApi')
    const directoryMethods = api.slice(start, api.indexOf('  async detail(', start))

    expect(directoryMethods).toContain('"/identity/workforce"')
    expect(directoryMethods).toContain('/identity/workforce/search?')
    expect(directoryMethods).not.toContain('/identity/users')
    expect(directoryMethods).not.toContain('runtimeUsers')
  })

  it('renders Workforce Profile facts without account-directory fields', () => {
    const page = readFileSync(new URL('./workforce-page.tsx', import.meta.url), 'utf8')

    expect(page).toContain('useWorkforceProfiles')
    expect(page).toContain('profile.workerNo')
    expect(page).toContain('profile.workStatus')
    for (const accountField of ['account.email', 'account.phone', 'useIdentityAccounts']) {
      expect(page).not.toContain(accountField)
    }
  })

  it('offers every governed employee lifecycle operation without Promise.all orchestration', () => {
    const page = readFileSync(new URL('./workforce-page.tsx', import.meta.url), 'utf8')
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    for (const operation of ['invite', 'onboard', 'assign', 'transfer', 'add_secondary', 'suspend', 'terminate', 'revoke_access']) {
      expect(page).toContain(`'${operation}'`)
    }
    expect(api).toContain('/lifecycle')
    expect(api).toContain('/terminate')
    expect(page).not.toContain('Promise.all')
  })

  it('creates an employee through the single atomic onboarding command', () => {
    const page = readFileSync(new URL('./workforce-page.tsx', import.meta.url), 'utf8')
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const inviteBranch = page.slice(
      page.indexOf("if (operation === 'invite')"),
      page.indexOf("} else if (operation === 'terminate')"),
    )

    expect(api).toContain('"/identity/workforce/onboard"')
    expect(inviteBranch).toContain('onboard.mutateAsync')
    expect(inviteBranch).toContain('user:')
    expect(inviteBranch).toContain('profile:')
    expect(inviteBranch).toContain('assignment:')
    expect(inviteBranch).toContain('role_ids:')
    expect(inviteBranch).not.toContain('usersApi.')
    expect(inviteBranch).not.toContain('workforceApi.lifecycle')
    expect(inviteBranch).not.toContain('roleAssignmentsApi.')
    expect(inviteBranch).not.toContain('Promise.all')
  })

  it('publishes receipt-backed batch transfer, grant, and revoke commands', () => {
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const batchMethods = api.slice(api.indexOf('  transferBatch('), api.indexOf('  lifecycle(', api.indexOf('  transferBatch(')))

    expect(batchMethods).toContain('"/identity/workforce/transfers/batch"')
    expect(batchMethods).toContain('"/identity/entitlements/batch"')
    expect(batchMethods).toContain('"Idempotency-Key"')
    expect(batchMethods).not.toContain('Promise.all')
  })
})
