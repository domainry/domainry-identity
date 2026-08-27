import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

describe('workforce detail ownership boundary', () => {
  it('shows account and business identity summaries without business profile mutation', () => {
    const page = readFileSync(new URL('./workforce-detail-page.tsx', import.meta.url), 'utf8')
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    expect(page).toContain('value.account')
    expect(page).toContain('value.businessProfiles')
    expect(page).toContain("to='/admin/security/accounts/$userId'")
    expect(page).toContain('userId: value.account.id')
    expect(api).toContain('/detail')
    for (const forbidden of ['identityProfilesApi', 'useUpdateIdentityProfile', 'objectsApi.update']) {
      expect(page).not.toContain(forbidden)
    }
  })

  it('populates the role selector only from the server eligibility endpoint', () => {
    const page = readFileSync(new URL('./workforce-detail-page.tsx', import.meta.url), 'utf8')
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    expect(page).toContain('useWorkforceAssignableRoles')
    expect(page).not.toContain('useRoles')
    expect(page).not.toContain('.filter(')
    expect(api).toContain('/assignable-roles')
    expect(api).toContain('workforce_profile_id: workforceProfileID')
  })
})
