import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { isRegisteredMenuPath, routeContractForPath } from '@/app-route-registry'
import { isRouteAllowed } from '@/router'

describe('identity account directory boundary', () => {
  it('publishes only the restricted security account route', () => {
    expect(isRegisteredMenuPath('/admin/security/accounts')).toBe(true)
    expect(isRegisteredMenuPath('/admin/org/users')).toBe(false)
    expect(routeContractForPath('/admin/security/accounts')?.requiredPermissions).toEqual(['identity.users.read'])
    expect(readFileSync(new URL('../../router.tsx', import.meta.url), 'utf8')).toContain("path: '/admin/security/accounts/$userId'")
  })

  it('does not grant the full account directory to a business Profile operator', () => {
    const businessPermissions = ['identity.profile_binding.manage', 'member_profile.read']
    expect(isRouteAllowed('/business-profiles/member', ['/business-profiles/member'], businessPermissions)).toBe(false)
    expect(isRouteAllowed('/admin/security/accounts', ['/business-profiles/member'], businessPermissions)).toBe(false)
    expect(isRouteAllowed('/admin/org/roles', ['/business-profiles/member'], businessPermissions)).toBe(false)
    expect(routeContractForPath('/admin/org/roles')?.requiredPermissions).toEqual(['identity.roles.read'])
    expect(
      isRouteAllowed(
        '/admin/security/accounts',
        ['/admin/security/accounts'],
        ['identity.users.read'],
        [],
      ),
    ).toBe(true)
  })

  it('keeps workforce, business profile, and entitlement fields out of the account page', () => {
    const page = [
      readFileSync(new URL('./identity-accounts-page.tsx', import.meta.url), 'utf8'),
      readFileSync(new URL('./identity-user-detail-page.tsx', import.meta.url), 'utf8'),
    ].join('\n')
    for (const forbidden of ['employeeNo', 'employmentStatus', 'deptId', 'managerId', 'roleIds', 'BusinessProfiles']) {
      expect(page).not.toContain(forbidden)
    }
  })

  it('keeps Workforce facts out of the Runtime account contract and write projection', () => {
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const identityContract = readFileSync(new URL('../../../../packages/management-contract/src/index.ts', import.meta.url), 'utf8')
    const runtimeUser = identityContract.slice(identityContract.indexOf('export interface IdentityUser {'), identityContract.indexOf('export interface IdentityUserDirectoryEntry'))
    const writeProjection = api.slice(api.indexOf('const identityUserWritableFields'), api.indexOf('function mapIdentityAccount'))

    for (const forbidden of [
      'employee_number',
      'department_id',
      'manager_id',
      'employment_status',
      'employeeNo',
      'deptId',
      'managerId',
      'employmentStatus',
    ]) {
      expect(runtimeUser).not.toContain(forbidden)
      expect(writeProjection).not.toContain(forbidden)
    }
    for (const accountField of ['id:', 'name:', 'email:', 'phone?:', 'status:']) {
      expect(runtimeUser).toContain(accountField)
    }
    expect(writeProjection).toContain('identityUserAuthoringContract.parameters')
    expect(writeProjection).toContain('identityUserWritableFields.has(key)')
    expect(api).toContain('from "@domainry/identity-management-contract"')
  })

  it('keeps the canonical display name independent from optional global name parts', () => {
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const contract = JSON.parse(
      readFileSync(new URL('../../../../packages/management-contract/src/generated/identity-user-authoring-contract.json', import.meta.url), 'utf8'),
    ) as { parameters: Array<{ key: string; required?: boolean }> }
    const accountPages = [
      readFileSync(new URL('./identity-accounts-page.tsx', import.meta.url), 'utf8'),
      readFileSync(new URL('./identity-user-detail-page.tsx', import.meta.url), 'utf8'),
    ].join('\n')
    const structuredFields = [
      'given_name',
      'middle_name',
      'family_name',
      'name_prefix',
      'name_suffix',
      'native_name',
      'name_locale',
    ]

    expect(contract.parameters.find((field) => field.key === 'name')?.required).toBe(true)
    for (const field of structuredFields) {
      expect(contract.parameters.find((parameter) => parameter.key === field)?.required).not.toBe(true)
      expect(api).toContain(`${field}:`)
    }
    for (const field of ['givenName', 'middleName', 'familyName', 'namePrefix', 'nameSuffix', 'nativeName', 'nameLocale']) {
      expect(accountPages).toContain(field)
    }
    const accountApi = api.slice(api.indexOf('export const identityAccountsApi'), api.indexOf('function mapWorkforceProfile'))
    expect(accountApi).toContain('name: input.name')
    expect(accountApi).toContain('name: patch.name ?? current.name')
    expect(accountApi).not.toMatch(/\[(?:input|patch)\.(?:givenName|middleName|familyName|namePrefix|nameSuffix)/)
    expect(accountApi).not.toContain(".filter(Boolean).join(' ')")
    expect(accountApi).not.toContain('.filter(Boolean).join(" ")')
  })

  it('lists accounts without per-user role or security requests', () => {
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const accountApi = api.slice(api.indexOf('export const identityAccountsApi'), api.indexOf('const MODULE_PERMISSION_KEYS'))
    expect(accountApi).toContain('return (await runtimeUsers()).map((user) => mapIdentityAccount(user))')
    expect(accountApi).not.toContain('userRoleAssignments')
    const listPage = readFileSync(new URL('./identity-accounts-page.tsx', import.meta.url), 'utf8')
    expect(listPage).not.toContain('useIdentityAccountSecurity')
    expect(accountApi).toContain('"/auth/reset-password"')
    expect(accountApi).toContain('"Idempotency-Key"')
    const detail = readFileSync(new URL('./identity-user-detail-page.tsx', import.meta.url), 'utf8')
    expect(detail).toContain("has('identity.security.write')")
  })

  it('renders only the safe account security projection', () => {
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const detail = readFileSync(new URL('./identity-user-detail-page.tsx', import.meta.url), 'utf8')
    expect(api).toContain('/security`')
    for (const field of ['mfa_enabled', 'locked', 'active_sessions', 'sessions', 'external_accounts', 'mfa_factors']) {
      expect(detail).toContain(field)
    }
    for (const secret of ['password_hash', 'token_hash', 'provider_subject', 'provider_ref']) {
      expect(api).not.toContain(secret)
      expect(detail).not.toContain(secret)
    }
  })

  it('renders every governed hard-delete blocker from the Runtime impact preview', () => {
    const page = readFileSync(new URL('./identity-accounts-page.tsx', import.meta.url), 'utf8')
    for (const field of [
      'business_profile_references',
      'owned_record_references',
      'pending_approval_task_ids',
      'retained_audit_event_ids',
      'active_legal_hold_ids',
      'impact.blockers',
    ]) {
      expect(page).toContain(field)
    }
  })

  it('requires a complete dual-identity impact preview before global disable', () => {
    const list = readFileSync(new URL('./identity-accounts-page.tsx', import.meta.url), 'utf8')
    const detail = readFileSync(new URL('./identity-user-detail-page.tsx', import.meta.url), 'utf8')
    const dialog = readFileSync(new URL('./account-disable-dialog.tsx', import.meta.url), 'utf8')
    expect(list).toContain('AccountDisableDialog')
    expect(detail).toContain('AccountDisableDialog')
    expect(dialog).toContain('identityAccountsApi.disableImpact')
    for (const field of ['workforce_profile_ids', 'profile_bindings', 'active_entitlement_role_ids', 'sessions_will_be_revoked', 'business_facts_preserved']) {
      expect(dialog).toContain(field)
    }
    expect(dialog.indexOf('identityAccountsApi.disableImpact')).toBeLessThan(dialog.indexOf("patch: { status: 'disabled' }"))
  })

  it('executes password reset, unlock, and force logout and renders their receipts', () => {
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const detail = readFileSync(new URL('./identity-user-detail-page.tsx', import.meta.url), 'utf8')
    for (const endpoint of ['/auth/reset-password', '/unlock`', '/force-logout`']) {
      expect(api).toContain(endpoint)
    }
    for (const call of ['identityAccountsApi.resetPassword', 'identityAccountsApi.unlock', 'identityAccountsApi.forceLogout']) {
      expect(detail).toContain(call)
    }
    expect(detail).toContain("role={mutationResult.error ? 'alert' : 'status'}")
    expect(detail).toContain('result.revoked_sessions')
    expect(detail).toContain('result.status')
    expect(detail).toContain('security.refetch()')
  })

  it('provisions and displays the fixed initial credential without caching it in the account list', () => {
    const api = readFileSync(new URL('../../data/api.ts', import.meta.url), 'utf8')
    const identityContract = readFileSync(new URL('../../../../packages/management-contract/src/index.ts', import.meta.url), 'utf8')
    const hooks = readFileSync(new URL('../../data/hooks.ts', import.meta.url), 'utf8')
    const page = readFileSync(new URL('./identity-accounts-page.tsx', import.meta.url), 'utf8')
    expect(identityContract).toContain('initial_password?: string')
    expect(api).toContain('identityAccountsApi')
    expect(api).toContain('provision(input:')
    expect(api).toContain('user.must_change_password !== false')
    expect(hooks).toContain('identityAccountsApi.provision(input)')
    expect(hooks).not.toContain('export const useCreateIdentityAccount = identityAccounts.useCreate')
    expect(page).toContain('provisioned.initialPassword')
    expect(page).toContain("t('accounts.defaultPassword')")
    expect(page).toContain('accounts.initialCredentialOneTimeWarning')
    expect(page).toContain('create.reset()')
  })
})
