import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const detail = readFileSync(new URL('./role-governance-detail.tsx', import.meta.url), 'utf8')
const roles = readFileSync(new URL('./roles.tsx', import.meta.url), 'utf8')
const api = readFileSync(new URL('../../data/governance-api.ts', import.meta.url), 'utf8')

describe('unified role governance detail', () => {
  it('renders every required governance dimension for the selected role', () => {
    for (const dimension of [
      'roles.detail.identity',
      'roles.detail.permissionSets',
      'roles.detail.businessActions',
      'roles.detail.objectCapabilities',
      'roles.detail.dataScopes',
      'roles.detail.fieldExport',
      'roles.detail.menuEntrypoints',
      'roles.detail.membersSources',
      'roles.detail.conflictsImpact',
      'roles.detail.versionsAudit',
    ]) {
      expect(detail).toContain(dimension)
    }
    expect(roles).toContain('<RoleGovernanceDetail roleID={selected.id} />')
    expect(roles).toContain("useState<'overview' | 'permissions' | 'menus'>('overview')")
  })

  it('uses the Runtime read projection, impact preview, and audit revision history', () => {
    expect(api).toContain('/governance-detail')
    expect(api).toContain('/impact-preview')
    expect(api).toContain('/versions')
    expect(detail).toContain('identityAccessApi.roleGovernanceDetail')
    expect(detail).toContain('identityAccessApi.roleImpact')
    expect(detail).toContain('identityAccessApi.roleVersions')
  })

  it('does not introduce a parallel role mutation model', () => {
    for (const mutation of ['runtimeRequest(', 'useMutation(', '.save(', '.publish(', 'PUT', 'PATCH', 'DELETE']) {
      expect(detail).not.toContain(mutation)
    }
    expect(api).toContain('{ method: "POST", body: { role } }')
  })

  it('renders menu entrypoints as a full-width responsive registry', () => {
    expect(detail).toContain("className='md:col-span-2'")
    expect(detail).toContain('roles.detail.menuName')
    expect(detail).toContain('roles.detail.menuKey')
    expect(detail).toContain('roles.detail.entrypoint')
    expect(detail).toContain('break-all')
    expect(detail).toContain("data-testid='role-menu-entrypoints'")
    expect(detail).not.toContain('menus.surface.')
  })
})
