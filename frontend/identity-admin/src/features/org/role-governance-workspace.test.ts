import { describe, expect, it } from 'vitest'
import rolesSource from './roles.tsx?raw'
import adminShellSource from '../shell/admin-shell.tsx?raw'

describe('role governance workspace boundary', () => {
  it('integrates every role policy dimension into the role page', () => {
    expect(rolesSource).toContain("value='role-policy'")
    expect(rolesSource).toContain("value='field-permissions'")
    expect(rolesSource).toContain('<FieldPermissionsPage />')
    expect(rolesSource).toContain('<EffectiveAccessWorkspace />')
    expect(rolesSource).toContain("value='permissions'")
    expect(rolesSource).toContain("value='menus'")
    expect(rolesSource).toContain('grant.data_scope')
    expect(rolesSource).not.toContain("value='data-scopes'")
    expect(rolesSource).not.toContain('<DataScopesPage />')
  })

  it('does not expose data and field policy as separate primary navigation entries', () => {
    const navGroups = adminShellSource.slice(
      adminShellSource.indexOf('const NAV_GROUPS'),
      adminShellSource.indexOf('export const DEV_NAV_KEYS'),
    )
    expect(navGroups).not.toContain('{ key: "dataScopes"')
    expect(navGroups).not.toContain('{ key: "fieldPerms"')
  })

  it('offers user, role, and object/action effective-access directions backed by runtime projections', async () => {
    const workspaceSource = await import('./effective-access-workspace.tsx?raw').then((module) => module.default)
    const apiSource = await import('../../data/governance-api.ts?raw').then((module) => module.default)
    expect(workspaceSource).toContain("value='user'")
    expect(workspaceSource).toContain("value='role'")
    expect(workspaceSource).toContain("value='object-action'")
    expect(workspaceSource).toContain('permission.sources')
    expect(apiSource).toContain('/effective-access')
    expect(apiSource).toContain('/identity/access/reverse-index')
  })
})
