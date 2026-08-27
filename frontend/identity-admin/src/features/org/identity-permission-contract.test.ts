import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { menuFieldControl } from './menu-field-error'
import { departmentFormControl, roleFormControl, userFormControl } from './identity-form-error'
import { RuntimeApiError } from '@/lib/runtime-api'
import { fieldPermissionControl, RolePolicySaveError, rolePolicyControl } from './identity-policy-field-error'

function source(name: string) {
  return readFileSync(new URL(`./${name}`, import.meta.url), 'utf8')
}

describe('identity permission authoring surfaces', () => {
  it('builds the role permission matrix from the Runtime catalog and publishes through a reviewed system draft', () => {
    const roles = source('roles.tsx')
    expect(roles).toContain('permissionsApi.catalog')
    expect(roles).toContain('buildRoleAuthorizationChangePlan')
    expect(roles).toContain('systemChangePlansApi.save')
    expect(roles).toContain('systemChangePlansApi.review')
    expect(roles).toContain('systemChangePlansApi.approve')
    expect(roles).toContain('systemChangePlansApi.publish')
    expect(roles).not.toContain('identityPoliciesApi.saveRolePermissions')
    expect(roles).toContain('permissionCatalogQuery.data')
    expect(roles).not.toContain('PERM_MODULES')
    expect(roles).not.toContain('PERM_ACTIONS')
  })

  it('loads and saves explicit role-menu assignments through Runtime', () => {
    const roles = source('roles.tsx')
    const governance = readFileSync(new URL('../../data/governance-api.ts', import.meta.url), 'utf8')
    expect(roles).toContain("value='menus'")
    expect(roles).toContain('identityPoliciesApi.roleMenus')
    expect(roles).toContain('identityPoliciesApi.saveRoleMenus')
    expect(governance).toContain('/menus`')
    expect(governance).toContain('menu_ids: menuIDs')
  })

  it('uses contract data for scopes and schema data for fields', () => {
    const scopes = source('data-scopes.tsx')
    const fields = source('field-permissions.tsx')
    expect(scopes).toContain("authoringParameter(capabilities, 'identity.role_data_scope', 'data_scope')")
    expect(scopes).toContain('data.actions.map')
    expect(scopes).toContain('buildRoleAuthorizationBatchChangePlan')
    expect(scopes).not.toContain('identityPoliciesApi.saveDataScopes')
    expect(scopes).not.toContain('identityPoliciesApi.saveRolePermissions')
    expect(fields).toContain('objectsApi.schemaSnapshot')
    expect(fields).toContain('buildRoleAuthorizationChangePlan')
    expect(fields).toContain('const roleLocked = Boolean(selectedRole?.builtIn)')
    expect(fields).toContain('shouldHydrateRoleAuthorizationDraft')
    expect(fields).toContain('aria-label={`${field.label || field.name || field.key}')
    expect(fields).not.toContain('identityPoliciesApi.saveFieldPermissions')
  })

  it('shares one revision-checked role Change Plan across permission, scope, and field pages', () => {
    const rolePolicy = source('roles.tsx')
    const scopes = source('data-scopes.tsx')
    const fields = source('field-permissions.tsx')
    for (const surface of [rolePolicy, scopes, fields]) {
      expect(surface).toContain('roleAuthorizationPlanID')
      expect(surface).toContain('existingDraft:')
      expect(surface).toContain('systemChangePlansApi.review')
      expect(surface).toContain('systemChangePlansApi.approve')
      expect(surface).toContain('systemChangePlansApi.publish')
    }
    expect(rolePolicy).not.toContain('-permissions-${revision}')
    expect(scopes).not.toContain('role-data-scopes-')
    expect(fields).not.toContain('-fields-${')
  })

  it('maps menu authoring errors to the dedicated form fields', () => {
    expect(menuFieldControl('menu.key', 'backend.identity.menu_key_exists')).toBe('code')
    expect(menuFieldControl('menu.parent_id', 'backend.identity.menu_parent_cycle')).toBe('parentId')
    expect(menuFieldControl('route')).toBe('path')
  })

  it('maps user and role authoring errors to dedicated controls', () => {
    expect(userFormControl(new RuntimeApiError(400, { field_path: 'user.email' }, 'invalid'))).toBe('email')
    expect(userFormControl(new RuntimeApiError(400, { field_path: 'user.manager_id' }, 'invalid'))).toBe('managerId')
    expect(roleFormControl(new RuntimeApiError(400, { field_path: 'role.key', code: 'backend.identity.role_key_exists' }, 'exists'))).toBe('code')
    expect(departmentFormControl(new RuntimeApiError(400, { field_path: 'department.parent_id' }, 'invalid'))).toBe('parentId')
    expect(departmentFormControl(new RuntimeApiError(400, { field_path: 'department.status' }, 'invalid'))).toBe('enabled')
  })

  it('maps indexed policy errors back to matrix cells using the submitted snapshot', () => {
    const runtime = new RuntimeApiError(400, { field_path: 'data_scopes[0].scope' }, 'invalid scope')
    const error = new RolePolicySaveError({ roleID: 'sales', permissionKeys: [], dataScopes: [{ resource: 'customer', scope: 'custom' }] }, runtime, runtime)
    expect(rolePolicyControl(error, [])).toBe('sales:customer:scope')
    expect(fieldPermissionControl(new RuntimeApiError(400, { field_path: 'field_permissions[0].editable' }, 'invalid'), [{ resource: 'customer', field: 'email', visible: false, editable: true }])).toBe('customer:email:editable')
  })
})
