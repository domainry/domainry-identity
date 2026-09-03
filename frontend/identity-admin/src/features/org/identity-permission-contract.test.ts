import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { menuFieldControl } from './menu-field-error'
import { organizationUnitFormControl, roleFormControl, userFormControl } from './identity-form-error'
import { RuntimeApiError } from '@/lib/runtime-api'
import { fieldPermissionControl, RolePolicySaveError, rolePolicyControl } from './identity-policy-field-error'

function source(name: string) {
  return readFileSync(new URL(`./${name}`, import.meta.url), 'utf8')
}

describe('identity permission authoring surfaces', () => {
  it('builds the role permission view from DB-backed definitions and publishes a normal RoleSchema version', () => {
    const roles = source('roles.tsx')
    expect(roles).toContain('permissionsApi.catalog')
    expect(roles).toContain('identityPoliciesApi.saveRolePermissions')
    expect(roles).toContain('rolePermissionsQuery.data.schemaHash')
    expect(roles).not.toContain('buildRoleAuthorizationChangePlan')
    expect(roles).not.toContain('systemChangePlansApi')
    expect(roles).toContain('permissionCatalogQuery.data')
    expect(roles).toContain('buildPermissionCatalogView')
    expect(roles).toContain('group.sourceOwner')
    expect(roles).toContain('group.sourceKind')
    expect(roles).toContain('group.category')
    expect(roles).toContain('schemaQuery.data?.objects')
    expect(roles).toContain('runtimeResourceLabels')
    expect(roles).toContain('binding.method')
    expect(roles).toContain('binding.route')
    expect(roles).toContain('operation.permissionKeys')
    expect(roles).not.toContain('PERM_MODULES')
    expect(roles).not.toContain('PERM_ACTIONS')
    expect(roles).not.toContain('businessActionPermissionRows')
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

  it('publishes each permission with its own data scope and keeps field policy versioning', () => {
    const roles = source('roles.tsx')
    const fields = source('field-permissions.tsx')
    expect(roles).toContain("['all', 'owner', 'org', 'org_child', 'target_org']")
    expect(roles).toContain('permission.permission_key === key')
    expect(roles).toContain('data_scope: scope as RuntimeDataScope')
    expect(roles).not.toContain('saveDataScopes')
    expect(fields).toContain('objectsApi.schemaSnapshot')
    expect(fields).toContain('identityPoliciesApi.fieldPermissionConfiguration')
    expect(fields).toContain('identityPoliciesApi.saveFieldPermissions')
    expect(fields).not.toContain('selectedRole?.builtIn')
    expect(fields).not.toContain('systemChangePlansApi')
    expect(fields).toContain('disabled={dirty || publish.isPending}')
    expect(fields).toContain('aria-label={`${field.label || field.name || field.key}')
  })

  it('keeps functional-permission publication on the direct RoleSchema path', () => {
    const rolePolicy = source('roles.tsx')
    const fields = source('field-permissions.tsx')
    expect(rolePolicy).toContain('identityPoliciesApi.saveRolePermissions')
    for (const surface of [rolePolicy, fields]) {
      expect(surface).not.toContain('roleAuthorizationPlanID')
      expect(surface).not.toContain('existingDraft:')
      expect(surface).not.toContain('systemChangePlansApi')
    }
  })

  it('maps menu authoring errors to the dedicated form fields', () => {
    expect(menuFieldControl('menu.key', 'backend.identity.menu_key_exists')).toBe('code')
    expect(menuFieldControl('menu.parent_id', 'backend.identity.menu_parent_cycle')).toBe('parentId')
    expect(menuFieldControl('route')).toBe('path')
  })

  it('maps user and role authoring errors to dedicated controls', () => {
    expect(userFormControl(new RuntimeApiError(400, { field_path: 'user.email' }, 'invalid'))).toBe('email')
    expect(userFormControl(new RuntimeApiError(400, { field_path: 'user.org_id' }, 'invalid'))).toBe('organizationUnitId')
    expect(userFormControl(new RuntimeApiError(400, { field_path: 'user.support_org_id' }, 'invalid'))).toBe('supportOrganizationUnitId')
    expect(roleFormControl(new RuntimeApiError(400, { field_path: 'role.key', code: 'backend.identity.role_key_exists' }, 'exists'))).toBe('code')
    expect(organizationUnitFormControl(new RuntimeApiError(400, { field_path: 'organization_unit.parent_id' }, 'invalid'))).toBe('parentId')
    expect(organizationUnitFormControl(new RuntimeApiError(400, { field_path: 'organization_unit.status' }, 'invalid'))).toBe('enabled')
  })

  it('maps indexed policy errors back to matrix cells using the submitted snapshot', () => {
    const runtime = new RuntimeApiError(400, { field_path: 'permissions[0].data_scope' }, 'invalid scope')
		const error = new RolePolicySaveError({ roleID: 'sales', permissions: [{ permission_key: 'customer.read', data_scope: 'target_org' }] }, runtime, runtime)
		expect(rolePolicyControl(error, [])).toBe('sales:customer.read:data_scope')
    expect(fieldPermissionControl(new RuntimeApiError(400, { field_path: 'field_permissions[0].editable' }, 'invalid'), [{ resource: 'customer', field: 'email', visible: false, editable: true }])).toBe('customer:email:editable')
  })
})
