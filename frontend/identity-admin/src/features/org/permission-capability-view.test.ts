import { describe, expect, it } from 'vitest'
import { buildPermissionCapabilityView, buildPermissionCatalogView } from './permission-capability-view'

describe('permission capability view', () => {
  it('groups live Action usages by capability and operation without using URLs as permission keys', () => {
    const view = buildPermissionCapabilityView([{
	  key: 'identity.roles.list', label: 'Role list', system: 'identity', resource: 'identity.roles', resource_label: 'Roles', action: 'list', category: 'Identity', description: '',
	  definition_status: 'active', enabled: true,
	  action_usage_status: 'available',
      action_usages: [
        { action_key: 'identity.roles.list', action_label: 'List roles', capability_key: 'identity.role_management', capability_label: '角色管理', operation_key: 'read', operation_label: '查看', object_key: '', http_method: 'GET', route_template: '/identity/roles', page_route: '/admin/org/roles', risk_level: 'medium', approval_required: false, assurance_required: [], lifecycle_status: 'active' },
	  ],
	}])
	expect(view).toHaveLength(1)
	expect(view[0].operations[0]).toMatchObject({ permissionKeys: ['identity.roles.list'], active: true, enabled: true })
	expect(view[0].operations[0].bindings.map((binding) => `${binding.method} ${binding.route}`)).toEqual(['GET /identity/roles'])
  })

  it('groups database definitions by category, canonical owner, source, and resource', () => {
	const points = [{
	  key: 'identity.roles.list', label: 'Role list', system: 'identity', resource: 'identity.roles', resource_label: 'Roles', action: 'list', category: 'Identity', description: '',
	  definition_status: 'retired' as const, enabled: false, source_kind: 'builtin_surface', source_owner: 'identity:builtin',
	  action_usage_status: 'available' as const,
	}]
	const groups = buildPermissionCatalogView(points)
	expect(groups).toHaveLength(1)
		expect(groups[0]).toMatchObject({
		  category: 'Identity', sourceKind: 'builtin_surface', sourceOwner: 'identity:builtin', resourceKey: 'identity.roles', resourceLabel: 'Roles',
		})
		expect(groups[0].permissions).toEqual([{ key: 'identity.roles.list', label: 'Role list', active: false, enabled: false }])
		expect(groups[0].capabilities[0].operations[0]).toMatchObject({ active: false, enabled: false })
  })

  it('uses the current Runtime schema label for object resources', () => {
	const points = [{
	  key: 'customer.read', label: 'Read customer', system: 'runtime', resource: 'customer', resource_label: 'customer', action: 'read', category: 'object', description: '',
	  definition_status: 'active' as const, enabled: true, source_kind: 'object_default', source_owner: 'application:crm',
	  action_usage_status: 'unavailable' as const,
	}]
		const groups = buildPermissionCatalogView(points, new Map([['customer', '客户']]))
		expect(groups[0].resourceLabel).toBe('客户')
		expect(groups[0].permissions[0]).toMatchObject({ key: 'customer.read', label: 'Read customer' })
		expect(groups[0].capabilities[0].operations[0]).toMatchObject({ bindings: [], usageAvailable: false })
  })

  it('does not fabricate Action bindings when the owner registry is unavailable', () => {
	const view = buildPermissionCapabilityView([{
	  key: 'customer.read', label: 'Read customer', system: 'runtime', resource: 'customer', resource_label: 'Customer', action: 'read', category: 'object', description: '',
	  definition_status: 'active', enabled: true, source_kind: 'object_default', source_owner: 'application:crm', action_usage_status: 'unavailable',
	}])
	expect(view[0].operations[0]).toMatchObject({ permissionKeys: ['customer.read'], bindings: [], usageAvailable: false })
  })
})
