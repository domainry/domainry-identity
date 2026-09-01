import { describe, expect, it } from 'vitest'
import { buildPermissionCapabilityView } from './permission-capability-view'

describe('permission capability view', () => {
  it('groups live Action usages by capability and operation without using URLs as permission keys', () => {
    const view = buildPermissionCapabilityView([{
      key: 'identity.roles.read', label: 'Role read', system: 'identity', resource: 'roles', resource_label: 'Roles', action: 'read', category: 'Identity', description: '',
      definition_status: 'active', enabled: true,
      action_usages: [
        { action_key: 'identity.roles.list', action_label: 'List roles', capability_key: 'identity.role_management', capability_label: '角色管理', operation_key: 'read', operation_label: '查看', object_key: '', authorization_strategy: 'static_all', http_method: 'GET', route_template: '/identity/roles', page_route: '/admin/org/roles', risk_level: 'medium', approval_required: false, assurance_required: [], lifecycle_status: 'active' },
        { action_key: 'identity.roles.get', action_label: 'Get role', capability_key: 'identity.role_management', capability_label: '角色管理', operation_key: 'read', operation_label: '查看', object_key: '', authorization_strategy: 'static_all', http_method: 'GET', route_template: '/identity/roles/{roleID}', page_route: '/admin/org/roles', risk_level: 'medium', approval_required: false, assurance_required: [], lifecycle_status: 'active' },
      ],
    }])
    expect(view).toHaveLength(1)
    expect(view[0].operations[0]).toMatchObject({ permissionKeys: ['identity.roles.read'], active: true, enabled: true })
    expect(view[0].operations[0].bindings.map((binding) => `${binding.method} ${binding.route}`)).toEqual(['GET /identity/roles', 'GET /identity/roles/{roleID}'])
  })
})

