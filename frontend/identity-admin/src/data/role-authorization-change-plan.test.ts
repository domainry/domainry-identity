import { describe, expect, it } from 'vitest'
import {
  buildRoleAuthorizationBatchChangePlan,
  buildRoleAuthorizationChangePlan,
  roleAuthorizationPlanID,
  type RuntimeChangePlanDraft,
  type RuntimeReferenceGraph,
  type RuntimeSystemSnapshot,
} from './action-definition-api'

const snapshot: RuntimeSystemSnapshot = {
  snapshot_hash: 'abc/def:1234567890-extra',
  runtime_version: '1',
  authoring_contract_version: '1',
  authoring_contract_hash: 'contract',
  schema: {
    roles: [
      { key: 'sales', name: 'Sales', permissions: ['order.read'], record_scope: 'all_records', data_permissions: [{ object_key: 'order', scope: 'owned_records', read: true, write: true }] },
      { key: 'support', name: 'Support', permissions: ['ticket.read'], record_scope: 'all_records' },
    ],
  },
  resource_sources: [
    { resource_type: 'role', resource_key: 'sales', schema_hash: 'sales-hash' },
    { resource_type: 'role', resource_key: 'support', schema_hash: 'support-hash' },
  ],
}

const graph: RuntimeReferenceGraph = { version: '1', hash: 'graph', nodes: [], edges: [] }

function draftFor(plan: ReturnType<typeof buildRoleAuthorizationBatchChangePlan>): RuntimeChangePlanDraft {
  return {
    workspace_id: 'default', plan_id: plan.plan_id, revision: 2, status: 'draft', payload: plan,
    created_by: 'maker', updated_by: 'maker', created_at: 'now', updated_at: 'now',
  }
}

describe('unified role authorization Change Plan', () => {
  it('uses one deterministic draft id for every role authorization surface', () => {
    expect(roleAuthorizationPlanID(snapshot.snapshot_hash)).toBe('identity-role-authorization-abc-def-12345678')
    expect(roleAuthorizationPlanID('  ')).toBe('')
  })

  it('merges later dimensions into the existing role draft without overwriting other changes', () => {
    const permissionsPlan = buildRoleAuthorizationBatchChangePlan({
      snapshot,
      graph,
      reason: 'permission update',
      planID: roleAuthorizationPlanID(snapshot.snapshot_hash),
      changes: [
        { roleKey: 'sales', roleName: 'Sales', permissionKeys: ['order.read', 'order.approve'] },
        { roleKey: 'support', roleName: 'Support', permissionKeys: ['ticket.read', 'ticket.reply'] },
      ],
    })
    const merged = buildRoleAuthorizationChangePlan({
      snapshot,
      graph,
      reason: 'scope and field update',
      planID: permissionsPlan.plan_id,
      existingDraft: draftFor(permissionsPlan),
      roleKey: 'sales',
      roleName: 'Sales',
      dataScopes: [{ resource: 'order', scope: 'department', audit_denial: true, predicate: { operator: 'eq' } }],
      fieldPermissions: [{ resource: 'order', field: 'amount', visible: true, editable: false, masked: true, policies: [{ effect: 'mask' }] }],
    })

    expect(merged.items.map((item) => item.resource_key)).toEqual(['sales', 'support'])
    expect(merged.items[0].after).toMatchObject({
      permissions: ['order.approve', 'order.read'],
      data_permissions: [{ object_key: 'order', scope: 'department', read: true, write: true, audit_denial: true, predicate: { operator: 'eq' } }],
      field_permissions: [{ object_key: 'order', field_key: 'amount', read: true, write: false, export: true, masked: true, policies: [{ effect: 'mask' }] }],
    })
    expect(merged.items[1].after).toMatchObject({ permissions: ['ticket.read', 'ticket.reply'] })
    expect(merged.items[0].before).toEqual(snapshot.schema.roles?.[0])
    expect(merged.release_order).toEqual(['role:sales', 'role:support'])
    expect(merged.rollback_order).toEqual(['role:support', 'role:sales'])
  })

  it('creates a complete new role while preserving empty optional policies', () => {
    const plan = buildRoleAuthorizationChangePlan({
      snapshot,
      graph,
      reason: 'new role',
      planID: 'new-role',
      roleKey: 'new-role',
      roleName: 'New role',
      permissionKeys: [],
      dataScopes: [],
      fieldPermissions: [],
    })
    expect(plan.items[0]).toMatchObject({
      operation: 'create',
      change_kind: 'additive',
      before: undefined,
      after: { key: 'new-role', name: 'New role', permissions: [], data_permissions: [], field_permissions: [] },
    })
  })
})
