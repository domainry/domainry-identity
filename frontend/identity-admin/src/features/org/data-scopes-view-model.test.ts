import { describe, expect, it } from 'vitest'
import type { RuntimePermissionPoint } from '@/data/api'
import type { Role } from '@/data/types'
import {
  dataScopeValues,
  effectiveObjectPermission,
  effectiveObjectScope,
  isDataScopeOptionDisabled,
  objectCrudActions,
  roleHasImplicitObjectAccess,
  shouldHydrateRoleAuthorizationDraft,
} from './data-scopes-view-model'

const role = (overrides: Partial<Role> = {}): Role => ({
  id: 'manager',
  name: 'Manager',
  code: 'manager',
  description: '',
  members: 1,
  builtIn: false,
  status: 'active',
  ...overrides,
})

const point = (resource: string, action: string): RuntimePermissionPoint => ({
  key: `${resource}.${action}`,
  label: action,
  system: 'business',
  resource,
  resource_label: resource,
  action,
  category: 'object',
  description: '',
  action_usage_status: 'unavailable',
})

describe('data scope permission matrix', () => {
  it('keeps only ordered CRUD actions belonging to visible domain objects', () => {
    const catalog = [
      point('employee_profile', 'update'),
      point('workspace', 'approve'),
      point('employee_profile', 'read'),
      point('employee_profile', 'archive'),
      point('employee_profile', 'create'),
      point('employee_profile', 'delete'),
    ]

    expect(objectCrudActions(['employee_profile'], catalog)).toEqual(['create', 'read', 'update', 'delete'])
  })

  it('renders workspace administrators as inherited full access', () => {
    const admin = role({ id: 'admin', builtIn: true })
    const read = point('employee_profile', 'read')

    expect(roleHasImplicitObjectAccess(admin, [])).toBe(true)
    expect(effectiveObjectPermission(admin, [], read)).toBe(true)
    expect(effectiveObjectScope(admin, [], 'none')).toBe('all_records')
  })

  it('uses direct grants and scopes for ordinary roles', () => {
    const manager = role()
    const read = point('employee_profile', 'read')

    expect(effectiveObjectPermission(manager, ['employee_profile.read'], read)).toBe(true)
    expect(effectiveObjectPermission(manager, [], read)).toBe(false)
    expect(effectiveObjectScope(manager, [], 'department')).toBe('department')
  })

  it('keeps backend scopes already in use even when capability discovery omits them', () => {
    expect(dataScopeValues(
      ['department', 'owned_records'],
      ['all_records', 'department'],
    )).toEqual(['department', 'owned_records', 'all_records', 'none'])
  })

  it('prevents authoring data-scope payloads that the backend cannot publish', () => {
    const onlyPolicy = [{ resource: 'employee_profile', scope: 'department' }]
    const twoPolicies = [
      ...onlyPolicy,
      { resource: 'leave_request', scope: 'owned_records' },
    ]

    expect(isDataScopeOptionDisabled('none', 'department', onlyPolicy, 'employee_profile')).toBe(true)
    expect(isDataScopeOptionDisabled('none', 'department', twoPolicies, 'employee_profile')).toBe(false)
    expect(isDataScopeOptionDisabled('custom', 'department', onlyPolicy, 'employee_profile')).toBe(true)
    expect(isDataScopeOptionDisabled('custom', 'custom', [{ resource: 'employee_profile', scope: 'custom' }], 'employee_profile')).toBe(false)
    expect(isDataScopeOptionDisabled('all_records', 'department', onlyPolicy, 'employee_profile')).toBe(false)
  })

  it('never rehydrates editable state from a published authorization plan', () => {
    expect(shouldHydrateRoleAuthorizationDraft('draft')).toBe(true)
    expect(shouldHydrateRoleAuthorizationDraft('in_review')).toBe(true)
    expect(shouldHydrateRoleAuthorizationDraft('published')).toBe(false)
    expect(shouldHydrateRoleAuthorizationDraft(undefined)).toBe(false)
  })
})
