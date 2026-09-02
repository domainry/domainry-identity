import type { RuntimeApiError } from '@/lib/runtime-api'

export type UserFormControl = 'name' | 'email' | 'workerNo' | 'workStatus' | 'organizationUnitId' | 'supportOrganizationUnitId' | 'managerUserId' | 'enabled'
export type RoleFormControl = 'name' | 'code' | 'description'
export type OrganizationUnitFormControl = 'code' | 'name' | 'nodeType' | 'parentId' | 'enabled'

function identityPath(fieldPath: string) {
  return fieldPath.replace(/^(user|role|organization_unit)\./, '')
}

export function userFormControl(error: RuntimeApiError | undefined): UserFormControl | undefined {
  if (!error) return undefined
  const path = identityPath(error.fieldPath)
  if (path === 'name') return 'name'
  if (path === 'email') return 'email'
  if (path === 'worker_no') return 'workerNo'
  if (path === 'org_id') return 'organizationUnitId'
  if (path === 'support_org_id') return 'supportOrganizationUnitId'
  if (path === 'manager_user_id') return 'managerUserId'
  if (path === 'work_status') return 'workStatus'
  if (path === 'status') return 'enabled'
  return undefined
}

export function roleFormControl(error: RuntimeApiError | undefined): RoleFormControl | undefined {
  if (!error) return undefined
  const path = identityPath(error.fieldPath)
  if (path === 'key' || error.code === 'backend.identity.role_key_exists' || error.code === 'backend.identity.role_id_key_required') return 'code'
  if (path === 'label') return 'name'
  if (path === 'description') return 'description'
  return undefined
}

export function organizationUnitFormControl(error: RuntimeApiError | undefined): OrganizationUnitFormControl | undefined {
  if (!error) return undefined
  const path = identityPath(error.fieldPath)
  if (path === 'code') return 'code'
  if (path === 'name') return 'name'
  if (path === 'node_type') return 'nodeType'
  if (path === 'parent_id' || error.code === 'backend.identity.organization_unit_parent_self' || error.code === 'backend.identity.organization_unit_cycle') return 'parentId'
  if (path === 'status') return 'enabled'
  return undefined
}
