import type { RuntimeApiError } from '@/lib/runtime-api'
import type { RuntimeFieldPermission, RuntimePermissionPoint } from '@/data/api'
import type { IdentityRolePermissionGrant } from '@/data/governance-api'

export type RolePolicySubmission = { roleID: string; permissions: IdentityRolePermissionGrant[] }

export class RolePolicySaveError extends Error {
  constructor(readonly submission: RolePolicySubmission, readonly runtime: RuntimeApiError | undefined, cause: unknown) {
    super(cause instanceof Error ? cause.message : 'Role policy save failed')
    this.name = 'RolePolicySaveError'
  }
}

function indexedPath(fieldPath: string, collection: string) {
  const match = fieldPath.match(new RegExp(`^${collection}\\[(\\d+)\\]\\.([a-z_]+)$`))
  return match ? { index: Number(match[1]), field: match[2] } : undefined
}

export function rolePolicyControl(error: RolePolicySaveError, catalog: RuntimePermissionPoint[]) {
  const path = error.runtime?.fieldPath ?? ''
  const permissionGrant = indexedPath(path, 'permissions')
  if (permissionGrant) {
    const permission = error.submission.permissions[permissionGrant.index]
    return permission ? `${error.submission.roleID}:${permission.permission_key}:${permissionGrant.field}` : undefined
  }
  const permission = path.match(/^permissions\[(\d+)\]\.permission_key$/)
  if (permission) {
    const key = error.submission.permissions[Number(permission[1])]?.permission_key
    const point = catalog.find((item) => item.key === key)
    return point ? `${error.submission.roleID}:${point.resource}:${point.action}` : undefined
  }
  return undefined
}

export function fieldPermissionControl(error: RuntimeApiError | undefined, submitted: RuntimeFieldPermission[]) {
  const path = indexedPath(error?.fieldPath ?? '', 'field_permissions')
  if (!path) return undefined
  const permission = submitted[path.index]
  return permission ? `${permission.resource}:${permission.field}:${path.field}` : undefined
}
