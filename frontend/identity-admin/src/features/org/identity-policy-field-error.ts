import type { RuntimeApiError } from '@/lib/runtime-api'
import type { RuntimeDataScopePolicy, RuntimeFieldPermission, RuntimePermissionPoint } from '@/data/api'

export type RolePolicySubmission = { roleID: string; permissionKeys: string[]; dataScopes: RuntimeDataScopePolicy[] }

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
  const scope = indexedPath(path, 'data_scopes')
  if (scope) {
    const policy = error.submission.dataScopes[scope.index]
    return policy ? `${error.submission.roleID}:${policy.resource}:scope` : undefined
  }
  const permission = path.match(/^permission_keys\[(\d+)\]$/)
  if (permission) {
    const key = error.submission.permissionKeys[Number(permission[1])]
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
