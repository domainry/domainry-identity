import type { RuntimeDataScopePolicy, RuntimePermissionPoint } from '@/data/api'

const OBJECT_CRUD_ACTION_ORDER = 'create|read|update|delete'

export function objectCrudActions(
  objectKeys: string[],
  permissionCatalog: RuntimePermissionPoint[],
): string[] {
  const objects = new Set(objectKeys)
  const available = new Set(
    permissionCatalog
      .filter((permission) => objects.has(permission.resource))
      .map((permission) => permission.action),
  )
  return OBJECT_CRUD_ACTION_ORDER.split('|').filter((action) => available.has(action))
}

export function dataScopeValues(capabilityValues: string[], currentValues: string[]): string[] {
  return [...new Set([...capabilityValues, ...currentValues, 'none'])]
}

export function isDataScopeOptionDisabled(
  option: string,
  currentScope: string,
  policies: RuntimeDataScopePolicy[],
  resource: string,
): boolean {
  if (option === 'custom' && currentScope !== 'custom') return true
  if (option !== 'none') return false

  const explicitScopes = policies.filter((item) => item.scope !== 'none')
  return explicitScopes.length === 1 && explicitScopes[0]?.resource === resource
}

export function shouldHydrateRoleAuthorizationDraft(status: string | undefined): boolean {
  return Boolean(status && status !== 'published')
}

export function effectiveObjectScope(directScope: string): string {
	return directScope
}

export function effectiveObjectPermission(
	permissionKeys: string[],
	point: RuntimePermissionPoint | undefined,
): boolean {
	if (!point) return false
	return permissionKeys.includes(point.key)
}
