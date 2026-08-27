import { useCallback, useMemo } from 'react'
import { useEffectiveMenus, useEffectivePermissions } from '@/data/hooks'
import type { PermAction } from '@/data/types'
import type { NavKey } from '@/features/shell/admin-shell'

const ROUTE_TO_NAV: Record<string, NavKey> = {
  '/admin/security/accounts': 'users',
  '/admin/org/workforce': 'workforce',
  '/admin/org/departments': 'departments',
  '/admin/org/roles': 'roles',
  '/admin/org/menus': 'menus',
  '/admin/org/data-scopes': 'dataScopes',
  '/admin/org/field-permissions': 'fieldPerms',
  '/admin/system/metadata': 'metadata',
}

const ALL_NAV_KEYS: NavKey[] = [
  'users',
  'workforce',
  'departments',
  'roles',
  'menus',
  'dataScopes',
  'fieldPerms',
  'metadata',
]

const MODULE_PERMISSION: Record<string, { read: string; write?: string; delete?: boolean }> = {
  users: { read: 'identity.users.read', write: 'identity.users.write' },
  workforce: { read: 'identity.workforce.read', write: 'identity.workforce.write' },
  departments: { read: 'identity.departments.read', write: 'identity.departments.write', delete: false },
  roles: { read: 'identity.roles.read', write: 'identity.roles.write' },
  menus: { read: 'identity.menus.read', write: 'identity.menus.write' },
  dataScopes: { read: 'identity.data_scopes.read', write: 'identity.data_scopes.write' },
  fieldPerms: { read: 'identity.field_permissions.read', write: 'identity.field_permissions.write' },
  metadata: { read: 'metadata.read', write: 'metadata.write' },
}

export interface Permissions {
  can: (module: string, action: PermAction) => boolean
  has: (permission: string) => boolean
  hiddenNavKeys: Set<NavKey>
  ready: boolean
}

export function usePermissions(): Permissions {
  const { data: snapshot, isSuccess: permissionsReady } = useEffectivePermissions()
  const { data: effectiveMenus = [], isSuccess: menusReady } = useEffectiveMenus()

  const permissionSet = useMemo(() => {
    const permissions = new Set<string>()
    for (const item of snapshot?.function_permissions ?? []) {
      if (item.decision.allowed) permissions.add(item.key)
    }
    return permissions
  }, [snapshot])

  const has = useCallback(
    (permission: string) => {
      if (permissionSet.has('*') || permissionSet.has(permission)) return true
      const namespace = permission.split('.').slice(0, -1).join('.')
      return Boolean(namespace && permissionSet.has(`${namespace}.*`))
    },
    [permissionSet]
  )

  const can = useCallback(
    (module: string, action: PermAction) => {
      const permission = MODULE_PERMISSION[module]
      if (permission) {
        if (action === 'view' || action === 'export') return has(permission.read)
        if (action === 'delete' && permission.delete === false) return false
        return Boolean(permission.write && has(permission.write))
      }
      const object = snapshot?.objects?.find((item) => item.object_key === module)
      const runtimeAction = action === 'view' ? 'read' : action === 'edit' ? 'update' : action
      return Boolean(object?.actions.find((item) => item.action === runtimeAction)?.allowed)
    },
    [has, snapshot]
  )

  const hiddenNavKeys = useMemo(() => {
    const allowed = new Set(
      effectiveMenus
        .map((menu) => ROUTE_TO_NAV[menu.route ?? ''])
        .filter((key): key is NavKey => Boolean(key))
    )
    return new Set(ALL_NAV_KEYS.filter((key) => !allowed.has(key)))
  }, [effectiveMenus])

  return { can, has, hiddenNavKeys, ready: permissionsReady && menusReady }
}
