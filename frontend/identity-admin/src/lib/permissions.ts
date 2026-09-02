import { useCallback, useMemo } from 'react'
import { useEffectiveMenus, useEffectivePermissions } from '@/data/hooks'
import type { NavKey } from '@/features/shell/admin-shell'

const ROUTE_TO_NAV: Record<string, NavKey> = {
  '/admin/security/accounts': 'users',
  '/admin/org/organization-units': 'organizationUnits',
  '/admin/org/roles': 'roles',
  '/admin/org/menus': 'menus',
  '/admin/org/data-scopes': 'dataScopes',
  '/admin/org/field-permissions': 'fieldPerms',
  '/admin/system/metadata': 'metadata',
}

const ALL_NAV_KEYS: NavKey[] = [
  'users',
  'organizationUnits',
  'roles',
  'menus',
  'dataScopes',
  'fieldPerms',
  'metadata',
]

export interface Permissions {
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
    (permission: string) => permissionSet.has(permission),
    [permissionSet]
  )

  const hiddenNavKeys = useMemo(() => {
    const allowed = new Set(
      effectiveMenus
        .map((menu) => ROUTE_TO_NAV[menu.route ?? ''])
        .filter((key): key is NavKey => Boolean(key))
    )
    return new Set(ALL_NAV_KEYS.filter((key) => !allowed.has(key)))
  }, [effectiveMenus])

  return { has, hiddenNavKeys, ready: permissionsReady && menusReady }
}
