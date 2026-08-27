export const RUNTIME_PRODUCT_SURFACES = [
  'business_workspace',
  'admin_console',
  'consumer_portal',
] as const

export const RUNTIME_SURFACE_CONTRACT_VERSION =
  'runtime-surface-contract-v2' as const

export type RuntimeProductSurface = (typeof RUNTIME_PRODUCT_SURFACES)[number]
export type FrontendSurface = RuntimeProductSurface | 'development'

export const RUNTIME_SHELLS = [
  'business_workspace',
  'admin_console',
  'consumer_portal',
] as const

export type RuntimeShell = (typeof RUNTIME_SHELLS)[number]
export type FrontendShell = RuntimeShell | 'development'

export const SURFACE_SHELL = {
  business_workspace: 'business_workspace',
  admin_console: 'admin_console',
  consumer_portal: 'consumer_portal',
} as const satisfies Record<RuntimeProductSurface, RuntimeShell>

export const SURFACE_SHELL_OWNERSHIP = {
  business_workspace: 'source_owned',
  admin_console: 'platform_admin',
  consumer_portal: 'source_owned',
} as const satisfies Record<
  RuntimeProductSurface,
  'source_owned' | 'platform_admin'
>

/**
 * Shell keys classify route/artifact boundaries. They do not identify a
 * reusable visual Shell component. Business and Portal layouts are owned by
 * each generated source project; the platform owns one Admin shell.
 */
export function shellOwnershipForSurface(
  surface: RuntimeProductSurface,
): 'source_owned' | 'platform_admin' {
  return SURFACE_SHELL_OWNERSHIP[surface]
}

export const SURFACE_LOGIN_PATH = {
  business_workspace: '/business/login',
  admin_console: '/admin/login',
  consumer_portal: '/portal/login',
} as const satisfies Record<RuntimeProductSurface, string>

export const SURFACE_DEVELOPMENT_ROUTE_ROOT = {
  business_workspace: '/business',
  admin_console: '/admin',
  consumer_portal: '/portal',
} as const satisfies Record<RuntimeProductSurface, string>

export function shellForSurface(surface: RuntimeProductSurface): RuntimeShell {
  return SURFACE_SHELL[surface]
}

export function loginPathForSurface(surface: RuntimeProductSurface): string {
  return SURFACE_LOGIN_PATH[surface]
}

export function developmentRouteRootForSurface(
  surface: RuntimeProductSurface,
): string {
  return SURFACE_DEVELOPMENT_ROUTE_ROOT[surface]
}

export function isAdminShellSurface(surface: RuntimeProductSurface): boolean {
  return shellForSurface(surface) === 'admin_console'
}

export type SurfaceAudience =
  | 'business_actor'
  | 'consumer_profile'
  | 'platform_admin'
  | 'local_developer'

export type SurfaceExposureClass = 'public' | 'platform_admin'
export type SurfaceEndpointEffect = 'read' | 'write'
export type HighRiskActionPolicy =
  | 'none'
  | 'reason_required'
  | 'confirmation_required'
  | 'break_glass_required'

export const SURFACE_EXPOSURE_CLASS = {
  business_workspace: 'public',
  admin_console: 'platform_admin',
  consumer_portal: 'public',
} as const satisfies Record<RuntimeProductSurface, SurfaceExposureClass>

export const SURFACE_REQUIRED_AUDIENCE = {
  business_workspace: 'business_actor',
  admin_console: 'platform_admin',
  consumer_portal: 'consumer_profile',
} as const satisfies Record<RuntimeProductSurface, SurfaceAudience>

export type SurfaceRouteContract = {
  contractVersion: typeof RUNTIME_SURFACE_CONTRACT_VERSION
  routeKey: string
  path: string
  surface: FrontendSurface
  shell: FrontendShell
  actorAudiences: readonly SurfaceAudience[]
  routePurpose: string
  requiredPermissions: readonly string[]
  exposureClass: SurfaceExposureClass
  highRiskActionPolicy: HighRiskActionPolicy
}

export type SurfaceEndpointContract = {
  contractVersion: typeof RUNTIME_SURFACE_CONTRACT_VERSION
  endpointIdentity: string
  surface: RuntimeProductSurface
  actorAudiences: readonly SurfaceAudience[]
  requiredPermissions: readonly string[]
  exposureClass: SurfaceExposureClass
  effectClass: SurfaceEndpointEffect
  highRiskActionPolicy: HighRiskActionPolicy
}

export function assertSurfaceRouteContract(
  contract: SurfaceRouteContract,
): void {
  if (contract.contractVersion !== RUNTIME_SURFACE_CONTRACT_VERSION) {
    throw new Error(`surface route ${contract.routeKey} has an unsupported contract version`)
  }
  if (!contract.routeKey.trim()) throw new Error('surface route_key is required')
  if (!contract.path.startsWith('/')) throw new Error(`surface route ${contract.routeKey} must use an absolute path`)
  if (!contract.routePurpose.trim()) throw new Error(`surface route ${contract.routeKey} requires routePurpose`)
  if (contract.actorAudiences.length === 0) throw new Error(`surface route ${contract.routeKey} requires actorAudiences`)
  if (contract.surface === 'development') {
    if (contract.shell !== 'development') throw new Error(`development route ${contract.routeKey} must use the development shell`)
    return
  }
  if (contract.shell !== shellForSurface(contract.surface)) {
    throw new Error(
      `surface route ${contract.routeKey} must use ${shellForSurface(contract.surface)} instead of ${contract.shell}`,
    )
  }
  if (!contract.actorAudiences.includes(SURFACE_REQUIRED_AUDIENCE[contract.surface])) {
    throw new Error(`surface route ${contract.routeKey} requires audience ${SURFACE_REQUIRED_AUDIENCE[contract.surface]}`)
  }
  if (contract.exposureClass !== SURFACE_EXPOSURE_CLASS[contract.surface]) {
    throw new Error(`surface route ${contract.routeKey} must use exposure ${SURFACE_EXPOSURE_CLASS[contract.surface]}`)
  }
}

export function assertSurfaceEndpointContract(
  contract: SurfaceEndpointContract,
): void {
  if (contract.contractVersion !== RUNTIME_SURFACE_CONTRACT_VERSION) {
    throw new Error(`surface endpoint ${contract.endpointIdentity} has an unsupported contract version`)
  }
  if (!contract.endpointIdentity.trim()) throw new Error('surface endpoint identity is required')
  if (!contract.actorAudiences.includes(SURFACE_REQUIRED_AUDIENCE[contract.surface])) {
    throw new Error(`surface endpoint ${contract.endpointIdentity} requires audience ${SURFACE_REQUIRED_AUDIENCE[contract.surface]}`)
  }
  if (contract.exposureClass !== SURFACE_EXPOSURE_CLASS[contract.surface]) {
    throw new Error(`surface endpoint ${contract.endpointIdentity} must use exposure ${SURFACE_EXPOSURE_CLASS[contract.surface]}`)
  }
  if (contract.effectClass === 'write' && contract.requiredPermissions.length === 0) {
    throw new Error(`write endpoint ${contract.endpointIdentity} requires an operation permission`)
  }
}

export type DomainryExtensionValue =
  | null
  | boolean
  | number
  | string
  | readonly DomainryExtensionValue[]
  | { readonly [key: string]: DomainryExtensionValue }

const forbiddenExtensionKeys = new Set(['__proto__', 'constructor', 'prototype'])

function isExtensionObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function isCompatibleExtensionValue(base: unknown, value: unknown): boolean {
  if (Array.isArray(base)) return Array.isArray(value)
  if (isExtensionObject(base)) return isExtensionObject(value)
  if (base === null) return value === null
  return typeof base === typeof value
}

/**
 * Merge a project-owned extension over system defaults without mutating either
 * input. Unknown keys are ignored so an extension cannot invent an unsupported
 * platform option. Objects merge recursively; arrays and scalars replace.
 */
export function mergeDomainryExtension<T extends Record<string, unknown>>(
  defaults: T,
  extension: Record<string, unknown> | undefined,
): T {
  const merge = (base: Record<string, unknown>, overlay: Record<string, unknown>): Record<string, unknown> => {
    const result: Record<string, unknown> = { ...base }
    for (const [key, value] of Object.entries(overlay)) {
      if (forbiddenExtensionKeys.has(key) || !Object.hasOwn(base, key)) continue
      const baseValue = base[key]
      if (!isCompatibleExtensionValue(baseValue, value)) continue
      result[key] = isExtensionObject(baseValue) && isExtensionObject(value)
        ? merge(baseValue, value)
        : value
    }
    return result
  }
  return merge(defaults, extension ?? {}) as T
}
