import type { RuntimePermissionPoint } from '@/data/api'

export interface PermissionActionBindingView {
  actionKey: string
  actionLabel: string
  method: string
  route: string
  pageRoute: string
  pageLabel: string
}

export interface PermissionCapabilityOperationView {
  key: string
  capabilityKey: string
  capabilityLabel: string
  operationKey: string
  operationLabel: string
  permissionKeys: string[]
  bindings: PermissionActionBindingView[]
  usageAvailable: boolean
  active: boolean
  enabled: boolean
  points: RuntimePermissionPoint[]
}

export interface PermissionCapabilityView {
  key: string
  label: string
  operations: PermissionCapabilityOperationView[]
}

export interface PermissionCatalogGroupView {
  key: string
  category: string
  sourceKind: string
  sourceOwner: string
  resourceKey: string
  resourceLabel: string
  capabilities: PermissionCapabilityView[]
}

export function buildPermissionCatalogView(points: RuntimePermissionPoint[], runtimeResourceLabels: ReadonlyMap<string, string> = new Map()): PermissionCatalogGroupView[] {
  const groupedPoints = new Map<string, RuntimePermissionPoint[]>()
  for (const point of points) {
    const category = point.category || 'uncategorized'
    const sourceKind = point.source_kind || point.source_type || 'unknown'
    const sourceOwner = point.source_owner || 'unknown'
    const resourceKey = point.resource || point.object_key || 'unknown'
    const key = `${category}\u0000${sourceOwner}\u0000${sourceKind}\u0000${resourceKey}`
    groupedPoints.set(key, [...(groupedPoints.get(key) ?? []), point])
  }
  const result: PermissionCatalogGroupView[] = []
  for (const [key, group] of groupedPoints) {
    const first = group[0]
    result.push({
      key,
      category: first.category || 'uncategorized',
      sourceKind: first.source_kind || first.source_type || 'unknown',
      sourceOwner: first.source_owner || 'unknown',
      resourceKey: first.resource || first.object_key || 'unknown',
	  resourceLabel: runtimeResourceLabels.get(first.resource || first.object_key || '') || first.resource_label || first.resource || first.object_key || 'unknown',
      capabilities: buildPermissionCapabilityView(group),
    })
  }
  return result.sort((left, right) =>
    `${left.category}\u0000${left.sourceOwner}\u0000${left.resourceLabel}`.localeCompare(`${right.category}\u0000${right.sourceOwner}\u0000${right.resourceLabel}`),
  )
}

export function buildPermissionCapabilityView(points: RuntimePermissionPoint[]): PermissionCapabilityView[] {
  const operations = new Map<string, PermissionCapabilityOperationView>()
  for (const point of points) {
    const usages = point.action_usages ?? []
    const usageGroups = new Map<string, typeof usages>()
    for (const usage of usages) {
      const capabilityKey = usage.capability_key || point.resource
      const operationKey = usage.operation_key || point.action
      const key = `${capabilityKey}\u0000${operationKey}`
      usageGroups.set(key, [...(usageGroups.get(key) ?? []), usage])
    }
    if (usageGroups.size === 0) {
      usageGroups.set(`${point.resource}\u0000${point.action}`, [])
    }
    for (const [key, groupedUsages] of usageGroups) {
      const first = groupedUsages[0]
      const capabilityKey = first?.capability_key || point.resource
      const operationKey = first?.operation_key || point.action
      const current = operations.get(key) ?? {
        key,
        capabilityKey,
        capabilityLabel: first?.capability_label || point.resource_label || capabilityKey,
        operationKey,
        operationLabel: first?.operation_label || point.label || operationKey,
        permissionKeys: [],
        bindings: [],
        usageAvailable: true,
        active: true,
        enabled: true,
        points: [],
      }
      if (!current.permissionKeys.includes(point.key)) current.permissionKeys.push(point.key)
      if (!current.points.some((candidate) => candidate.key === point.key)) current.points.push(point)
      current.usageAvailable = current.usageAvailable && point.action_usage_status === 'available'
      current.active = current.active && (point.definition_status ?? 'active') === 'active'
      current.enabled = current.enabled && (point.enabled ?? true)
      for (const usage of groupedUsages) {
        const binding = {
          actionKey: usage.action_key,
          actionLabel: usage.action_label || usage.action_key,
          method: usage.http_method || '',
          route: usage.display_route_template || usage.route_template || '',
          pageRoute: usage.page_route || '',
          pageLabel: usage.page_label || '',
        }
        if (!current.bindings.some((candidate) => candidate.actionKey === binding.actionKey)) current.bindings.push(binding)
      }
      current.permissionKeys.sort()
      current.bindings.sort((left, right) => `${left.method} ${left.route}`.localeCompare(`${right.method} ${right.route}`))
      operations.set(key, current)
    }
  }
  const capabilities = new Map<string, PermissionCapabilityView>()
  for (const operation of operations.values()) {
    const capability = capabilities.get(operation.capabilityKey) ?? { key: operation.capabilityKey, label: operation.capabilityLabel, operations: [] }
    capability.operations.push(operation)
    capabilities.set(operation.capabilityKey, capability)
  }
  const result = [...capabilities.values()]
  for (const capability of result) capability.operations.sort((left, right) => left.operationLabel.localeCompare(right.operationLabel))
  return result.sort((left, right) => left.label.localeCompare(right.label))
}
