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
  active: boolean
  enabled: boolean
  points: RuntimePermissionPoint[]
}

export interface PermissionCapabilityView {
  key: string
  label: string
  operations: PermissionCapabilityOperationView[]
}

export function buildPermissionCapabilityView(points: RuntimePermissionPoint[]): PermissionCapabilityView[] {
  const operations = new Map<string, PermissionCapabilityOperationView>()
  for (const point of points) {
    const usages = point.action_usages?.length ? point.action_usages : [{
      action_key: point.source_action_key || point.key,
      action_label: point.action_label || point.label,
      object_key: point.object_key || point.resource,
      authorization_strategy: point.authorization_strategy || 'dedicated_permission' as const,
      risk_level: point.risk_level || 'medium' as const,
      approval_required: point.approval_required || false,
      assurance_required: point.assurance_required || [],
      lifecycle_status: point.lifecycle_status || 'active',
    }]
    const usageGroups = new Map<string, typeof usages>()
    for (const usage of usages) {
      const capabilityKey = usage.capability_key || point.resource
      const operationKey = usage.operation_key || point.action
      const key = `${capabilityKey}\u0000${operationKey}`
      usageGroups.set(key, [...(usageGroups.get(key) ?? []), usage])
    }
    for (const [key, groupedUsages] of usageGroups) {
      const first = groupedUsages[0]
      const capabilityKey = first.capability_key || point.resource
      const operationKey = first.operation_key || point.action
      const current = operations.get(key) ?? {
        key,
        capabilityKey,
        capabilityLabel: first.capability_label || point.resource_label || capabilityKey,
        operationKey,
        operationLabel: first.operation_label || operationKey,
        permissionKeys: [],
        bindings: [],
        active: true,
        enabled: true,
        points: [],
      }
      if (!current.permissionKeys.includes(point.key)) current.permissionKeys.push(point.key)
      if (!current.points.some((candidate) => candidate.key === point.key)) current.points.push(point)
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

