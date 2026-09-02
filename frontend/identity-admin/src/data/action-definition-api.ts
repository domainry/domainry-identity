import { runtimeRequest } from '@/lib/runtime-api'
import type {
  IdentityRoleDefinition as RuntimeManifestRole,
} from '@domainry/identity-management-contract'
export type {
  IdentityRoleDataPermission as RuntimeRoleDataPermission,
  IdentityRoleDefinition as RuntimeManifestRole,
  IdentityRoleFieldPermission as RuntimeRoleFieldPermission,
} from '@domainry/identity-management-contract'

export interface RuntimeActionPayloadField {
  key: string
  name?: string
  type?: string
  options?: string[]
  required?: boolean
  default_value?: unknown
}

export interface RuntimeActionAssurancePolicy {
  required_methods: string[]
  recent_reauth_max_age_seconds?: number
  approval_version_field?: string
  approval_hash_field?: string
  maker_field?: string
}

export interface RuntimeActionDefinition {
  key: string
  object_key: string
  label: string
  kind: string
  risk_level?: 'low' | 'medium' | 'high' | 'critical'
  requires_permission: string
  preconditions: string[]
  audit_event: string
  payload_fields?: RuntimeActionPayloadField[]
  idempotency_keys?: string[]
  defaults?: Record<string, unknown>
  optimistic_concurrency?: boolean
  concurrency_field?: string
  assurance_policy?: RuntimeActionAssurancePolicy
  effect_set?: RuntimeActionEffectSet
}

export interface RuntimeActionObjectEffect {
  object_key: string
  fields: string[]
  operations?: string[]
}

export interface RuntimeActionEffectSet {
  read: RuntimeActionObjectEffect[]
  write: RuntimeActionObjectEffect[]
}

export interface RuntimeMetadataDefinition<T> {
  resource_type: string
  resource_key: string
  object_key?: string
  name?: string
  payload: T
  schema_version?: string
  schema_hash?: string
  source_kind?: string
  source_id?: string
  disabled_at?: string
  created_at?: string
  updated_at?: string
}

export interface RuntimeDefinitionValidationIssue {
  field_path: string
  step_key?: string
  operation_key?: string
  error_code: string
  message_key: string
  capability_key?: string
  contract_version: string
  params?: Record<string, string>
}

export interface RuntimeDefinitionValidation {
  valid: boolean
  resource_type: string
  resource_key: string
  normalized_payload?: unknown
  errors: RuntimeDefinitionValidationIssue[]
}

export interface RuntimeReferenceEdge {
  from_type: string
  from_key: string
  to_type: string
  to_key: string
  kind: string
  path?: string
}

export interface RuntimeReferenceGraph {
  version: string
  hash: string
  nodes: Array<{ resource_type: string; resource_key: string; object_key?: string; label?: string; owner?: string }>
  edges: RuntimeReferenceEdge[]
}

export interface RuntimeSystemSnapshot {
  snapshot_hash: string
  runtime_version: string
  authoring_contract_version: string
  authoring_contract_hash: string
  schema: { roles?: RuntimeManifestRole[] }
  resource_sources: Array<{
    resource_type: string
    resource_key: string
    object_key?: string
    name?: string
    schema_version?: string
    schema_hash?: string
    source_kind?: string
    source_id?: string
    disabled?: boolean
  }>
}

export interface RuntimeChangePlanItem {
  item_id: string
  operation: 'create' | 'update' | 'delete' | 'noop'
  change_kind: string
  risk_level: string
  resource_type: string
  resource_key: string
  resource_owner: string
  expected_resource_hash?: string
  owner_authorized: boolean
  capability_key: string
  before?: unknown
  after?: unknown
  dependencies?: Array<{ resource_type: string; resource_key: string; reason?: string }>
  impacts?: Array<{ resource_type: string; resource_key: string; reason?: string }>
  validation_methods: string[]
  rollback_method?: string
}

export interface RuntimeChangePlan {
  plan_version: 'domain-system-change-plan-v1'
  plan_id: string
  draft_revision?: number
  business_reason: string
  snapshot_hash: string
  reference_graph_hash: string
  runtime_version: string
  authoring_contract_version: string
  authoring_contract_hash: string
  reviewed: boolean
  reviewed_by?: string
  release_order: string[]
  rollback_order: string[]
  items: RuntimeChangePlanItem[]
}

export interface RuntimeChangePlanDraft {
  workspace_id: string
  plan_id: string
  revision: number
  status: 'draft' | 'in_review' | 'approved' | 'applying' | 'published'
  payload: RuntimeChangePlan
  created_by: string
  updated_by: string
  created_at: string
  updated_at: string
}

export interface RuntimeChangePlanValidation {
  valid: boolean
  apply_allowed: boolean
  issues: Array<{ item_id?: string; field_path: string; code: string; severity: string; params?: Record<string, string> }>
  diffs: unknown[]
  risk_summary: Record<string, number>
}

export interface SystemResourceChangePlanInput {
  snapshot: RuntimeSystemSnapshot
  graph: RuntimeReferenceGraph
  resourceType: string
  resourceKey: string
  current?: unknown
  after?: unknown
  expectedResourceHash?: string
  operation?: 'create' | 'update' | 'delete'
  resourceOwner?: string
  capabilityKey: string
  changeKind?: string
  riskLevel?: string
  validationMethods?: string[]
  reason: string
  planID: string
}

function systemResourceOwner(sourceKind?: string): string {
  switch ((sourceKind ?? '').trim().toLowerCase()) {
    case 'builder': case 'builder_v4': case 'model': case 'agent': return 'builder'
    case 'manual': case 'user': case 'human': case 'admin': return 'manual'
    case 'platform': case 'system': case 'runtime': return 'platform'
    case 'plugin': return 'plugin'
    case 'template': case 'generated': case 'manifest': case 'package': case 'seed': return 'template'
    default: return 'unknown'
  }
}

export function buildSystemResourceChangePlan(input: SystemResourceChangePlanInput): RuntimeChangePlan {
  const operation = input.operation ?? (input.current === undefined ? 'create' : 'update')
  const itemID = `${input.resourceType}:${input.resourceKey}`
  const source = input.snapshot.resource_sources.find((item) => item.resource_type === input.resourceType && item.resource_key === input.resourceKey)
  const item: RuntimeChangePlanItem = {
    item_id: itemID,
    operation,
    change_kind: input.changeKind ?? (operation === 'create' ? 'additive' : operation === 'delete' ? 'destructive' : 'compatible'),
    risk_level: input.riskLevel ?? (operation === 'delete' ? 'critical' : 'high'),
    resource_type: input.resourceType,
    resource_key: input.resourceKey,
		resource_owner: input.resourceOwner ?? systemResourceOwner(source?.source_kind),
    expected_resource_hash:
      operation === 'create'
        ? undefined
        : input.expectedResourceHash || source?.schema_hash,
    owner_authorized: true,
    capability_key: input.capabilityKey,
    before: input.current,
    after: operation === 'delete' ? undefined : input.after,
    validation_methods: input.validationMethods ?? ['metadata.validate', 'reference_graph.validate'],
    rollback_method: operation === 'create' ? 'restore_as_new_system_draft' : 'metadata.version.rollback',
  }
  return {
    plan_version: 'domain-system-change-plan-v1',
    plan_id: input.planID,
    business_reason: input.reason.trim(),
    snapshot_hash: input.snapshot.snapshot_hash,
    reference_graph_hash: input.graph.hash,
    runtime_version: input.snapshot.runtime_version,
    authoring_contract_version: input.snapshot.authoring_contract_version,
    authoring_contract_hash: input.snapshot.authoring_contract_hash,
    reviewed: false,
    release_order: [itemID],
    rollback_order: [itemID],
    items: [item],
  }
}

export type PublishSystemResourceChangeInput = Omit<SystemResourceChangePlanInput, 'snapshot' | 'graph' | 'planID'> & {
  planIDPrefix?: string
}

const pendingSystemDraftStorageKey = 'domainry.pending-system-drafts'
export const systemDraftSavedEvent = 'domainry:system-draft-saved'

export function pendingSystemDraftIDs(): string[] {
  if (typeof window === 'undefined') return []
  try {
    const parsed = JSON.parse(window.localStorage.getItem(pendingSystemDraftStorageKey) ?? '[]')
    return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === 'string' && value.trim() !== '') : []
  } catch {
    return []
  }
}

export function rememberPendingSystemDraft(planID: string): void {
  if (typeof window === 'undefined') return
  const next = Array.from(new Set([...pendingSystemDraftIDs(), planID])).slice(-20)
  window.localStorage.setItem(pendingSystemDraftStorageKey, JSON.stringify(next))
  window.dispatchEvent(new CustomEvent(systemDraftSavedEvent, { detail: { planID } }))
}

export function forgetPendingSystemDraft(planID: string): void {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(pendingSystemDraftStorageKey, JSON.stringify(pendingSystemDraftIDs().filter((value) => value !== planID)))
  window.dispatchEvent(new CustomEvent(systemDraftSavedEvent, { detail: { planID } }))
}

export async function saveSystemResourceDraft(input: PublishSystemResourceChangeInput): Promise<RuntimeChangePlanDraft> {
  const [snapshot, graph] = await Promise.all([systemChangePlansApi.snapshot(), systemChangePlansApi.graph()])
  const normalizedKey = input.resourceKey.trim().replace(/[^a-zA-Z0-9_.-]+/g, '-')
  const plan = buildSystemResourceChangePlan({
    ...input,
    snapshot,
    graph,
    planID: `${input.planIDPrefix ?? input.resourceType}-${normalizedKey}-${crypto.randomUUID()}`,
  })
  const validation = await systemChangePlansApi.validate(plan)
  const blockingIssues = validation.issues.filter((issue) => issue.code !== 'backend.change_plan.review_required')
  if (blockingIssues.length > 0 || (validation.valid && !validation.apply_allowed)) {
    throw new Error(blockingIssues.map((issue) => issue.code).join(',') || 'backend.change_plan.candidate_invalid')
  }
  const draft = await systemChangePlansApi.save(plan, 0)
  rememberPendingSystemDraft(draft.plan_id)
  return draft
}

export const actionDefinitionsApi = {
  list: () => runtimeRequest<{ definitions: RuntimeMetadataDefinition<RuntimeActionDefinition>[] }>('/tenant-admin/metadata/definitions/action').then((value) => value.definitions ?? []),
}

export const systemChangePlansApi = {
  snapshot: () => runtimeRequest<RuntimeSystemSnapshot>('/domain-system-snapshot'),
  graph: () => runtimeRequest<RuntimeReferenceGraph>('/domain-reference-graph'),
  validate: (plan: RuntimeChangePlan) => runtimeRequest<RuntimeChangePlanValidation>('/tenant-admin/change-plans/validate', { method: 'POST', body: plan }),
  save: (plan: RuntimeChangePlan, expectedRevision: number) => runtimeRequest<RuntimeChangePlanDraft>(`/tenant-admin/change-plans/${encodeURIComponent(plan.plan_id)}`, { method: 'PUT', body: { expected_revision: expectedRevision, plan } }),
  get: (planID: string) => runtimeRequest<RuntimeChangePlanDraft>(`/tenant-admin/change-plans/${encodeURIComponent(planID)}`),
  simulate: (draft: RuntimeChangePlanDraft) => runtimeRequest<{ plan_id: string; draft_revision: number; side_effect_free: boolean; passed: boolean; results: unknown[] }>(`/tenant-admin/change-plans/${encodeURIComponent(draft.plan_id)}/simulate`, { method: 'POST', body: { expected_revision: draft.revision } }),
  review: (draft: RuntimeChangePlanDraft) => runtimeRequest<{ draft: RuntimeChangePlanDraft; validation: RuntimeChangePlanValidation }>(`/tenant-admin/change-plans/${encodeURIComponent(draft.plan_id)}/review`, { method: 'POST', body: { expected_revision: draft.revision } }),
  approve: (draft: RuntimeChangePlanDraft) => runtimeRequest<{ draft: RuntimeChangePlanDraft; validation: RuntimeChangePlanValidation }>(`/tenant-admin/change-plans/${encodeURIComponent(draft.plan_id)}/approve`, { method: 'POST', body: { expected_revision: draft.revision } }),
  validateForPublish: (draft: RuntimeChangePlanDraft) => systemChangePlansApi.validate({
    ...draft.payload,
    draft_revision: draft.revision,
    reviewed: true,
    reviewed_by: draft.updated_by,
  }),
  publish: (draft: RuntimeChangePlanDraft) => runtimeRequest<{ result: unknown; current_snapshot: RuntimeSystemSnapshot }>('/tenant-admin/change-plans/apply', {
    method: 'POST',
    headers: { 'Idempotency-Key': `system-draft:${draft.plan_id}:${draft.revision}` },
    body: { plan_id: draft.plan_id, expected_revision: draft.revision, confirmation: draft.plan_id },
  }),
}
