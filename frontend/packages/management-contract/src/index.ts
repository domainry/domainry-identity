/**
 * Identity-owned management HTTP wire contracts.
 *
 * Keep application view models and request execution outside this package.
 * Embedded and SaaS admin clients consume these same payload shapes.
 */

export interface IdentityListQuery {
  page: number
  pageSize: number
  search?: string
  searchFields?: string[]
  filters?: Record<string, string>
  sort?: Array<{ field: string; direction: 'asc' | 'desc' }>
}

export interface IdentityPage<T> {
  items: T[]
  page: number
  page_size: number
  total: number
  has_next: boolean
}

export function identityListParams(query: IdentityListQuery): string {
  const params = new URLSearchParams({
    page: String(query.page),
    page_size: String(query.pageSize),
  })
  if (query.search?.trim()) params.set('search', query.search.trim())
  if (query.searchFields?.length) params.set('search_fields', query.searchFields.join(','))
  if (query.filters && Object.keys(query.filters).length) params.set('filters', JSON.stringify(query.filters))
  if (query.sort?.length) params.set('sort', query.sort.map((rule) => `${rule.field}:${rule.direction}`).join(','))
  return params.toString()
}

export interface IdentityOrganizationUnit {
  id: string
  code: string
  name: string
  node_type: 'company' | 'region' | 'store' | 'department' | 'team' | 'warehouse'
  parent_id?: string
  path: string
  ancestor_ids: string[]
  depth: number
  sort_order: number
  status: 'active' | 'disabled'
}

export interface IdentityUser {
  id: string
  name: string
  given_name?: string
  middle_name?: string
  family_name?: string
  name_prefix?: string
  name_suffix?: string
  native_name?: string
  name_locale?: string
  account_type: 'human' | 'service' | 'automation'
  locale?: string
  timezone?: string
  org_id?: string
  support_org_id?: string
  manager_user_id?: string
  reporting_path: string
  worker_no?: string
  worker_type?: 'employee' | 'contractor' | 'partner_staff' | 'temporary'
  work_status?: 'pending' | 'active' | 'suspended' | 'terminated'
  start_date?: string
  end_date?: string
  email: string
  phone?: string
  status: 'active' | 'disabled'
  version: number
  created_at: string
  updated_at: string
  initial_password?: string
  must_change_password?: boolean
}

export interface IdentityUserProjectionEntry {
  user: IdentityUser
  roles: Array<{ id: string; key: string; label: string; source?: string; status?: string }>
  security: { mfa_enabled: boolean; locked: boolean; active_sessions: number; last_login_at?: string }
  identity_badges: Array<{ kind: 'business_profile'; key: string; id: string; status: string }>
}

export interface IdentityRole {
  id: string
  key: string
  label: string
  description: string
  status: 'active' | 'disabled'
}

export type IdentityRolePage = IdentityPage<IdentityRole>

export interface IdentityRoleAssignment {
  user_id: string
  role_id: string
  binding_key?: string
  profile_id?: string
  source?: string
  status?: string
  valid_from?: string
  valid_until?: string
  granted_by?: string
  created_at?: string
  expires_at?: string
}

export interface IdentityUserDeletionImpact {
  user_id: string
  profile_bindings: Array<{ object_key: string; profile_id: string; binding_key: string; status: string }>
  active_role_ids: string[]
  business_profile_references: Array<{ object_key: string; field_key: string; count: number }>
  owned_record_references: Array<{ object_key: string; field_key: string; count: number }>
  pending_approval_task_ids: string[]
  retained_audit_event_ids: string[]
  active_legal_hold_ids: string[]
  blockers: string[]
  credentials_and_sessions_revoked: boolean
  can_delete: boolean
}

export interface IdentityUserDisableImpact {
  user_id: string
  profile_bindings: Array<{ object_key: string; profile_id: string; binding_key: string; status: string }>
  active_entitlement_role_ids: string[]
  sessions_will_be_revoked: boolean
  business_facts_preserved: boolean
}

export interface IdentityAccountSecurity {
  credential?: {
    user_id: string
    password_updated_at?: string
    failed_login_count: number
    locked_until?: string
    last_login_at?: string
    must_change_password: boolean
  }
  sessions: Array<{
    id: string
    session_id: string
    expires_at: string
    revoked_at?: string
    created_at?: string
    last_used_at?: string
  }>
  external_accounts: Array<{
    id: string
    provider: string
    email?: string
    phone?: string
    display_name?: string
    linked_at?: string
  }>
  mfa_factors: Array<{
    id: string
    type: string
    label?: string
    provider?: string
    status: string
    verified_at?: string
    last_used_at?: string
    created_at?: string
  }>
  mfa_enabled: boolean
  active_sessions: number
  locked: boolean
}

export interface IdentityBatchReceipt<T> {
  id: string
  workspace_id: string
  actor_id: string
  idempotency_key: string
  items: T[]
  replayed?: boolean
  created_at: string
}

export interface EntitlementBatchItem {
  operation: 'grant' | 'revoke'
  user_id: string
  role_id: string
  binding_key?: string
  profile_id?: string
  valid_from?: string
  valid_until?: string
  reason?: string
}

export interface IdentityMenu {
  id: string
  key: string
  label: string
  description?: string
  route?: string
  icon?: string
  parent_id?: string
  sort_order: number
  status: 'active' | 'disabled'
}

export interface IdentityRoleMenuAssignment {
  role_id: string
  menu_id: string
}

export interface EffectivePermissionDecision {
  key: string
  permission_key?: string
	data_scopes?: IdentityDataScope[]
  allowed: boolean
  reason: string
}

export interface EffectiveActionPermission {
  key: string
  object_key: string
  label?: string
  kind: string
  permission_key: string
	data_scopes?: IdentityDataScope[]
  allowed: boolean
  reason: string
  assurance_required: string[]
}

export interface EffectivePermissions {
  role_key: string
  user_id: string
  function_permissions?: Array<{ key: string; decision: EffectivePermissionDecision }>
  objects?: Array<{
    object_key: string
    actions: Array<EffectivePermissionDecision & { action?: string }>
  }>
  actions?: EffectiveActionPermission[]
}

export interface IdentityPolicyExpression {
  operator: 'and' | 'or' | 'not' | 'eq' | 'in'
  path?: Array<{
    direction: 'forward' | 'reverse'
    relation_field_key: string
    target_object_key: string
  }>
  field_key?: string
  value_source?: 'literal' | 'actor_claim'
  claim_key?: string
  values?: string[]
  children?: IdentityPolicyExpression[]
}

export type IdentityDataScope = 'all' | 'owner' | 'org' | 'org_child' | 'target_org'

export interface IdentityFieldPermission {
  resource: string
  field: string
  visible: boolean
  editable: boolean
  masked?: boolean
  policies?: unknown[]
}

export interface IdentityActionPermissionUsage {
  action_key: string
  capability_key?: string
  capability_label?: string
  operation_key?: string
  operation_label?: string
  object_key: string
  action_label: string
  http_method?: string
  route_template?: string
  display_route_template?: string
  page_route?: string
  page_label?: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  approval_required: boolean
  assurance_required: string[]
  lifecycle_status: string
}

export interface IdentityPermissionPoint {
  key: string
  label: string
  system: string
  resource: string
  resource_label: string
  action: string
  category: string
  description: string
  source_type?: string
  source_action_key?: string
  object_key?: string
  action_label?: string
  risk_level?: 'low' | 'medium' | 'high' | 'critical'
  approval_required?: boolean
  assurance_required?: string[]
  lifecycle_status?: string
  definition_status?: 'active' | 'retired'
  enabled?: boolean
  source_kind?: string
  source_owner?: string
  definition_hash?: string
  source_snapshot_hash?: string
  action_usage_status: 'available' | 'unavailable'
  action_usages?: IdentityActionPermissionUsage[]
}

export interface IdentityRolePermissionAssignment {
  role_id: string
  permission_key: string
  data_scope: IdentityDataScope
  audit_denial?: boolean
}

export interface IdentityRolePermissionGrant {
  permission_key: string
  data_scope: IdentityDataScope
  audit_denial?: boolean
}

export interface IdentityRoleFieldPermission {
  object_key: string
  field_key: string
  read: boolean
  write: boolean
  export: boolean
  masked?: boolean
  policies?: unknown[]
}

export interface IdentityRoleDefinition {
  key: string
  name: string
  description?: string
  permissions: IdentityRolePermissionGrant[]
  field_permissions?: IdentityRoleFieldPermission[]
  reference_permissions?: unknown[]
  export_rules?: Array<{ object_key: string; mode: string; fields: string[] }>
  audience?: 'any' | 'user' | 'business_profile' | 'service'
  required_binding_key?: string
  assignment_mode?: 'manual' | 'request_only' | 'system_managed'
  risk_level?: 'normal' | 'elevated' | 'privileged'
  conflict_role_keys?: string[]
  grantable_role_keys?: string[]
  permission_set_keys?: string[]
  permission_set_group_keys?: string[]
  guardrail_keys?: string[]
  [key: string]: unknown
}

export interface IdentityGrantSource {
  type: string
  key: string
  role_id?: string
  role_key?: string
  permission_set_key?: string
  permission_set_group_key?: string
  assignment_source?: string
  binding_key?: string
  profile_id?: string
  valid_from?: string
  valid_until?: string
  expires_at?: string
}

export interface IdentityEffectiveAccessSnapshot {
  user_id: string
  known: boolean
  authorization_revision?: string
  org_id?: string
  support_org_id?: string
  support_org_scope_ids?: string[]
  organization_path?: string
  role_keys: string[]
  permission_set_keys: string[]
  guardrail_keys: string[]
  permissions: Array<{
    key: string
    object_key?: string
    action?: string
    sources: IdentityGrantSource[]
  }>
  data_access: Array<{
	resource: string
    allowed: boolean
	scopes: IdentityDataScope[]
    audit_denial?: boolean
    sources: IdentityGrantSource[]
  }>
  field_access: Array<{
    object_key: string
    field_key: string
    read: boolean
    write: boolean
    export: boolean
    masked?: boolean
    sensitive?: boolean
    sources: IdentityGrantSource[]
  }>
}

export interface IdentityAccessReason {
  code: string
  effect: string
  layer: string
  subject?: string
  details?: Record<string, string>
  sources?: IdentityGrantSource[]
  children?: IdentityAccessReason[]
}

export interface IdentityAccessExplainResult {
  user_id: string
  object_key?: string
  action?: string
  field_key?: string
  allowed: boolean
  authorization_revision?: string
  reason: IdentityAccessReason
}

export interface IdentityAccessReverseIndex {
  user_roles: Record<string, string[]>
  role_permissions: Record<string, string[]>
  permission_roles: Record<string, string[]>
  object_action_roles: Record<string, string[]>
}

export interface IdentityRoleGovernanceDetail {
  role: { id: string; key: string; label: string; description: string; status: string }
  definition: IdentityRoleDefinition
  permission_sets: Array<{
    key: string
    name: string
    description?: string
    permissions?: string[]
  }>
  permission_set_groups: Array<{
    key: string
    name: string
    description?: string
    permission_set_keys: string[]
  }>
  guardrails: Array<{
    key: string
    name: string
    description?: string
    denied_permission_keys?: string[]
  }>
  permissions: IdentityRolePermissionAssignment[]
  field_permissions: IdentityFieldPermission[]
  export_rules: Array<{ object_key: string; mode: string; fields: string[] }>
  menus: Array<{ id: string; key: string; label: string; route?: string; status: string }>
  members: Array<IdentityGrantSource & {
    user_id: string
    source?: string
    status?: string
    granted_by?: string
    grant_reason?: string
    created_at?: string
  }>
}

export interface IdentityRoleChangeImpact {
  role_key: string
  affected_user_count: number
  profile_types: string[]
  added_permissions: string[]
  removed_permissions: string[]
  affected_objects: string[]
  affected_actions: string[]
  sensitive_fields: string[]
  high_risk_capabilities: string[]
}

export interface IdentityAuditEvent {
  id: string
  event: string
  object_key?: string
  record_id?: string
  actor_id: string
  role_key: string
  summary: string
  metadata?: Record<string, unknown>
  before?: Record<string, unknown>
  after?: Record<string, unknown>
  created_at: string
}

export interface IdentityRoleVersionHistory {
  capability_key: string
  resource_id: string
  versioning: string
  items: IdentityAuditEvent[]
  count: number
}
