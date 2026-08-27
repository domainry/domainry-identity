import { createRuntimeRequestID, RuntimeApiError, runtimeRequest, runtimeRequestWithResponse } from "@/lib/runtime-api";
import type {
  Department,
  IdentityAccount,
  OrgUser,
  PermAction,
  PermMatrix,
  Role,
  WorkforceProfile,
  WorkforceAssignment,
  WorkforceDetail,
  WorkforceAssignableRole,
} from "./types";
import { identityListParams, type IdentityListQuery, type IdentityPage } from "./identity-list-query";
export type { IdentityListQuery, IdentityPage } from "./identity-list-query";
import identityUserAuthoringContract from "./generated/identity-user-authoring-contract.json";
import { saveSystemResourceDraft } from "./action-definition-api";

const identityUserWritableFields = new Set(
  identityUserAuthoringContract.parameters
    .filter((parameter) => !("read_only" in parameter) || !parameter.read_only)
    .map((parameter) => parameter.key),
);

function identityUserWriteBody(body: Record<string, unknown>) {
  for (const key of Object.keys(body)) {
    if (!identityUserWritableFields.has(key)) {
      throw new Error(`identity.user write field ${key} is not declared by the Runtime authoring contract`);
    }
  }
  return body;
}

interface RuntimeDepartment {
  id: string;
  name: string;
  parent_id?: string;
  path: string;
  ancestor_ids: string[];
  depth: number;
  sort_order: number;
  status: "active" | "disabled";
}

interface RuntimeUser {
  id: string;
  name: string;
  given_name?: string;
  middle_name?: string;
  family_name?: string;
  name_prefix?: string;
  name_suffix?: string;
  native_name?: string;
  name_locale?: string;
  account_type: "human" | "service" | "automation";
  locale?: string;
  timezone?: string;
  email: string;
  phone?: string;
  status: "active" | "disabled";
  version: number;
  created_at: string;
  updated_at: string;
  initial_password?: string;
  must_change_password?: boolean;
}

interface RuntimeUserDirectoryEntry {
  user: RuntimeUser;
  roles: Array<{ id: string; key: string; label: string; source?: string; status?: string }>;
  security: { mfa_enabled: boolean; locked: boolean; active_sessions: number; last_login_at?: string };
  identity_badges: Array<{ kind: "workforce" | "business_profile"; key: string; id: string; status: string }>;
}

function mapIdentityAccount(user: RuntimeUser, resourceHash?: string): IdentityAccount {
  return {
    id: user.id,
    name: user.name,
    givenName: user.given_name ?? "",
    middleName: user.middle_name ?? "",
    familyName: user.family_name ?? "",
    namePrefix: user.name_prefix ?? "",
    nameSuffix: user.name_suffix ?? "",
    nativeName: user.native_name ?? "",
    nameLocale: user.name_locale ?? "",
    accountType: user.account_type,
    locale: user.locale ?? "",
    timezone: user.timezone ?? "",
    email: user.email,
    phone: user.phone ?? "",
    status: user.status,
    version: user.version,
    resourceHash,
    createdAt: user.created_at,
    updatedAt: user.updated_at,
  };
}

export interface RuntimeRole {
  id: string;
  key: string;
  label: string;
  description: string;
  status: "active" | "disabled";
  permission_keys: string[] | null;
  data_scopes: unknown[] | null;
  field_permissions: unknown[] | null;
}

interface RuntimeRolePage {
  items: RuntimeRole[];
  page: number;
  page_size: number;
  total: number;
  has_next: boolean;
}

export interface RoleListQuery {
  page: number;
  pageSize: number;
  search?: string;
  searchFields?: string[];
}

export interface RolePage {
  items: Role[];
  page: number;
  pageSize: number;
  total: number;
  hasNext: boolean;
}

export interface RoleCreateInput extends Omit<Role, "id"> {
  businessReason: string;
  permissionKeys: string[];
  dataPermission: {
    object_key: string;
    scope: string;
    read: boolean;
    write: boolean;
  };
}

export interface RuntimeRoleAssignment {
  user_id: string;
  role_id: string;
  workforce_profile_id?: string;
  binding_key?: string;
  profile_id?: string;
  source?: string;
  status?: string;
  valid_from?: string;
  valid_until?: string;
  granted_by?: string;
  created_at?: string;
  expires_at?: string;
}

export interface IdentityUserDeletionImpact {
  user_id: string;
  profile_bindings: Array<{ object_key: string; profile_id: string; binding_key: string; status: string }>;
  workforce_profile_ids: string[];
  active_role_ids: string[];
  business_profile_references: Array<{ object_key: string; field_key: string; count: number }>;
  owned_record_references: Array<{ object_key: string; field_key: string; count: number }>;
  pending_approval_task_ids: string[];
  retained_audit_event_ids: string[];
  active_legal_hold_ids: string[];
  blockers: string[];
  credentials_and_sessions_revoked: boolean;
  can_delete: boolean;
}

export interface IdentityUserDisableImpact {
  user_id: string;
  profile_bindings: Array<{ object_key: string; profile_id: string; binding_key: string; status: string }>;
  workforce_profile_ids: string[];
  active_entitlement_role_ids: string[];
  sessions_will_be_revoked: boolean;
  business_facts_preserved: boolean;
}

export interface IdentityAccountSecurity {
  credential?: {
    user_id: string;
    password_updated_at?: string;
    failed_login_count: number;
    locked_until?: string;
    last_login_at?: string;
    must_change_password: boolean;
  };
  sessions: Array<{
    id: string;
    session_id: string;
    expires_at: string;
    revoked_at?: string;
    created_at?: string;
    last_used_at?: string;
  }>;
  external_accounts: Array<{
    id: string;
    provider: string;
    email?: string;
    phone?: string;
    display_name?: string;
    linked_at?: string;
  }>;
  mfa_factors: Array<{
    id: string;
    type: string;
    label?: string;
    provider?: string;
    status: string;
    verified_at?: string;
    last_used_at?: string;
    created_at?: string;
  }>;
  mfa_enabled: boolean;
  active_sessions: number;
  locked: boolean;
}

interface RuntimeWorkforceProfile {
  id: string;
  organization_id: string;
  identity_user_id: string;
  worker_no: string;
  worker_type: WorkforceProfile["workerType"];
  work_status: WorkforceProfile["workStatus"];
  start_date?: string;
  end_date?: string;
  primary_assignment_id?: string;
  version: number;
}

interface RuntimeWorkforceProfilePage {
  items: RuntimeWorkforceProfile[];
  page: number;
  page_size: number;
  total: number;
  has_next: boolean;
}

interface RuntimeWorkforceAssignment {
  id: string;
  workforce_profile_id: string;
  organization_unit_id: string;
  position_id?: string;
  manager_workforce_profile_id?: string;
  assignment_type: WorkforceAssignment["assignmentType"];
  effective_from?: string;
  effective_to?: string;
  status: WorkforceAssignment["status"];
  version: number;
}

interface RuntimeWorkforceDetail {
  profile: RuntimeWorkforceProfile;
  assignments: RuntimeWorkforceAssignment[];
  account: RuntimeUser;
  business_profiles: Array<{
    binding_key: string;
    object_key: string;
    profile_id: string;
    status: WorkforceDetail["businessProfiles"][number]["status"];
  }>;
}

export type WorkforceLifecycleOperation = "invite" | "onboard" | "assign" | "transfer" | "add_secondary" | "suspend" | "revoke_access";

export interface WorkforceLifecycleInput {
  operation: WorkforceLifecycleOperation;
  profile: {
    id: string;
    organization_id?: string;
    identity_user_id?: string;
    worker_no?: string;
    worker_type?: WorkforceProfile["workerType"];
    work_status?: WorkforceProfile["workStatus"];
    start_date?: string;
    end_date?: string;
    primary_assignment_id?: string;
    version?: number;
  };
  assignment?: {
    id: string;
    organization_unit_id: string;
    position_id?: string;
    manager_workforce_profile_id?: string;
    assignment_type?: WorkforceAssignment["assignmentType"];
    effective_from?: string;
  };
  previous_assignment_id?: string;
  effective_at?: string;
  reason?: string;
}

export interface WorkforceOnboardingInput {
  user: {
    id: string;
    name: string;
    email: string;
    phone?: string;
    status: "active";
  };
  profile: {
    id: string;
    organization_id: string;
    identity_user_id: string;
    worker_no: string;
    worker_type: WorkforceProfile["workerType"];
    work_status: "active";
    start_date?: string;
  };
  assignment: {
    id: string;
    organization_unit_id: string;
    effective_from?: string;
  };
  role_ids?: string[];
  reason?: string;
}

export interface WorkforceOnboardingResult {
  user: RuntimeUser;
  profile: RuntimeWorkforceProfile;
  assignment: RuntimeWorkforceAssignment;
  role_assignments: RuntimeRoleAssignment[];
}

export interface WorkforceLifecycleResult {
  profile?: RuntimeWorkforceProfile;
  assignments?: RuntimeWorkforceAssignment[];
  ended_assignment_count: number;
  revoked_entitlement_count: number;
}

export interface WorkforceTransferBatchItem {
  profile_id: string;
  previous_assignment_id: string;
  assignment: NonNullable<WorkforceLifecycleInput["assignment"]>;
  effective_at: string;
  reason?: string;
}

export interface IdentityBatchReceipt<T> {
  id: string;
  workspace_id: string;
  actor_id: string;
  idempotency_key: string;
  items: T[];
  replayed?: boolean;
  created_at: string;
}

export interface EntitlementBatchItem {
  operation: "grant" | "revoke";
  user_id: string;
  role_id: string;
  workforce_profile_id?: string;
  binding_key?: string;
  profile_id?: string;
  valid_from?: string;
  valid_until?: string;
  reason?: string;
}

export interface RuntimeMenu {
  id: string;
  key: string;
  label: string;
  description?: string;
  route?: string;
  icon?: string;
  parent_id?: string;
  sort_order: number;
  status: "active" | "disabled";
}

export interface RuntimeRoleMenuAssignment {
  role_id: string;
  menu_id: string;
}

export interface RuntimeSchema {
  template_id?: string;
  template_version?: string;
  name?: string;
  schema_hash?: string;
  objects?: RuntimeObjectSchema[];
  actions?: RuntimePublishedAction[];
  guarded_writes?: Array<{
    object_key: string;
    operation: string;
    action_key: string;
    endpoint?: string;
  }>;
}

export interface RuntimePublishedAction {
  key: string;
  object_key: string;
  label?: string;
  kind?: string;
  requires_permission?: string;
  preconditions?: string[];
  payload_fields?: Array<{
    key: string;
    name?: string;
    type?: string;
    options?: string[];
    required?: boolean;
    default_value?: unknown;
  }>;
  assurance_policy?: {
    required_methods: string[];
  };
  config?: Record<string, unknown>;
}

export interface RuntimeObjectField {
  key: string;
  name?: string;
  label?: string;
  type: string;
  required?: boolean;
  unique?: boolean;
  default?: unknown;
  default_value?: unknown;
  config?: Record<string, unknown>;
  validation?: Record<string, unknown>;
  i18n?: Record<string, { name?: string; label?: string; description?: string }>;
}

export interface RuntimeObjectSchema {
  key: string;
  name?: string;
  label?: string;
  fields: RuntimeObjectField[];
  ux?: Record<string, unknown>;
  config?: Record<string, unknown>;
  i18n?: Record<string, { name?: string; label?: string; description?: string }>;
}

export interface RuntimeAuditEvent {
  id: string;
  event: string;
  object_key?: string;
  record_id?: string;
  actor_id: string;
  role_key: string;
  summary: string;
  metadata?: Record<string, unknown>;
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  created_at: string;
}

export interface EffectivePermissionDecision {
  key: string;
  permission_key?: string;
  data_scope?: string;
  allowed: boolean;
  reason: string;
}

export interface EffectiveActionPermission {
  key: string;
  object_key: string;
  label?: string;
  kind: string;
  permission_key: string;
  data_scope: string;
  allowed: boolean;
  reason: string;
  assurance_required: string[];
}

export interface EffectivePermissions {
  role_key: string;
  user_id: string;
  function_permissions?: Array<{
    key: string;
    decision: EffectivePermissionDecision;
  }>;
  objects?: Array<{
    object_key: string;
    actions: Array<EffectivePermissionDecision & { action?: string }>;
  }>;
  actions?: EffectiveActionPermission[];
}

export interface RuntimeDataScopePolicy {
  resource: string;
  scope: string;
  audit_denial?: boolean;
  predicate?: RuntimeIdentityPolicyExpression;
}

export interface RuntimeIdentityPolicyExpression {
  operator: 'and' | 'or' | 'not' | 'eq' | 'in';
  path?: Array<{
    direction: 'forward' | 'reverse';
    relation_field_key: string;
    target_object_key: string;
  }>;
  field_key?: string;
  value_source?: 'literal' | 'actor_claim';
  claim_key?: string;
  values?: string[];
  children?: RuntimeIdentityPolicyExpression[];
}

export interface RuntimeFieldPermission {
  resource: string;
  field: string;
  visible: boolean;
  editable: boolean;
  masked?: boolean;
  policies?: unknown[];
}

export interface RuntimePermissionPoint {
  key: string;
  label: string;
  system: string;
  resource: string;
  resource_label: string;
  action: string;
  category: string;
  description: string;
  source_type?: string;
  source_action_key?: string;
  object_key?: string;
  action_label?: string;
  authorization_strategy?: 'inherit_object_permission' | 'dedicated_permission';
  risk_level?: 'low' | 'medium' | 'high' | 'critical';
  approval_required?: boolean;
  assurance_required?: string[];
  lifecycle_status?: string;
  action_usages?: RuntimeActionPermissionUsage[];
}

export interface RuntimeActionPermissionUsage {
  action_key: string;
  object_key: string;
  action_label: string;
  authorization_strategy: 'inherit_object_permission' | 'dedicated_permission';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  approval_required: boolean;
  assurance_required: string[];
  lifecycle_status: string;
}

export interface RuntimeRolePermissionAssignment {
  role_id: string;
  permission_key: string;
}

function makeID(prefix: string, source: string): string {
  const normalized = source
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `${prefix}_${normalized || crypto.randomUUID().slice(0, 8)}`;
}

function mapDepartment(value: RuntimeDepartment, memberCount = 0): Department {
  return {
    id: value.id,
    parentId: value.parent_id ?? null,
    name: value.name,
    leader: "",
    memberCount,
    sort: value.sort_order ?? 0,
    status: value.status || "active",
    updatedAt: "",
  };
}

interface RuntimeAuthoringResult<T> {
  resource: T;
  resource_hash?: string;
  snapshot_hash?: string;
}

function runtimeAuthoringResource<T>(
  value: T | RuntimeAuthoringResult<T>,
): T {
  if (
    typeof value === "object" &&
    value !== null &&
    "resource" in value
  ) {
    return (value as RuntimeAuthoringResult<T>).resource;
  }
  return value as T;
}

async function runtimeDepartments(): Promise<RuntimeDepartment[]> {
  return runtimeRequest<RuntimeDepartment[]>("/identity/departments");
}

async function runtimeUsers(): Promise<RuntimeUser[]> {
  return runtimeRequest<RuntimeUser[]>("/identity/users");
}

export const departmentsApi = {
  async list(): Promise<Department[]> {
    return (await runtimeDepartments()).map((department) => mapDepartment(department));
  },
  async create(input: Omit<Department, "id">): Promise<Department> {
    const requestID = createRuntimeRequestID();
    const result = await runtimeRequest<
      RuntimeDepartment | RuntimeAuthoringResult<RuntimeDepartment>
    >(
      "/identity/departments",
      {
        method: "POST",
        headers: {
          "Builder-Task-ID": `tenant-admin.identity-department.${requestID}`,
          "Idempotency-Key": requestID,
          "Expected-Schema-Hash": "empty",
        },
        body: {
          id: makeID("dept", String(input.name)),
          name: input.name,
          parent_id: input.parentId || undefined,
          sort_order: input.sort,
          status: input.status,
        },
      },
    );
    const department = runtimeAuthoringResource(result);
    return mapDepartment(department);
  },
  async update(
    id: string,
    patch: Partial<Omit<Department, "id">>,
  ): Promise<Department> {
    const path = `/identity/departments/${encodeURIComponent(id)}`;
    const current = await runtimeRequestWithResponse<RuntimeDepartment>(path);
    const existing = current.data;
    const expectedResourceHash = current.headers.get("X-Resource-Hash")?.trim();
    if (!expectedResourceHash) {
      throw new RuntimeApiError(
        503,
        { code: "backend.authoring.resource_projection_unavailable" },
        "Runtime did not publish the authoritative department resource hash",
      );
    }
    const requestID = createRuntimeRequestID();
    const result = await runtimeRequest<
      RuntimeDepartment | RuntimeAuthoringResult<RuntimeDepartment>
    >(
      path,
      {
        method: "PATCH",
        headers: {
          "Builder-Task-ID": `tenant-admin.identity-department.${requestID}`,
          "Idempotency-Key": requestID,
          "Expected-Schema-Hash": expectedResourceHash,
        },
        body: {
          ...existing,
          name: patch.name ?? existing.name,
          parent_id:
            patch.parentId === undefined
              ? existing.parent_id
              : patch.parentId || undefined,
          sort_order: patch.sort ?? existing.sort_order,
          status: patch.status ?? existing.status,
        },
      },
    );
    const department = runtimeAuthoringResource(result);
    return mapDepartment(department, patch.memberCount);
  },
  async remove(): Promise<void> {
    throw new RuntimeApiError(
      405,
      {},
      "The runtime does not expose destructive department deletion",
    );
  },
};

async function userRoleAssignments(
  userID: string,
): Promise<RuntimeRoleAssignment[]> {
  return runtimeRequest<RuntimeRoleAssignment[]>(
    `/identity/users/${userID}/role-assignments`,
  );
}

async function assignIdentityUserRole(
  userID: string,
  body: {
    role_id: string;
    grant_reason: string;
    workforce_profile_id?: string;
  },
): Promise<void> {
  const path = `/identity/users/${encodeURIComponent(userID)}/role-assignments`;
  const current = await runtimeRequestWithResponse<RuntimeRoleAssignment[]>(path);
  const expectedResourceHash = current.headers.get("X-Resource-Hash")?.trim();
  if (!expectedResourceHash) {
    throw new RuntimeApiError(
      503,
      { code: "backend.authoring.resource_projection_unavailable" },
      "Runtime did not publish the authoritative role-assignment resource hash",
    );
  }
  const requestID = createRuntimeRequestID();
  await runtimeRequest(path, {
    method: "POST",
    headers: {
      "Builder-Task-ID": `tenant-admin.identity-role-assignment.${requestID}`,
      "Idempotency-Key": requestID,
      "Expected-Schema-Hash": expectedResourceHash,
    },
    body,
  });
}

function mapUser(
  user: RuntimeUser,
  roleIds: string[],
  lastLogin = "",
  identityBadges: OrgUser["identityBadges"] = [],
  securitySummary: OrgUser["securitySummary"] = { mfaEnabled: false, locked: false, activeSessions: 0 },
): OrgUser {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    employeeNo: "",
    phone: user.phone ?? "",
    gender: "",
    hireDate: "",
    jobTitle: "",
    jobLevel: "",
    managerId: "",
    managerPath: [user.id],
    employmentType: "",
    employmentStatus: "",
    deptId: "",
    roleIds,
    status: user.status,
    lastLogin,
    identityBadges,
    securitySummary,
  };
}

export const usersApi = {
  async list(): Promise<OrgUser[]> {
    const result: OrgUser[] = [];
    let pageNumber = 1;
    let hasNext = true;
    while (hasNext) {
      const page = await runtimeRequest<IdentityPage<RuntimeUserDirectoryEntry>>(
        `/identity/users/directory/search?${identityListParams({
          page: pageNumber,
          pageSize: 200,
          sort: [{ field: "name", direction: "asc" }, { field: "id", direction: "asc" }],
        })}`,
      );
      result.push(...page.items.map((entry) => mapUser(
        entry.user,
        entry.roles.map((role) => role.id),
        entry.security.last_login_at,
        entry.identity_badges,
        {
          mfaEnabled: entry.security.mfa_enabled,
          locked: entry.security.locked,
          activeSessions: entry.security.active_sessions,
        },
      )));
      hasNext = page.has_next;
      pageNumber += 1;
    }
    return result;
  },
  async get(id: string): Promise<OrgUser> {
    const [user, assignments, security] = await Promise.all([
      runtimeRequest<RuntimeUser>(`/identity/users/${encodeURIComponent(id)}`),
      userRoleAssignments(id),
      runtimeRequest<IdentityAccountSecurity>(`/identity/users/${encodeURIComponent(id)}/security`),
    ]);
    return mapUser(user, assignments.map((item) => item.role_id), security.credential?.last_login_at);
  },
  async create(_input: Omit<OrgUser, "id">): Promise<OrgUser> {
    throw new RuntimeApiError(
      410,
      {},
      "The mixed account/employee editor is retired; create Workforce through the atomic onboarding command",
    );
  },
  async update(
    _id: string,
    _patch: Partial<Omit<OrgUser, "id">>,
  ): Promise<OrgUser> {
    throw new RuntimeApiError(
      410,
      {},
      "The mixed account/employee editor is retired; update account and Workforce through their independent commands",
    );
  },
  async remove(id: string): Promise<void> {
    await runtimeRequest(`/identity/users/${id}`, { method: "DELETE" });
  },
};

export const identityAccountsApi = {
  async list(): Promise<IdentityAccount[]> {
    return (await runtimeUsers()).map((user) => mapIdentityAccount(user));
  },
  async search(query: IdentityListQuery): Promise<IdentityPage<IdentityAccount>> {
    const page = await runtimeRequest<IdentityPage<RuntimeUser>>(`/identity/users/search?${identityListParams(query)}`);
    return { ...page, items: page.items.map((user) => mapIdentityAccount(user)) };
  },
  async get(id: string): Promise<IdentityAccount> {
    const response = await runtimeRequestWithResponse<RuntimeUser>(`/identity/users/${encodeURIComponent(id)}`);
    return mapIdentityAccount(response.data, response.headers.get("X-Resource-Hash")?.trim() || undefined);
  },
  async provision(input: Omit<IdentityAccount, "id" | "version" | "createdAt" | "updatedAt">): Promise<{
    account: IdentityAccount;
    initialPassword: string;
    mustChangePassword: boolean;
  }> {
    const id = makeID("user", input.email.split("@")[0] || String(input.name));
    const user = await runtimeRequest<RuntimeUser>("/identity/users", {
      method: "POST",
      body: identityUserWriteBody({
        id,
        name: input.name,
        given_name: input.givenName,
        middle_name: input.middleName,
        family_name: input.familyName,
        name_prefix: input.namePrefix,
        name_suffix: input.nameSuffix,
        native_name: input.nativeName,
        name_locale: input.nameLocale,
        account_type: input.accountType,
        locale: input.locale,
        timezone: input.timezone,
        email: input.email,
        phone: input.phone,
        status: input.status,
      }),
    });
    if (!user.initial_password || user.must_change_password !== false) {
      throw new RuntimeApiError(
        502,
        {},
        "Runtime created the account without returning its fixed initial credential",
      );
    }
    return {
      account: mapIdentityAccount(user),
      initialPassword: user.initial_password,
      mustChangePassword: user.must_change_password,
    };
  },
  async create(input: Omit<IdentityAccount, "id" | "version" | "createdAt" | "updatedAt">): Promise<IdentityAccount> {
    return (await this.provision(input)).account;
  },
  async update(id: string, patch: Partial<Omit<IdentityAccount, "id" | "version" | "createdAt" | "updatedAt">> & { expectedResourceHash?: string }): Promise<IdentityAccount> {
    const path = `/identity/users/${encodeURIComponent(id)}`;
    const currentResponse = await runtimeRequestWithResponse<RuntimeUser>(path);
    const current = currentResponse.data;
    const observedResourceHash = currentResponse.headers.get("X-Resource-Hash")?.trim();
    const expectedResourceHash = patch.expectedResourceHash?.trim() || observedResourceHash;
    if (!observedResourceHash || !expectedResourceHash) {
      throw new RuntimeApiError(
        503,
        { code: "backend.authoring.resource_projection_unavailable" },
        "Runtime did not publish the authoritative identity user resource hash",
      );
    }
    const statusOnly = patch.status !== undefined
      && patch.status !== current.status
      && Object.keys(patch).every((key) => key === "status" || key === "expectedResourceHash");
    if (statusOnly) {
      await runtimeRequest(`/identity/users/${encodeURIComponent(id)}/${patch.status === "disabled" ? "disable" : "enable"}`, {
        method: "POST",
      });
      return mapIdentityAccount(await runtimeRequest<RuntimeUser>(path));
    }
    const requestID = createRuntimeRequestID();
    const result = await runtimeRequest<
      RuntimeUser | RuntimeAuthoringResult<RuntimeUser>
    >(path, {
      method: "PATCH",
      headers: {
        "Builder-Task-ID": `tenant-admin.identity-user.${requestID}`,
        "Idempotency-Key": requestID,
        "Expected-Schema-Hash": expectedResourceHash,
      },
      body: identityUserWriteBody({
        name: patch.name ?? current.name,
        given_name: patch.givenName ?? current.given_name ?? "",
        middle_name: patch.middleName ?? current.middle_name ?? "",
        family_name: patch.familyName ?? current.family_name ?? "",
        name_prefix: patch.namePrefix ?? current.name_prefix ?? "",
        name_suffix: patch.nameSuffix ?? current.name_suffix ?? "",
        native_name: patch.nativeName ?? current.native_name ?? "",
        name_locale: patch.nameLocale ?? current.name_locale ?? "",
        account_type: patch.accountType ?? current.account_type,
        locale: patch.locale ?? current.locale ?? "",
        timezone: patch.timezone ?? current.timezone ?? "",
        email: patch.email ?? current.email,
        phone: patch.phone ?? current.phone ?? "",
        status: patch.status ?? current.status,
      }),
    });
    return mapIdentityAccount(runtimeAuthoringResource(result));
  },
  async remove(id: string): Promise<void> {
    await runtimeRequest(`/identity/users/${encodeURIComponent(id)}`, { method: "DELETE" });
  },
  deletionImpact(id: string): Promise<IdentityUserDeletionImpact> {
    return runtimeRequest(`/identity/users/${encodeURIComponent(id)}/deletion-impact`);
  },
  security(id: string): Promise<IdentityAccountSecurity> {
    return runtimeRequest(`/identity/users/${encodeURIComponent(id)}/security`);
  },
  roleAssignments(id: string, query: IdentityListQuery): Promise<IdentityPage<RuntimeRoleAssignment>> {
    return runtimeRequest(`/identity/users/${encodeURIComponent(id)}/role-assignments/search?${identityListParams(query)}`);
  },
  async assignRole(id: string, roleID: string, reason: string): Promise<void> {
    await assignIdentityUserRole(id, { role_id: roleID, grant_reason: reason });
  },
  disableImpact(id: string): Promise<IdentityUserDisableImpact> {
    return runtimeRequest(`/identity/users/${encodeURIComponent(id)}/disable-impact`);
  },
  resetPassword(id: string, newPassword: string): Promise<{ ok: boolean }> {
    return runtimeRequest("/auth/reset-password", {
      method: "POST",
      headers: { "Idempotency-Key": createRuntimeRequestID() },
      body: { user_id: id, new_password: newPassword, must_change_password: true },
    });
  },
  unlock(id: string): Promise<{ status: string }> {
    return runtimeRequest(`/identity/users/${encodeURIComponent(id)}/unlock`, { method: "POST" });
  },
  forceLogout(id: string): Promise<{ revoked_sessions: number }> {
    return runtimeRequest(`/identity/users/${encodeURIComponent(id)}/force-logout`, {
      method: "POST",
      headers: { "Idempotency-Key": createRuntimeRequestID() },
    });
  },
};

function mapWorkforceProfile(profile: RuntimeWorkforceProfile): WorkforceProfile {
  return {
    id: profile.id,
    organizationId: profile.organization_id,
    identityUserId: profile.identity_user_id,
    workerNo: profile.worker_no,
    workerType: profile.worker_type,
    workStatus: profile.work_status,
    startDate: profile.start_date ?? "",
    endDate: profile.end_date ?? "",
    primaryAssignmentId: profile.primary_assignment_id ?? "",
    version: profile.version,
  };
}

function mapWorkforceAssignment(assignment: RuntimeWorkforceAssignment): WorkforceAssignment {
  return {
    id: assignment.id,
    workforceProfileId: assignment.workforce_profile_id,
    organizationUnitId: assignment.organization_unit_id,
    positionId: assignment.position_id ?? "",
    managerWorkforceProfileId: assignment.manager_workforce_profile_id ?? "",
    assignmentType: assignment.assignment_type,
    effectiveFrom: assignment.effective_from ?? "",
    effectiveTo: assignment.effective_to ?? "",
    status: assignment.status,
    version: assignment.version,
  };
}

export const workforceApi = {
  async list(): Promise<WorkforceProfile[]> {
    const page = await runtimeRequest<RuntimeWorkforceProfilePage>("/identity/workforce");
    return page.items.map(mapWorkforceProfile);
  },
  async search(query: IdentityListQuery): Promise<IdentityPage<WorkforceProfile>> {
    const page = await runtimeRequest<IdentityPage<RuntimeWorkforceProfile>>(`/identity/workforce/search?${identityListParams(query)}`);
    return { ...page, items: page.items.map(mapWorkforceProfile) };
  },
  async detail(profileID: string): Promise<WorkforceDetail> {
    const detail = await runtimeRequest<RuntimeWorkforceDetail>(`/identity/workforce/${encodeURIComponent(profileID)}/detail`);
    return {
      profile: mapWorkforceProfile(detail.profile),
      assignments: detail.assignments.map(mapWorkforceAssignment),
      account: mapIdentityAccount(detail.account),
      businessProfiles: detail.business_profiles.map((binding) => ({
        bindingKey: binding.binding_key,
        objectKey: binding.object_key,
        profileId: binding.profile_id,
        status: binding.status,
      })),
    };
  },
  async assignableRoles(workforceProfileID: string): Promise<WorkforceAssignableRole[]> {
    const roles = await runtimeRequest<RuntimeRole[]>(`/identity/workforce/${encodeURIComponent(workforceProfileID)}/assignable-roles`);
    return roles.map((role) => ({ id: role.id, key: role.key, label: role.label, description: role.description }));
  },
  async grantRole(identityUserID: string, workforceProfileID: string, roleID: string, reason: string): Promise<void> {
    await assignIdentityUserRole(identityUserID, {
      role_id: roleID,
      workforce_profile_id: workforceProfileID,
      grant_reason: reason,
    });
  },
  onboard(input: WorkforceOnboardingInput): Promise<WorkforceOnboardingResult> {
    return runtimeRequest("/identity/workforce/onboard", {
      method: "POST",
      headers: { "Idempotency-Key": createRuntimeRequestID() },
      body: input,
    });
  },
  transferBatch(items: WorkforceTransferBatchItem[]): Promise<IdentityBatchReceipt<WorkforceTransferBatchItem>> {
    return runtimeRequest("/identity/workforce/transfers/batch", {
      method: "POST",
      headers: { "Idempotency-Key": createRuntimeRequestID() },
      body: { items },
    });
  },
  entitlementBatch(items: EntitlementBatchItem[]): Promise<IdentityBatchReceipt<EntitlementBatchItem>> {
    return runtimeRequest("/identity/entitlements/batch", {
      method: "POST",
      headers: { "Idempotency-Key": createRuntimeRequestID() },
      body: { items },
    });
  },
  lifecycle(input: WorkforceLifecycleInput): Promise<WorkforceLifecycleResult> {
    return runtimeRequest(`/identity/workforce/${encodeURIComponent(input.profile.id)}/lifecycle`, {
      method: "POST",
      headers: { "Idempotency-Key": createRuntimeRequestID() },
      body: input,
    });
  },
  terminate(profileID: string, input: { effective_at: string; reason: string }): Promise<RuntimeWorkforceProfile> {
    return runtimeRequest(`/identity/workforce/${encodeURIComponent(profileID)}/terminate`, {
      method: "POST",
      headers: { "Idempotency-Key": createRuntimeRequestID() },
      body: input,
    });
  },
};

const MODULE_PERMISSION_KEYS: Record<string, { read: string; write?: string }> =
  {
    users: { read: "identity.users.read", write: "identity.users.write" },
    departments: {
      read: "identity.departments.read",
      write: "identity.departments.write",
    },
    roles: { read: "identity.roles.read", write: "identity.roles.write" },
    menus: { read: "identity.menus.read", write: "identity.menus.write" },
    metadata: { read: "metadata.read", write: "metadata.write" },
  };

function permissionKeysToMatrix(keys: string[] | null): PermMatrix {
  const set = new Set(keys ?? []);
  return Object.fromEntries(
    Object.entries(MODULE_PERMISSION_KEYS).map(([module, permission]) => {
      const actions: PermAction[] = [];
      if (set.has(permission.read)) actions.push("view", "export");
      if (permission.write && set.has(permission.write))
        actions.push("create", "edit", "delete");
      return [module, actions];
    }),
  );
}

async function runtimeRoles(): Promise<RuntimeRole[]> {
  return runtimeRequest<RuntimeRole[]>("/identity/roles");
}

async function searchRuntimeRoles(
  query: RoleListQuery,
): Promise<RuntimeRolePage> {
  const params = new URLSearchParams({
    page: String(query.page),
    page_size: String(query.pageSize),
  });
  if (query.search?.trim()) params.set("search", query.search.trim());
  if (query.searchFields?.length)
    params.set("search_fields", query.searchFields.join(","));
  return runtimeRequest<RuntimeRolePage>(
    `/identity/roles/search?${params.toString()}`,
  );
}

async function mapRoles(roles: RuntimeRole[]): Promise<Role[]> {
  const users = await runtimeUsers();
  const assignments = (
    await Promise.all(users.map((user) => userRoleAssignments(user.id)))
  ).flat();
  const counts = new Map<string, number>();
  for (const assignment of assignments)
    counts.set(assignment.role_id, (counts.get(assignment.role_id) ?? 0) + 1);
  return roles.map((role) => ({
    id: role.id,
    name: role.label,
    code: role.key,
    description: role.description,
    members: counts.get(role.id) ?? 0,
    builtIn: role.id === "admin",
    status: role.status,
    perms: permissionKeysToMatrix(role.permission_keys),
  }));
}

export const rolesApi = {
  async list(): Promise<Role[]> {
    return mapRoles(await runtimeRoles());
  },
  async search(query: RoleListQuery): Promise<RolePage> {
    const page = await searchRuntimeRoles(query);
    return {
      items: await mapRoles(page.items),
      page: page.page,
      pageSize: page.page_size,
      total: page.total,
      hasNext: page.has_next,
    };
  },
  async create(input: RoleCreateInput): Promise<Role> {
    const key = input.code.toLowerCase();
    const { businessReason, permissionKeys, dataPermission, ...role } = input;
    await saveSystemResourceDraft({
      resourceType: "role",
      resourceKey: key,
      after: {
        key,
        name: input.name,
        permissions: Array.from(new Set(permissionKeys)).sort(),
        record_scope: dataPermission.scope,
        data_permissions: [dataPermission],
        field_permissions: [],
      },
      operation: "create",
      resourceOwner: "manual",
      capabilityKey: "identity.role",
      riskLevel: "high",
      validationMethods: ["identity.validate", "permission_catalog.validate"],
      reason: businessReason,
      planIDPrefix: "identity-role",
    });
    return { ...role, id: key };
  },
};

export * from "./records-api";
export * from "./governance-api";
export * from "./identity-system-api";
export * from "./authoring-capability-contracts";
