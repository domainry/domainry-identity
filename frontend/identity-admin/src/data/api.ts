import { createRuntimeRequestID, RuntimeApiError, runtimeRequest, runtimeRequestWithResponse } from "@/lib/runtime-api";
import type {
  OrganizationUnit,
  IdentityAccount,
  OrgUser,
  Role,
} from "./types";
import {
  identityListParams,
  type IdentityAccountSecurity,
  type IdentityDataScope as RuntimeDataScope,
  type IdentityOrganizationUnit as RuntimeOrganizationUnit,
  type IdentityListQuery,
  type IdentityPage,
  type IdentityRole as RuntimeRole,
  type IdentityRoleAssignment as RuntimeRoleAssignment,
  type IdentityRolePage as RuntimeRolePage,
  type IdentityUser as RuntimeUser,
  type IdentityUserDeletionImpact,
  type IdentityUserDirectoryEntry as RuntimeUserDirectoryEntry,
  type IdentityUserDisableImpact,
} from "@domainry/identity-management-contract";
export type {
  IdentityAccountSecurity,
	IdentityDataScope as RuntimeDataScope,
  IdentityFieldPermission as RuntimeFieldPermission,
  IdentityListQuery,
  IdentityMenu as RuntimeMenu,
  IdentityPage,
  IdentityPermissionPoint as RuntimePermissionPoint,
  IdentityPolicyExpression as RuntimeIdentityPolicyExpression,
  IdentityRole as RuntimeRole,
  IdentityRoleAssignment as RuntimeRoleAssignment,
  IdentityRoleMenuAssignment as RuntimeRoleMenuAssignment,
  IdentityRolePermissionAssignment as RuntimeRolePermissionAssignment,
  IdentityUserDeletionImpact,
  IdentityUserDisableImpact,
  EffectiveActionPermission,
  EffectivePermissionDecision,
  EffectivePermissions,
} from "@domainry/identity-management-contract";
import identityUserAuthoringContract from "@domainry/identity-management-contract/identity-user-authoring-contract.json";

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
    organizationUnitId: user.org_id ?? "",
    supportOrganizationUnitId: user.support_org_id ?? "",
    managerUserId: user.manager_user_id ?? "",
    reportingPath: user.reporting_path ?? `/${user.id}`,
    workerNo: user.worker_no ?? "",
    workerType: user.worker_type ?? "",
    workStatus: user.work_status ?? "",
    startDate: user.start_date ?? "",
    endDate: user.end_date ?? "",
    email: user.email,
    phone: user.phone ?? "",
    status: user.status,
    version: user.version,
    resourceHash,
    createdAt: user.created_at,
    updatedAt: user.updated_at,
  };
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
  permissions: Array<{
    permission_key: string;
    data_scope: RuntimeDataScope;
    audit_denial?: boolean;
  }>;
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

function makeID(prefix: string, source: string): string {
  const normalized = source
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `${prefix}_${normalized || crypto.randomUUID().slice(0, 8)}`;
}

function mapOrganizationUnit(value: RuntimeOrganizationUnit, memberCount = 0): OrganizationUnit {
  return {
    id: value.id,
    code: value.code,
    parentId: value.parent_id ?? null,
    name: value.name,
    nodeType: value.node_type,
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

async function runtimeOrganizationUnits(): Promise<RuntimeOrganizationUnit[]> {
  return runtimeRequest<RuntimeOrganizationUnit[]>("/identity/organization-units");
}

async function runtimeUsers(): Promise<RuntimeUser[]> {
  return runtimeRequest<RuntimeUser[]>("/identity/users");
}

export const organizationUnitsApi = {
  async list(): Promise<OrganizationUnit[]> {
    return (await runtimeOrganizationUnits()).map((unit) => mapOrganizationUnit(unit));
  },
  async create(input: Omit<OrganizationUnit, "id">): Promise<OrganizationUnit> {
    const requestID = createRuntimeRequestID();
    const result = await runtimeRequest<
      RuntimeOrganizationUnit | RuntimeAuthoringResult<RuntimeOrganizationUnit>
    >(
      "/identity/organization-units",
      {
        method: "POST",
        headers: {
          "Builder-Task-ID": `tenant-admin.identity-organization-unit.${requestID}`,
          "Idempotency-Key": requestID,
          "Expected-Schema-Hash": "empty",
        },
        body: {
          id: makeID("org", String(input.code || input.name)),
          code: input.code,
          name: input.name,
          node_type: input.nodeType,
          parent_id: input.parentId || undefined,
          sort_order: input.sort,
          status: input.status,
        },
      },
    );
    return mapOrganizationUnit(runtimeAuthoringResource(result));
  },
  async update(
    id: string,
    patch: Partial<Omit<OrganizationUnit, "id">>,
  ): Promise<OrganizationUnit> {
    const path = `/identity/organization-units/${encodeURIComponent(id)}`;
    const current = await runtimeRequestWithResponse<RuntimeOrganizationUnit>(path);
    const existing = current.data;
    const expectedResourceHash = current.headers.get("X-Resource-Hash")?.trim();
    if (!expectedResourceHash) {
      throw new RuntimeApiError(
        503,
        { code: "backend.authoring.resource_projection_unavailable" },
        "Runtime did not publish the authoritative organization-unit resource hash",
      );
    }
    const requestID = createRuntimeRequestID();
    const result = await runtimeRequest<
      RuntimeOrganizationUnit | RuntimeAuthoringResult<RuntimeOrganizationUnit>
    >(
      path,
      {
        method: "PATCH",
        headers: {
          "Builder-Task-ID": `tenant-admin.identity-organization-unit.${requestID}`,
          "Idempotency-Key": requestID,
          "Expected-Schema-Hash": expectedResourceHash,
        },
        body: {
          ...existing,
          code: patch.code ?? existing.code,
          name: patch.name ?? existing.name,
          node_type: patch.nodeType ?? existing.node_type,
          parent_id:
            patch.parentId === undefined
              ? existing.parent_id
              : patch.parentId || undefined,
          sort_order: patch.sort ?? existing.sort_order,
          status: patch.status ?? existing.status,
        },
      },
    );
    return mapOrganizationUnit(runtimeAuthoringResource(result), patch.memberCount);
  },
  async remove(): Promise<void> {
    throw new RuntimeApiError(
      405,
      {},
      "The runtime does not expose destructive organization-unit deletion",
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
    workerNo: user.worker_no ?? "",
    phone: user.phone ?? "",
    gender: "",
    startDate: user.start_date ?? "",
    endDate: user.end_date ?? "",
    jobTitle: "",
    jobLevel: "",
    managerId: user.manager_user_id ?? "",
    managerPath: (user.reporting_path || `/${user.id}`).split("/").filter(Boolean),
    workerType: user.worker_type ?? "",
    workStatus: user.work_status ?? "",
    organizationUnitId: user.org_id ?? "",
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
      "Create users through the identity user API",
    );
  },
  async update(
    _id: string,
    _patch: Partial<Omit<OrgUser, "id">>,
  ): Promise<OrgUser> {
    throw new RuntimeApiError(
      410,
      {},
      "Update users through the identity user API",
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
  async provision(input: Omit<IdentityAccount, "id" | "reportingPath" | "version" | "createdAt" | "updatedAt">): Promise<{
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
        org_id: input.organizationUnitId,
        support_org_id: input.supportOrganizationUnitId,
        manager_user_id: input.managerUserId,
        worker_no: input.workerNo,
        worker_type: input.workerType || undefined,
        work_status: input.workStatus || undefined,
        start_date: input.startDate,
        end_date: input.endDate,
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
  async create(input: Omit<IdentityAccount, "id" | "reportingPath" | "version" | "createdAt" | "updatedAt">): Promise<IdentityAccount> {
    return (await this.provision(input)).account;
  },
  async update(id: string, patch: Partial<Omit<IdentityAccount, "id" | "reportingPath" | "version" | "createdAt" | "updatedAt">> & { expectedResourceHash?: string }): Promise<IdentityAccount> {
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
        org_id: patch.organizationUnitId ?? current.org_id ?? "",
        support_org_id: patch.supportOrganizationUnitId ?? current.support_org_id ?? "",
        manager_user_id: patch.managerUserId ?? current.manager_user_id ?? "",
        worker_no: patch.workerNo ?? current.worker_no ?? "",
        worker_type: patch.workerType ?? current.worker_type ?? "",
        work_status: patch.workStatus ?? current.work_status ?? "",
        start_date: patch.startDate ?? current.start_date ?? "",
        end_date: patch.endDate ?? current.end_date ?? "",
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
    status: role.status,
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
    const { businessReason, permissions, ...role } = input;
    const requestID = createRuntimeRequestID();
    await runtimeRequest(`/identity/roles`, {
      method: "POST",
      headers: { "Idempotency-Key": requestID },
      body: {
        role: {
        key,
        name: input.name,
        description: input.description,
        permissions: [...permissions].sort((left, right) => left.permission_key.localeCompare(right.permission_key)),
        field_permissions: [],
        audience: "any",
        assignment_mode: "manual",
        risk_level: "normal",
        },
        business_reason: businessReason,
      },
    });
    return { ...role, id: key };
  },
};

export * from "./records-api";
export * from "./governance-api";
export * from "./identity-system-api";
export * from "./authoring-capability-contracts";
