import {
  createRuntimeRequestID,
  RuntimeApiError,
  runtimeRequest,
  runtimeRequestWithResponse,
  type RuntimeResponse,
} from "@/lib/runtime-api";
import type { RuntimeProductSurface } from "@domainry/surface-contract";
import type {
  IdentityAccessExplainResult,
  IdentityAccessReverseIndex,
  IdentityEffectiveAccessSnapshot,
  IdentityRoleChangeImpact,
  IdentityRoleDefinition,
  IdentityRoleGovernanceDetail,
  IdentityRoleVersionHistory,
} from '@domainry/identity-management-contract'
export type {
  IdentityAccessExplainResult,
  IdentityAccessReason,
  IdentityAccessReverseIndex,
  IdentityEffectiveAccessSnapshot,
  IdentityGrantSource,
  IdentityRoleChangeImpact,
  IdentityRoleGovernanceDetail,
  IdentityRoleVersionHistory,
} from '@domainry/identity-management-contract'
import type {
  EffectivePermissions,
  RuntimeAuditEvent,
  RuntimeDataScopePolicy,
  RuntimeFieldPermission,
  RuntimePermissionPoint,
  RuntimeRoleMenuAssignment,
  RuntimeRolePermissionAssignment,
} from "./api";
import type { AuditAction, AuditLog } from "./types";

function auditAction(event: string): AuditAction {
  if (event.includes("delete") || event.includes("removed")) return "delete";
  if (event.includes("create") || event.includes("added") || event.includes("initialized")) return "create";
  if (event.includes("login")) return "login";
  if (event.includes("export")) return "export";
  return "update";
}

export type AuditListQuery = {
  resource?: string;
  recordId?: string;
  actor?: string;
  event?: string;
  requestId?: string;
  createdFrom?: string;
  createdTo?: string;
};

function auditListParams(query: AuditListQuery, limit = 200): URLSearchParams {
  const params = new URLSearchParams({ limit: String(limit) });
  if (query.resource?.trim()) params.set('object_key', query.resource.trim());
  if (query.recordId?.trim()) params.set('record_id', query.recordId.trim());
  if (query.actor?.trim()) params.set('actor_id', query.actor.trim());
  if (query.event?.trim()) params.set('event', query.event.trim());
  if (query.requestId?.trim()) params.set('request_id', query.requestId.trim());
  if (query.createdFrom) params.set('created_from', query.createdFrom);
  if (query.createdTo) params.set('created_to', query.createdTo);
  return params;
}

export const auditApi = {
  async list(query: AuditListQuery = {}): Promise<AuditLog[]> {
    const params = auditListParams(query);
    const response = await runtimeRequest<RuntimeAuditEvent[] | { items: RuntimeAuditEvent[] }>(
      `/tenant-admin/audit-events?${params.toString()}`,
    );
    const events = Array.isArray(response) ? response : response.items ?? [];
    return events.map((event) => {
      const metadata = event.metadata ?? {};
      return {
        id: event.id,
        time: event.created_at,
        operator: event.actor_id,
        action: auditAction(event.event),
        module: event.object_key || event.role_key,
        detail: event.summary,
        ip: typeof metadata.ip === "string" ? metadata.ip : "—",
        result: metadata.result === "failed" ? "failed" : "success",
        event: event.event,
        resource: event.object_key || "",
        recordId: event.record_id,
        roleKey: event.role_key,
        requestId: typeof metadata.request_id === "string" ? metadata.request_id : undefined,
        correlationId: typeof metadata.correlation_id === "string" ? metadata.correlation_id : undefined,
        metadata,
        before: event.before,
        after: event.after,
      };
    });
  },
  export(query: AuditListQuery = {}) {
    return runtimeRequest<{
      items: RuntimeAuditEvent[];
      count: number;
      retention_class: string;
      retention_days: number;
    }>(`/tenant-admin/audit-events/export?${auditListParams(query, 1000).toString()}`);
  },
};

export const permissionsApi = {
  effective: (context?: { objectKey: string; recordID: string }, productSurface?: RuntimeProductSurface) => {
    const query = context
      ? `?object_key=${encodeURIComponent(context.objectKey)}&record_id=${encodeURIComponent(context.recordID)}`
      : "";
    return runtimeRequest<EffectivePermissions>(`/permissions/effective${query}`, { productSurface });
  },
  catalog: () =>
    runtimeRequest<RuntimePermissionPoint[]>("/identity/permissions"),
};

export interface IdentityRolePermissionConfiguration {
  permissionKeys: string[];
  schemaHash: string;
  schemaVersion: string;
}

export interface IdentityRoleDataScopeConfiguration {
  dataScopes: RuntimeDataScopePolicy[];
  schemaHash: string;
  schemaVersion: string;
}

export interface IdentityRoleFieldPermissionConfiguration {
  fieldPermissions: RuntimeFieldPermission[];
  schemaHash: string;
  schemaVersion: string;
}

function roleSchemaRevision(response: RuntimeResponse<unknown>) {
  const schemaHash = response.headers.get("X-Resource-Hash")?.trim() ?? "";
  if (!schemaHash) {
    throw new RuntimeApiError(
      503,
      { code: "backend.authoring.resource_projection_unavailable" },
      "Identity did not publish the authoritative RoleSchema hash",
    );
  }
  return {
    schemaHash,
    schemaVersion: response.headers.get("X-Schema-Version")?.trim() ?? "",
  };
}

function rolePermissionConfiguration(
  response: RuntimeResponse<RuntimeRolePermissionAssignment[]>,
): IdentityRolePermissionConfiguration {
  return {
    permissionKeys: response.data.map((item) => item.permission_key).sort(),
    ...roleSchemaRevision(response),
  };
}

function roleDataScopeConfiguration(
  response: RuntimeResponse<RuntimeDataScopePolicy[] | null>,
): IdentityRoleDataScopeConfiguration {
  return { dataScopes: response.data ?? [], ...roleSchemaRevision(response) };
}

function roleFieldPermissionConfiguration(
  response: RuntimeResponse<RuntimeFieldPermission[] | null>,
): IdentityRoleFieldPermissionConfiguration {
  return { fieldPermissions: response.data ?? [], ...roleSchemaRevision(response) };
}

function fetchRolePermissionConfiguration(roleID: string) {
  return runtimeRequestWithResponse<RuntimeRolePermissionAssignment[]>(
    `/identity/roles/${encodeURIComponent(roleID)}/permissions`,
  ).then(rolePermissionConfiguration);
}

export const identityPoliciesApi = {
  roleMenus(roleID: string) {
    return runtimeRequest<RuntimeRoleMenuAssignment[]>(
      `/identity/roles/${encodeURIComponent(roleID)}/menus`,
    ).then((items) => items.map((item) => item.menu_id));
  },
  saveRoleMenus(roleID: string, menuIDs: string[]) {
    const path = `/identity/roles/${encodeURIComponent(roleID)}/menus`;
    return runtimeRequestWithResponse<RuntimeRoleMenuAssignment[]>(path).then((current) => {
      const expectedResourceHash = current.headers.get("X-Resource-Hash")?.trim();
      if (!expectedResourceHash) {
        throw new RuntimeApiError(
          503,
          { code: "backend.authoring.resource_projection_unavailable" },
          "Runtime did not publish the authoritative role-menu resource hash",
        );
      }
      const requestID = createRuntimeRequestID();
      return runtimeRequest<{ resource: RuntimeRoleMenuAssignment[] }>(path, {
        method: "PUT",
        headers: {
          "Builder-Task-ID": `tenant-admin.identity-role-menu-assignment.${requestID}`,
          "Idempotency-Key": requestID,
          "Expected-Schema-Hash": expectedResourceHash,
        },
        body: { menu_ids: menuIDs },
      }).then((result) => result.resource);
    });
  },
  rolePermissions(roleID: string) {
    return fetchRolePermissionConfiguration(roleID).then((configuration) => configuration.permissionKeys);
  },
  rolePermissionConfiguration(roleID: string) {
    return fetchRolePermissionConfiguration(roleID);
  },
  saveRolePermissions(roleID: string, permissionKeys: string[], businessReason: string, expectedSchemaHash: string) {
    const path = `/identity/roles/${encodeURIComponent(roleID)}/permissions`;
    if (!expectedSchemaHash.trim()) {
      throw new RuntimeApiError(
        503,
        { code: "backend.authoring.resource_projection_unavailable" },
        "Identity did not publish the authoritative RoleSchema hash",
      );
    }
    const requestID = createRuntimeRequestID();
    return runtimeRequestWithResponse<RuntimeRolePermissionAssignment[]>(path, {
      method: "PUT",
      headers: {
        "Idempotency-Key": requestID,
        "Expected-Schema-Hash": expectedSchemaHash,
      },
      body: { permission_keys: permissionKeys, business_reason: businessReason },
    }).then(rolePermissionConfiguration);
  },
  dataScopes(roleID: string) {
    return identityPoliciesApi.dataScopeConfiguration(roleID).then((configuration) => configuration.dataScopes);
  },
  dataScopeConfiguration(roleID: string) {
    return runtimeRequestWithResponse<RuntimeDataScopePolicy[] | null>(
      `/identity/roles/${encodeURIComponent(roleID)}/data-scopes`,
    ).then(roleDataScopeConfiguration);
  },
  saveDataScopes(roleID: string, dataScopes: RuntimeDataScopePolicy[], businessReason: string, expectedSchemaHash: string) {
    if (!expectedSchemaHash.trim()) {
      throw new RuntimeApiError(503, { code: "backend.authoring.resource_projection_unavailable" }, "Identity did not publish the authoritative RoleSchema hash");
    }
    const requestID = createRuntimeRequestID();
    return runtimeRequestWithResponse<RuntimeDataScopePolicy[]>(`/identity/roles/${encodeURIComponent(roleID)}/data-scopes`, {
      method: "PUT",
      headers: { "Idempotency-Key": requestID, "Expected-Schema-Hash": expectedSchemaHash },
      body: { data_scopes: dataScopes, business_reason: businessReason },
    }).then(roleDataScopeConfiguration);
  },
  fieldPermissions(roleID: string) {
    return identityPoliciesApi.fieldPermissionConfiguration(roleID).then((configuration) => configuration.fieldPermissions);
  },
  fieldPermissionConfiguration(roleID: string) {
    return runtimeRequestWithResponse<RuntimeFieldPermission[] | null>(
      `/identity/roles/${encodeURIComponent(roleID)}/field-permissions`,
    ).then(roleFieldPermissionConfiguration);
  },
  saveFieldPermissions(
    roleID: string,
    fieldPermissions: RuntimeFieldPermission[],
    businessReason: string,
    expectedSchemaHash: string,
  ) {
    if (!expectedSchemaHash.trim()) {
      throw new RuntimeApiError(503, { code: "backend.authoring.resource_projection_unavailable" }, "Identity did not publish the authoritative RoleSchema hash");
    }
    const requestID = createRuntimeRequestID();
    return runtimeRequestWithResponse<RuntimeFieldPermission[]>(`/identity/roles/${encodeURIComponent(roleID)}/field-permissions`, {
      method: "PUT",
      headers: { "Idempotency-Key": requestID, "Expected-Schema-Hash": expectedSchemaHash },
      body: { field_permissions: fieldPermissions, business_reason: businessReason },
    }).then(roleFieldPermissionConfiguration);
  },
};

export const identityAccessApi = {
  snapshot(userID: string) {
    return runtimeRequest<IdentityEffectiveAccessSnapshot>(
      `/identity/users/${encodeURIComponent(userID)}/effective-access`,
    );
  },
  explain(input: { user_id: string; object_key: string; action: string; field_key?: string; record_id?: string }) {
    return runtimeRequest<IdentityAccessExplainResult>("/identity/access/explain", {
      method: "POST",
      body: input,
    });
  },
  reverseIndex() {
    return runtimeRequest<IdentityAccessReverseIndex>("/identity/access/reverse-index");
  },
  roleGovernanceDetail(roleID: string) {
    return runtimeRequest<IdentityRoleGovernanceDetail>(
      `/identity/roles/${encodeURIComponent(roleID)}/governance-detail`,
    );
  },
  roleImpact(roleID: string, role: IdentityRoleDefinition) {
    return runtimeRequest<IdentityRoleChangeImpact>(
      `/identity/roles/${encodeURIComponent(roleID)}/impact-preview`,
      { method: "POST", body: { role } },
    );
  },
  roleVersions(roleID: string) {
    return runtimeRequest<IdentityRoleVersionHistory>(
      `/identity/roles/${encodeURIComponent(roleID)}/versions`,
    );
  },
};
