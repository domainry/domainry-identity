import {
  createRuntimeRequestID,
  RuntimeApiError,
  runtimeRequest,
  runtimeRequestWithResponse,
} from "@/lib/runtime-api";
import type { RuntimeProductSurface } from "@domainry/surface-contract";
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
    return runtimeRequest<RuntimeRolePermissionAssignment[]>(
      `/identity/roles/${encodeURIComponent(roleID)}/permissions`,
    ).then((items) => items.map((item) => item.permission_key));
  },
  saveRolePermissions(roleID: string, permissionKeys: string[]) {
    return runtimeRequest<RuntimeRolePermissionAssignment[]>(
      `/identity/roles/${encodeURIComponent(roleID)}/permissions`,
      { method: "PUT", body: { permission_keys: permissionKeys } },
    );
  },
  dataScopes(roleID: string) {
    return runtimeRequest<RuntimeDataScopePolicy[] | null>(
      `/identity/roles/${encodeURIComponent(roleID)}/data-scopes`,
    ).then((items) => items ?? []);
  },
  saveDataScopes(roleID: string, dataScopes: RuntimeDataScopePolicy[]) {
    return runtimeRequest<RuntimeDataScopePolicy[]>(
      `/identity/roles/${encodeURIComponent(roleID)}/data-scopes`,
      { method: "PUT", body: { data_scopes: dataScopes } },
    );
  },
  fieldPermissions(roleID: string) {
    return runtimeRequest<RuntimeFieldPermission[] | null>(
      `/identity/roles/${encodeURIComponent(roleID)}/field-permissions`,
    ).then((items) => items ?? []);
  },
  saveFieldPermissions(
    roleID: string,
    fieldPermissions: RuntimeFieldPermission[],
  ) {
    return runtimeRequest<RuntimeFieldPermission[]>(
      `/identity/roles/${encodeURIComponent(roleID)}/field-permissions`,
      { method: "PUT", body: { field_permissions: fieldPermissions } },
    );
  },
};

export interface IdentityGrantSource {
  type: string;
  key: string;
  role_id?: string;
  role_key?: string;
  permission_set_key?: string;
  permission_set_group_key?: string;
  assignment_source?: string;
  binding_key?: string;
  profile_id?: string;
  workforce_profile_id?: string;
  valid_from?: string;
  valid_until?: string;
  expires_at?: string;
}

export interface IdentityEffectiveAccessSnapshot {
  user_id: string;
  known: boolean;
  authorization_revision?: string;
  role_keys: string[];
  permission_set_keys: string[];
  guardrail_keys: string[];
  permissions: Array<{
    key: string;
    object_key?: string;
    action?: string;
    sources: IdentityGrantSource[];
  }>;
  data_access: Array<{
    object_key: string;
    action: string;
    allowed: boolean;
    scope: string;
    scopes: string[];
    sources: IdentityGrantSource[];
  }>;
  field_access: Array<{
    object_key: string;
    field_key: string;
    read: boolean;
    write: boolean;
    export: boolean;
    masked?: boolean;
    sensitive?: boolean;
    sources: IdentityGrantSource[];
  }>;
}

export interface IdentityAccessReason {
  code: string;
  effect: string;
  layer: string;
  subject?: string;
  details?: Record<string, string>;
  sources?: IdentityGrantSource[];
  children?: IdentityAccessReason[];
}

export interface IdentityAccessExplainResult {
  user_id: string;
  object_key?: string;
  action?: string;
  field_key?: string;
  record_id?: string;
  allowed: boolean;
  authorization_revision?: string;
  reason: IdentityAccessReason;
}

export interface IdentityAccessReverseIndex {
  user_roles: Record<string, string[]>;
  role_permissions: Record<string, string[]>;
  permission_roles: Record<string, string[]>;
  object_action_roles: Record<string, string[]>;
}

export interface IdentityRoleGovernanceDetail {
  role: {
    id: string;
    key: string;
    label: string;
    description: string;
    status: string;
  };
  definition: import("./action-definition-api").RuntimeManifestRole;
  permission_sets: Array<{
    key: string;
    name: string;
    description?: string;
    permissions?: string[];
  }>;
  permission_set_groups: Array<{
    key: string;
    name: string;
    description?: string;
    permission_set_keys: string[];
  }>;
  guardrails: Array<{
    key: string;
    name: string;
    description?: string;
    denied_permission_keys?: string[];
  }>;
  permissions: Array<{ role_id: string; permission_key: string }>;
  data_scopes: RuntimeDataScopePolicy[];
  field_permissions: RuntimeFieldPermission[];
  export_rules: Array<{ object_key: string; mode: string; fields: string[] }>;
  menus: Array<{
    id: string;
    key: string;
    label: string;
    route?: string;
    status: string;
  }>;
  members: Array<IdentityGrantSource & {
    user_id: string;
    source?: string;
    status?: string;
    granted_by?: string;
    grant_reason?: string;
    created_at?: string;
  }>;
}

export interface IdentityRoleChangeImpact {
  role_key: string;
  affected_user_count: number;
  profile_types: string[];
  added_permissions: string[];
  removed_permissions: string[];
  affected_objects: string[];
  affected_actions: string[];
  sensitive_fields: string[];
  high_risk_capabilities: string[];
}

export interface IdentityRoleVersionHistory {
  capability_key: string;
  resource_id: string;
  versioning: string;
  items: RuntimeAuditEvent[];
  count: number;
}

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
  roleImpact(roleID: string, role: import("./action-definition-api").RuntimeManifestRole) {
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
