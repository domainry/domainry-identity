package identity

import identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

const (
	IdentityBuiltinAuthorizationOwner = "identity:builtin"

	IdentityActionRolesList               = "identity.roles.list"
	IdentityActionRolesSearch             = "identity.roles.search"
	IdentityActionRolesGet                = "identity.roles.get"
	IdentityActionRolesGovernanceDetail   = "identity.roles.governance_detail"
	IdentityActionRolesVersions           = "identity.roles.versions"
	IdentityActionRolesValidateGovernance = "identity.roles.validate_governance"
	IdentityActionRolesValidate           = "identity.roles.validate"
	IdentityActionRolesImpactPreview      = "identity.roles.impact_preview"
	IdentityActionPermissionsList         = "identity.permissions.list"
	IdentityActionRolePermissionsList     = "identity.role_permissions.list"
	IdentityActionRolePermissionsValidate = "identity.role_permissions.validate"
	IdentityActionRolePermissionsPublish  = "identity.role_permissions.publish"
)

func StandaloneIdentityAuthorizationSliceActions() []identitymodel.IdentityActionDefinition {
	rolePage := &identitymodel.IdentityPageActionBinding{Route: "/admin/org/roles", Label: "角色管理"}
	permissionPage := &identitymodel.IdentityPageActionBinding{Route: "/admin/org/roles", Label: "角色管理 / 功能权限"}
	roles := func(key, method, route, label, operationKey, operationLabel, permission string, owned ...identitymodel.IdentityOwnedPermissionDefinition) identitymodel.IdentityActionDefinition {
		return builtinIdentityAction(key, method, route, label, "identity.role_management", "角色管理", operationKey, operationLabel, permission, rolePage, owned...)
	}
	permissions := func(key, method, route, label, operationKey, operationLabel, permission string, owned ...identitymodel.IdentityOwnedPermissionDefinition) identitymodel.IdentityActionDefinition {
		return builtinIdentityAction(key, method, route, label, "identity.permission_management", "功能权限管理", operationKey, operationLabel, permission, permissionPage, owned...)
	}
	return []identitymodel.IdentityActionDefinition{
		roles(IdentityActionRolesList, "GET", "/identity/roles", "列出角色", "read", "查看", "identity.roles.read", identitymodel.IdentityOwnedPermissionDefinition{
			Key: "identity.roles.read", ResourceKey: "roles", ActionKey: "read", Label: "角色管理 · 查看", Description: "查看角色、版本及变更影响", Category: "Identity 权限管理",
		}),
		roles(IdentityActionRolesSearch, "GET", "/identity/roles/search", "搜索角色", "read", "查看", "identity.roles.read"),
		roles(IdentityActionRolesGet, "GET", "/identity/roles/{roleID}", "查看角色详情", "read", "查看", "identity.roles.read"),
		roles(IdentityActionRolesGovernanceDetail, "GET", "/identity/roles/{roleID}/governance-detail", "查看角色治理详情", "read", "查看", "identity.roles.read"),
		roles(IdentityActionRolesVersions, "GET", "/identity/roles/{roleID}/versions", "查看角色版本", "read", "查看", "identity.roles.read"),
		roles(IdentityActionRolesImpactPreview, "POST", "/identity/roles/{roleID}/impact-preview", "预览角色变更影响", "read", "查看", "identity.roles.read"),
		roles(IdentityActionRolesValidateGovernance, "POST", "/identity/governance/validate", "校验角色治理约束", "configure", "配置", "identity.roles.write", identitymodel.IdentityOwnedPermissionDefinition{
			Key: "identity.roles.write", ResourceKey: "roles", ActionKey: "write", Label: "角色管理 · 配置", Description: "校验并配置角色定义", Category: "Identity 权限管理",
		}),
		roles(IdentityActionRolesValidate, "POST", "/identity/roles/{roleID}/validate", "校验角色定义", "configure", "配置", "identity.roles.write"),
		permissions(IdentityActionPermissionsList, "GET", "/identity/permissions", "列出功能权限", "read", "查看", "identity.permissions.read", identitymodel.IdentityOwnedPermissionDefinition{
			Key: "identity.permissions.read", ResourceKey: "permissions", ActionKey: "read", Label: "功能权限管理 · 查看", Description: "查看当前功能权限及其接口用途", Category: "Identity 权限管理",
		}),
		permissions(IdentityActionRolePermissionsList, "GET", "/identity/roles/{roleID}/permissions", "查看角色功能权限", "read", "查看", "identity.permissions.read"),
		permissions(IdentityActionRolePermissionsValidate, "POST", "/identity/roles/{roleID}/permissions/validate", "校验角色功能权限", "configure", "配置", "identity.permissions.write", identitymodel.IdentityOwnedPermissionDefinition{
			Key: "identity.permissions.write", ResourceKey: "permissions", ActionKey: "write", Label: "功能权限管理 · 配置", Description: "校验角色的功能权限选择", Category: "Identity 权限管理",
		}),
		permissions(IdentityActionRolePermissionsPublish, "PUT", "/identity/roles/{roleID}/permissions", "发布角色功能权限版本", "configure", "配置", "identity.permissions.write"),
	}
}

func builtinIdentityAction(key, method, route, label, capabilityKey, capabilityLabel, operationKey, operationLabel, permission string, page *identitymodel.IdentityPageActionBinding, owned ...identitymodel.IdentityOwnedPermissionDefinition) identitymodel.IdentityActionDefinition {
	return identitymodel.IdentityActionDefinition{
		Key: key, Owner: IdentityBuiltinAuthorizationOwner, SourceKind: "builtin_surface",
		CapabilityKey: capabilityKey, CapabilityLabel: capabilityLabel, OperationKey: operationKey, OperationLabel: operationLabel,
		Label: label, Exposure: "tenant_admin", AuthorizationStrategy: identitymodel.IdentityActionStaticAll,
		HTTP: identitymodel.IdentityHTTPActionBinding{Method: method, RouteTemplate: route, DisplayRouteTemplate: route}, Page: page,
		RequiredPermissions: []string{permission}, OwnedPermissions: owned,
		RiskLevel: "medium", AuditClass: "identity_management", LifecycleStatus: "active",
	}
}

func NewStandaloneIdentityAuthorizationSliceRegistry() (*IdentityActionRegistry, error) {
	return NewIdentityActionRegistry(StandaloneIdentityAuthorizationSliceActions())
}
