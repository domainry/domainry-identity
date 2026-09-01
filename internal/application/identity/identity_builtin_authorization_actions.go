package identity

import (
	"strings"

	actioncontract "github.com/domainry/domainry-foundation/action"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
)

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
	IdentityActionPermissionsSetEnabled   = "identity.permissions.set_enabled"
	IdentityActionRolePermissionsList     = "identity.role_permissions.list"
	IdentityActionRolePermissionsValidate = "identity.role_permissions.validate"
	IdentityActionRolePermissionsPublish  = "identity.role_permissions.publish"
)

type identityBuiltinActionSpec struct {
	group, groupLabel         string
	operation, operationLabel string
	method, route, label      string
	page                      *identitymodel.IdentityPageActionBinding
	authorization             actioncontract.Authorization
	exposures                 []actioncontract.Exposure
}

func IdentityBuiltinAuthorizationActions() []identitymodel.IdentityActionDefinition {
	accounts := page("/admin/security/accounts", "账号管理")
	accountDetail := page("/admin/security/accounts/$userId", "账号详情")
	workforce := page("/admin/org/workforce", "员工管理")
	workforceDetail := page("/admin/org/workforce/$profileID", "员工详情")
	departments := page("/admin/org/departments", "部门管理")
	roles := page("/admin/org/roles", "角色管理")
	menus := page("/admin/org/menus", "菜单管理")
	dataScopes := page("/admin/org/data-scopes", "数据范围")
	fieldPermissions := page("/admin/org/field-permissions", "字段权限")
	metadata := page("/admin/system/metadata", "元数据")

	specs := []identityBuiltinActionSpec{
		anonymousAction("auth.discovery", "认证发现", "jwks", "读取 JWKS", "GET", "/.well-known/jwks.json", "读取 JSON Web Key Set"),
		anonymousAction("auth.discovery", "认证发现", "openid_configuration", "读取 OpenID 配置", "GET", "/.well-known/openid-configuration", "读取 OpenID Connect 配置"),
		anonymousAction("auth", "认证", "login", "登录", "POST", "/auth/login", "密码登录"),
		anonymousAction("auth", "认证", "guest", "访客登录", "POST", "/auth/guest", "访客登录"),
		anonymousAction("auth", "认证", "refresh", "刷新会话", "POST", "/auth/refresh", "刷新访问会话"),
		anonymousAction("auth", "认证", "logout", "退出", "POST", "/auth/logout", "撤销刷新会话并退出"),
		authPrincipalAction("auth.session", "浏览器会话", "get", "读取会话", "GET", "/auth/session", "读取当前浏览器会话"),
		anonymousAction("auth.code", "认证码", "exchange", "交换认证码", "POST", "/auth/code/exchange", "交换一次性认证码"),
		authPrincipalAction("auth.sessions", "会话安全", "revoke_others", "撤销其它会话", "POST", "/auth/sessions/revoke-others", "撤销当前用户的其它会话"),
		authPrincipalAction("auth", "认证安全", "change_password", "修改密码", "POST", "/auth/change-password", "修改当前用户密码"),
		authPermissionAction("auth", "认证安全", "reset_password", "重置密码", "POST", "/auth/reset-password", "重置用户密码"),
		anonymousAction("auth.providers", "认证提供方", "list", "列出", "GET", "/auth/providers", "列出可用认证提供方"),
		authAnonymousAction("auth.providers", "认证提供方", "setup_check", "配置检查", "GET", "/auth/providers/{provider}/setup-check", "检查认证提供方配置"),
		authPermissionAction("auth.providers", "认证提供方", "setup", "配置", "PUT", "/auth/providers/{provider}/setup", "配置认证提供方"),
		anonymousAction("auth.providers", "认证提供方", "start_get", "发起登录", "GET", "/auth/providers/{provider}/start", "发起认证提供方登录"),
		anonymousAction("auth.providers", "认证提供方", "start_post", "发起登录", "POST", "/auth/providers/{provider}/start", "发起认证提供方登录"),
		anonymousAction("auth.providers", "认证提供方", "callback_get", "处理回调", "GET", "/auth/providers/{provider}/callback", "处理认证提供方回调"),
		anonymousAction("auth.providers", "认证提供方", "callback_post", "处理回调", "POST", "/auth/providers/{provider}/callback", "处理认证提供方回调"),
		anonymousAction("auth.providers", "认证提供方", "verify", "验证", "POST", "/auth/providers/{provider}/verify", "验证认证提供方挑战"),
		anonymousAction("auth.providers", "认证提供方", "exchange", "交换凭证", "POST", "/auth/providers/{provider}/exchange", "交换认证提供方凭证"),
		authPrincipalAction("auth.external_accounts", "外部账号", "list", "列出", "GET", "/auth/external-accounts", "列出当前用户外部账号"),
		authPrincipalAction("auth.external_accounts", "外部账号", "bind", "绑定", "POST", "/auth/external-accounts/{provider}/bind", "绑定当前用户外部账号"),
		authPrincipalAction("auth.external_accounts", "外部账号", "unbind", "解绑", "DELETE", "/auth/external-accounts/{provider}/{accountID}", "解绑当前用户外部账号"),
		authPrincipalAction("auth.me", "当前用户", "get", "查看", "GET", "/auth/me", "查看当前用户"),
		authPrincipalAction("auth.me", "当前用户", "update", "更新", "PATCH", "/auth/me", "更新当前用户设置"),
		authPrincipalAction("auth.role_options", "角色选项", "list", "列出", "GET", "/auth/role-options", "列出当前用户角色选项"),
		authPrincipalAction("auth.role_requests", "角色申请", "list", "列出", "GET", "/auth/role-requests", "列出当前用户角色申请"),
		authPrincipalAction("auth.role_requests", "角色申请", "create", "创建", "POST", "/auth/role-requests", "创建当前用户角色申请"),
		principalAction("identity.effective_menus", "有效菜单", "get", "获取", "GET", "/identity/effective-menus", "获取当前用户有效菜单"),

		permissionAction("identity.departments", "部门管理", "list", "列出", "GET", "/identity/departments", "列出部门", departments),
		permissionAction("identity.departments", "部门管理", "get", "查看", "GET", "/identity/departments/{departmentID}", "查看部门", nil),
		permissionAction("identity.departments", "部门管理", "versions", "查看版本", "GET", "/identity/departments/{departmentID}/versions", "查看部门版本", nil),
		permissionAction("identity.departments", "部门管理", "create", "创建", "POST", "/identity/departments", "创建部门", nil),
		permissionAction("identity.departments", "部门管理", "validate", "校验", "POST", "/identity/departments/{departmentID}/validate", "校验部门定义", nil),
		permissionAction("identity.departments", "部门管理", "update", "更新", "PATCH", "/identity/departments/{departmentID}", "更新部门", nil),

		permissionAction("identity.users", "账号管理", "list", "列出", "GET", "/identity/users", "列出用户", accounts),
		permissionAction("identity.users", "账号管理", "search", "搜索", "GET", "/identity/users/search", "搜索用户", nil),
		permissionAction("identity.users", "账号管理", "directory_search", "目录搜索", "GET", "/identity/users/directory/search", "搜索用户目录", nil),
		selfPageAction("identity.users", "账号管理", "get", "查看", "GET", "/identity/users/{userID}", "查看用户", "identity.user.self", accountDetail),
		permissionAction("identity.users", "账号管理", "deletion_impact", "删除影响", "GET", "/identity/users/{userID}/deletion-impact", "查看用户删除影响", nil),
		permissionAction("identity.users", "账号管理", "disable_impact", "停用影响", "GET", "/identity/users/{userID}/disable-impact", "查看用户停用影响", nil),
		permissionAction("identity.users", "账号管理", "versions", "查看版本", "GET", "/identity/users/{userID}/versions", "查看用户版本", nil),
		permissionAction("identity.users", "账号管理", "create", "创建", "POST", "/identity/users", "创建用户", nil),
		permissionAction("identity.users", "账号管理", "validate", "校验", "POST", "/identity/users/{userID}/validate", "校验用户定义", nil),
		permissionAction("identity.users", "账号管理", "update", "更新", "PATCH", "/identity/users/{userID}", "更新用户", nil),
		permissionAction("identity.users", "账号管理", "delete", "删除", "DELETE", "/identity/users/{userID}", "删除用户", nil),
		permissionAction("identity.users", "账号管理", "disable", "停用", "POST", "/identity/users/{userID}/disable", "停用用户", nil),
		permissionAction("identity.users", "账号管理", "enable", "启用", "POST", "/identity/users/{userID}/enable", "启用用户", nil),
		selfAction("identity.users", "账号管理", "security_get", "查看安全信息", "GET", "/identity/users/{userID}/security", "查看用户安全信息", "identity.user.self"),
		selfAction("identity.users", "账号管理", "effective_access", "查看有效权限", "GET", "/identity/users/{userID}/effective-access", "查看用户有效权限", "identity.user.self"),
		permissionAction("identity.users", "账号管理", "unlock", "解锁", "POST", "/identity/users/{userID}/unlock", "解锁用户", nil),
		permissionAction("identity.users", "账号管理", "force_logout", "强制退出", "POST", "/identity/users/{userID}/force-logout", "强制用户退出", nil),
		permissionAction("identity.users", "账号管理", "mfa_revoke", "撤销 MFA", "DELETE", "/identity/users/{userID}/mfa/{factorID}", "撤销用户 MFA 因子", nil),
		selfAction("identity.user_role_assignments", "用户角色", "list", "列出", "GET", "/identity/users/{userID}/role-assignments", "列出用户角色分配", "identity.user.self"),
		selfAction("identity.user_role_assignments", "用户角色", "search", "搜索", "GET", "/identity/users/{userID}/role-assignments/search", "搜索用户角色分配", "identity.user.self"),
		permissionAction("identity.user_role_assignments", "用户角色", "assignable_roles", "可分配角色", "GET", "/identity/users/{userID}/assignable-roles", "列出用户可分配角色", nil),
		permissionAction("identity.user_role_assignments", "用户角色", "account_and_roles_update", "更新账号与角色", "PUT", "/identity/users/{userID}/account-and-roles", "更新用户账号与角色", nil),
		permissionAction("identity.user_role_assignments", "用户角色", "versions", "查看版本", "GET", "/identity/users/{userID}/role-assignments/versions", "查看用户角色分配版本", nil),
		permissionAction("identity.user_role_assignments", "用户角色", "assign", "分配", "POST", "/identity/users/{userID}/role-assignments", "分配用户角色", nil),
		permissionAction("identity.user_role_assignments", "用户角色", "validate", "校验", "POST", "/identity/users/{userID}/role-assignments/validate", "校验用户角色分配", nil),
		permissionAction("identity.user_role_assignments", "用户角色", "revoke", "撤销", "DELETE", "/identity/users/{userID}/role-assignments/{roleID}", "撤销用户角色", nil),

		permissionAction("identity.workforce", "员工管理", "list", "列出", "GET", "/identity/workforce", "列出员工档案", workforce),
		permissionAction("identity.workforce", "员工管理", "search", "搜索", "GET", "/identity/workforce/search", "搜索员工档案", nil),
		permissionAction("identity.workforce", "员工管理", "onboard", "入职", "POST", "/identity/workforce/onboard", "办理员工入职", nil),
		permissionAction("identity.workforce", "员工管理", "transfer_batch", "批量调动", "POST", "/identity/workforce/transfers/batch", "批量调动员工", nil),
		permissionAction("identity.workforce", "员工管理", "get", "查看", "GET", "/identity/workforce/{profileID}", "查看员工档案", nil),
		permissionAction("identity.workforce", "员工管理", "detail", "查看详情", "GET", "/identity/workforce/{profileID}/detail", "查看员工详情", workforceDetail),
		permissionAction("identity.workforce", "员工管理", "assignable_roles", "可分配角色", "GET", "/identity/workforce/{profileID}/assignable-roles", "列出员工可分配角色", nil),
		permissionAction("identity.workforce", "员工管理", "create", "创建", "POST", "/identity/workforce", "创建员工档案", nil),
		permissionAction("identity.workforce", "员工管理", "update", "更新", "PATCH", "/identity/workforce/{profileID}", "更新员工档案", nil),
		permissionAction("identity.workforce", "员工管理", "validate", "校验", "POST", "/identity/workforce/{profileID}/validate", "校验员工档案", nil),
		permissionAction("identity.workforce", "员工管理", "terminate", "离职", "POST", "/identity/workforce/{profileID}/terminate", "办理员工离职", nil),
		permissionAction("identity.workforce", "员工管理", "rehire", "返聘", "POST", "/identity/workforce/{profileID}/rehire", "办理员工返聘", nil),
		permissionAction("identity.workforce", "员工管理", "lifecycle", "生命周期变更", "POST", "/identity/workforce/{profileID}/lifecycle", "变更员工生命周期", nil),
		permissionAction("identity.workforce_assignments", "员工任职", "list", "列出", "GET", "/identity/workforce/{profileID}/assignments", "列出员工任职", nil),
		permissionAction("identity.workforce_assignments", "员工任职", "upsert", "保存", "POST", "/identity/workforce/{profileID}/assignments", "保存员工任职", nil),
		permissionAction("identity.workforce_assignments", "员工任职", "validate", "校验", "POST", "/identity/workforce/{profileID}/assignments/validate", "校验员工任职", nil),

		selfAction("identity.profile_bindings", "业务身份绑定", "get", "查看", "GET", "/identity/profile-bindings/{objectKey}/{profileID}", "查看业务身份绑定", "identity.profile_binding.self"),
		selfAction("identity.profile_bindings", "业务身份绑定", "command", "执行命令", "POST", "/identity/profile-bindings/{objectKey}/{profileID}/commands", "执行业务身份绑定命令", "identity.profile_binding.self"),
		principalAction("identity.principal_context", "主体上下文", "get", "获取", "GET", "/identity/principal-context", "获取当前主体上下文"),
		selfAction("identity.access", "有效权限", "explain", "解释", "POST", "/identity/access/explain", "解释用户有效权限", "identity.effective_access.self"),
		permissionAction("identity.access", "权限治理", "reverse_index", "反向索引", "GET", "/identity/access/reverse-index", "查看权限反向索引", nil),
		permissionAction("identity.access", "权限治理", "reports", "治理报告", "GET", "/identity/access/reports", "查看权限治理报告", nil),
		permissionAction("identity.access_reviews", "访问评审", "create", "创建", "POST", "/identity/access-reviews", "创建访问评审", nil),
		permissionAction("identity.access_reviews", "访问评审", "list", "列出", "GET", "/identity/access-reviews", "列出访问评审", nil),
		permissionAction("identity.access_review_items", "访问评审项", "decide", "决策", "POST", "/identity/access-review-items/{itemID}/decision", "决策访问评审项", nil),
		permissionAction("identity.entitlements", "授权批处理", "batch", "批量执行", "POST", "/identity/entitlements/batch", "批量处理授权", nil),
		permissionAction("identity.role_requests", "角色申请", "list", "列出", "GET", "/identity/role-requests", "列出角色申请", nil),
		permissionAction("identity.role_requests", "角色申请", "approve", "批准", "POST", "/identity/role-requests/{requestID}/approve", "批准角色申请", nil),
		permissionAction("identity.role_requests", "角色申请", "reject", "拒绝", "POST", "/identity/role-requests/{requestID}/reject", "拒绝角色申请", nil),

		permissionAction("identity.roles", "角色管理", "list", "列出", "GET", "/identity/roles", "列出角色", roles),
		permissionAction("identity.roles", "角色管理", "search", "搜索", "GET", "/identity/roles/search", "搜索角色", nil),
		permissionAction("identity.roles", "角色管理", "get", "查看", "GET", "/identity/roles/{roleID}", "查看角色", nil),
		permissionAction("identity.roles", "角色管理", "governance_detail", "治理详情", "GET", "/identity/roles/{roleID}/governance-detail", "查看角色治理详情", nil),
		permissionAction("identity.roles", "角色管理", "versions", "查看版本", "GET", "/identity/roles/{roleID}/versions", "查看角色版本", nil),
		permissionAction("identity.roles", "角色管理", "impact_preview", "影响预览", "POST", "/identity/roles/{roleID}/impact-preview", "预览角色变更影响", nil),
		permissionAction("identity.roles", "角色管理", "validate_governance", "治理校验", "POST", "/identity/governance/validate", "校验角色治理约束", nil),
		permissionAction("identity.roles", "角色管理", "validate", "校验", "POST", "/identity/roles/{roleID}/validate", "校验角色定义", nil),

		permissionAction("identity.menus", "菜单管理", "list", "列出", "GET", "/identity/menus", "列出菜单", menus),
		permissionAction("identity.menus", "菜单管理", "get", "查看", "GET", "/identity/menus/{menuID}", "查看菜单", nil),
		permissionAction("identity.menus", "菜单管理", "versions", "查看版本", "GET", "/identity/menus/{menuID}/versions", "查看菜单版本", nil),
		permissionAction("identity.menus", "菜单管理", "validate", "校验", "POST", "/identity/menus/{menuID}/validate", "校验菜单", nil),
		permissionAction("identity.menus", "菜单管理", "upsert", "保存", "PUT", "/identity/menus/{menuID}", "保存菜单", nil),
		permissionAction("identity.menus", "菜单管理", "delete", "删除", "DELETE", "/identity/menus/{menuID}", "删除菜单", nil),
		permissionAction("identity.role_menus", "角色菜单", "list", "列出", "GET", "/identity/roles/{roleID}/menus", "列出角色菜单", nil),
		permissionAction("identity.role_menus", "角色菜单", "versions", "查看版本", "GET", "/identity/roles/{roleID}/menus/versions", "查看角色菜单版本", nil),
		permissionAction("identity.role_menus", "角色菜单", "validate", "校验", "POST", "/identity/roles/{roleID}/menus/validate", "校验角色菜单", nil),
		permissionAction("identity.role_menus", "角色菜单", "publish", "发布", "PUT", "/identity/roles/{roleID}/menus", "发布角色菜单", nil),

		permissionAction("identity.permissions", "功能权限管理", "list", "列出", "GET", "/identity/permissions", "列出功能权限", nil),
		permissionAction("identity.permissions", "功能权限管理", "set_enabled", "设置启停状态", "PUT", "/identity/permissions/{permissionKey}/enabled", "启用或停用功能权限", nil),
		permissionAction("identity.role_permissions", "角色功能权限", "list", "列出", "GET", "/identity/roles/{roleID}/permissions", "查看角色功能权限", nil),
		permissionAction("identity.role_permissions", "角色功能权限", "validate", "校验", "POST", "/identity/roles/{roleID}/permissions/validate", "校验角色功能权限", nil),
		permissionAction("identity.role_permissions", "角色功能权限", "publish", "发布", "PUT", "/identity/roles/{roleID}/permissions", "发布角色功能权限", nil),
		permissionAction("identity.role_data_scopes", "角色数据范围", "list", "列出", "GET", "/identity/roles/{roleID}/data-scopes", "列出角色数据范围", dataScopes),
		permissionAction("identity.role_data_scopes", "角色数据范围", "validate", "校验", "POST", "/identity/roles/{roleID}/data-scopes/validate", "校验角色数据范围", nil),
		permissionAction("identity.role_field_permissions", "角色字段权限", "list", "列出", "GET", "/identity/roles/{roleID}/field-permissions", "列出角色字段权限", fieldPermissions),
		permissionAction("identity.role_field_permissions", "角色字段权限", "validate", "校验", "POST", "/identity/roles/{roleID}/field-permissions/validate", "校验角色字段权限", nil),

		principalAction("identity.permissions", "功能权限", "effective", "读取当前生效权限", "GET", "/permissions/effective", "读取当前主体的生效权限"),
		principalAction("identity.runtime_schema", "Identity Runtime Schema", "get", "读取", "GET", "/tenant-admin/runtime-schema", "读取按当前主体过滤的 Identity Runtime Schema"),
		permissionAction("identity.platform_capabilities", "平台能力", "get", "读取", "GET", "/tenant-admin/platform-capabilities", "读取 Identity 平台能力目录", nil),
	}

	out := make([]identitymodel.IdentityActionDefinition, 0, len(specs)+8)
	out = append(out, identityMetadataNonHTTPActions(metadata)...)
	for _, spec := range specs {
		out = append(out, buildIdentityBuiltinAction(spec))
	}
	return out
}

func identityMetadataNonHTTPActions(metadataPage *identitymodel.IdentityPageActionBinding) []identitymodel.IdentityActionDefinition {
	actions := []identitymodel.IdentityActionDefinition{
		nonHTTPPermissionAction(metadatacontract.MetadataActionManifestGet, "identity.metadata.manifest", "元数据清单", "get", "读取", "读取当前元数据清单", actioncontract.EffectRead, actioncontract.RiskLow),
		nonHTTPPermissionAction(metadatacontract.MetadataActionReload, "identity.metadata", "元数据", "reload", "重新加载", "重新加载并激活元数据", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(metadatacontract.MetadataActionMigrationPlanGet, "identity.metadata.migration_plan", "元数据迁移计划", "get", "读取", "读取元数据迁移计划", actioncontract.EffectRead, actioncontract.RiskLow),
		nonHTTPPermissionAction(metadatacontract.MetadataActionObjectRecordCountGet, "identity.metadata.object_record_count", "对象记录计数", "get", "读取", "读取元数据对象的记录计数", actioncontract.EffectRead, actioncontract.RiskLow),
		nonHTTPPermissionAction(metadatacontract.MetadataActionDefinitionGet, "identity.metadata.definition", "元数据定义", "get", "读取", "读取元数据定义", actioncontract.EffectRead, actioncontract.RiskLow),
		nonHTTPPermissionAction(metadatacontract.MetadataActionDefinitionVersions, "identity.metadata.definition", "元数据定义", "versions", "查看版本", "读取元数据定义版本", actioncontract.EffectRead, actioncontract.RiskLow),
		nonHTTPPermissionAction(metadatacontract.MetadataActionDefinitionValidate, "identity.metadata.definition", "元数据定义", "validate", "校验", "校验元数据定义候选", actioncontract.EffectRead, actioncontract.RiskLow),
		nonHTTPPermissionAction(metadatacontract.MetadataActionDefinitionUpsert, "identity.metadata.definition", "元数据定义", "upsert", "保存", "保存元数据定义", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(metadatacontract.MetadataActionDefinitionDisable, "identity.metadata.definition", "元数据定义", "disable", "停用", "停用元数据定义", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(metadatacontract.MetadataActionDefinitionRollback, "identity.metadata.definition", "元数据定义", "rollback", "回滚", "回滚元数据定义", actioncontract.EffectWrite, actioncontract.RiskHigh),
	}
	if metadataPage != nil {
		actions[0].Pages = []identitymodel.IdentityPageActionBinding{*metadataPage}
	}
	return actions
}

func nonHTTPPermissionAction(key, capabilityKey, capabilityLabel, operationKey, operationLabel, label string, effect actioncontract.EffectClass, risk actioncontract.RiskLevel) identitymodel.IdentityActionDefinition {
	return identitymodel.IdentityActionDefinition{
		Key: key, Owner: IdentityBuiltinAuthorizationOwner, SourceKind: "builtin_capability",
		CapabilityKey: capabilityKey, CapabilityLabel: capabilityLabel, OperationKey: operationKey, OperationLabel: operationLabel,
		Label: label, Exposures: []actioncontract.Exposure{actioncontract.ExposureTenantAdmin},
		Authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationExactRolePermission},
		NonHTTP:       []identitymodel.IdentityNonHTTPActionBinding{{Kind: "application_use_case", InvocationKey: key}},
		Permission: &identitymodel.IdentityPermissionDefinitionContract{
			Key: key, Owner: IdentityBuiltinAuthorizationOwner, ResourceKey: capabilityKey, ActionKey: operationKey,
			Label: capabilityLabel + " · " + operationLabel, Description: label,
			Category: "Identity 权限管理", LifecycleStatus: actioncontract.LifecycleActive,
		},
		EffectClass: effect, RiskLevel: risk, IdempotencyDecision: "application_service_contract",
		AuditClass: "identity_management", LifecycleStatus: actioncontract.LifecycleActive,
	}
}

// StandaloneIdentityAuthorizationSliceActions is kept as the assembly entry
// point while now returning the complete Identity-owned management surface.
func StandaloneIdentityAuthorizationSliceActions() []identitymodel.IdentityActionDefinition {
	return IdentityBuiltinAuthorizationActions()
}

func permissionAction(group, groupLabel, operation, operationLabel, method, route, label string, pageBinding *identitymodel.IdentityPageActionBinding) identityBuiltinActionSpec {
	return identityBuiltinActionSpec{
		group: group, groupLabel: groupLabel, operation: operation, operationLabel: operationLabel, method: method, route: route, label: label, page: pageBinding,
		authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationExactRolePermission},
	}
}

func authPermissionAction(group, groupLabel, operation, operationLabel, method, route, label string) identityBuiltinActionSpec {
	spec := permissionAction(group, groupLabel, operation, operationLabel, method, route, label, nil)
	spec.exposures = []actioncontract.Exposure{actioncontract.ExposurePublic, actioncontract.ExposureTenantAdmin}
	return spec
}

func principalAction(group, groupLabel, operation, operationLabel, method, route, label string) identityBuiltinActionSpec {
	return identityBuiltinActionSpec{
		group: group, groupLabel: groupLabel, operation: operation, operationLabel: operationLabel, method: method, route: route, label: label,
		authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticatedPrincipal},
	}
}

func anonymousAction(group, groupLabel, operation, operationLabel, method, route, label string) identityBuiltinActionSpec {
	return identityBuiltinActionSpec{
		group: group, groupLabel: groupLabel, operation: operation, operationLabel: operationLabel, method: method, route: route, label: label,
		authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAnonymousProtocol, PolicyKey: group + "." + operation},
		exposures:     []actioncontract.Exposure{actioncontract.ExposurePublic},
	}
}

func authAnonymousAction(group, groupLabel, operation, operationLabel, method, route, label string) identityBuiltinActionSpec {
	spec := anonymousAction(group, groupLabel, operation, operationLabel, method, route, label)
	spec.exposures = []actioncontract.Exposure{actioncontract.ExposurePublic, actioncontract.ExposureTenantAdmin}
	return spec
}

func authPrincipalAction(group, groupLabel, operation, operationLabel, method, route, label string) identityBuiltinActionSpec {
	spec := principalAction(group, groupLabel, operation, operationLabel, method, route, label)
	spec.exposures = []actioncontract.Exposure{actioncontract.ExposurePublic, actioncontract.ExposureTenantAdmin}
	return spec
}

func selfAction(group, groupLabel, operation, operationLabel, method, route, label, policy string) identityBuiltinActionSpec {
	return identityBuiltinActionSpec{
		group: group, groupLabel: groupLabel, operation: operation, operationLabel: operationLabel, method: method, route: route, label: label,
		authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationSelfOrPermission, PolicyKey: policy},
	}
}

func selfPageAction(group, groupLabel, operation, operationLabel, method, route, label, policy string, pageBinding *identitymodel.IdentityPageActionBinding) identityBuiltinActionSpec {
	spec := selfAction(group, groupLabel, operation, operationLabel, method, route, label, policy)
	spec.page = pageBinding
	return spec
}

func page(route, label string) *identitymodel.IdentityPageActionBinding {
	return &identitymodel.IdentityPageActionBinding{Route: route, Label: label}
}

func buildIdentityBuiltinAction(spec identityBuiltinActionSpec) identitymodel.IdentityActionDefinition {
	key := strings.TrimSpace(spec.group) + "." + strings.TrimSpace(spec.operation)
	displayRoute := spec.route
	if strings.Contains(displayRoute, "{objectKey}") || strings.Contains(displayRoute, "{actionKey}") {
		displayRoute = ""
	}
	effect, idempotency, risk := actioncontract.EffectRead, "not_applicable", actioncontract.RiskLow
	if spec.method != "GET" && spec.method != "HEAD" {
		effect, idempotency, risk = actioncontract.EffectWrite, "idempotency_key_or_domain_receipt", actioncontract.RiskMedium
	}
	exposures := append([]actioncontract.Exposure(nil), spec.exposures...)
	if len(exposures) == 0 {
		exposures = []actioncontract.Exposure{actioncontract.ExposureTenantAdmin}
	}
	definition := identitymodel.IdentityActionDefinition{
		Key: key, Owner: IdentityBuiltinAuthorizationOwner, SourceKind: "builtin_surface",
		CapabilityKey: spec.group, CapabilityLabel: spec.groupLabel, OperationKey: spec.operation, OperationLabel: spec.operationLabel,
		Label: spec.label, Exposures: exposures, Authorization: spec.authorization,
		HTTP:        &identitymodel.IdentityHTTPActionBinding{Method: spec.method, RouteTemplate: spec.route, DisplayRouteTemplate: displayRoute},
		EffectClass: effect, RiskLevel: risk, IdempotencyDecision: idempotency,
		AuditClass: "identity_management", LifecycleStatus: actioncontract.LifecycleActive,
	}
	if spec.page != nil {
		definition.Pages = []identitymodel.IdentityPageActionBinding{*spec.page}
	}
	if definition.Authorization.Strategy == actioncontract.AuthorizationExactRolePermission || definition.Authorization.Strategy == actioncontract.AuthorizationSelfOrPermission {
		definition.Permission = &identitymodel.IdentityPermissionDefinitionContract{
			Key: key, Owner: IdentityBuiltinAuthorizationOwner, ResourceKey: spec.group, ActionKey: spec.operation,
			Label: strings.TrimSpace(spec.groupLabel) + " · " + strings.TrimSpace(spec.operationLabel), Description: spec.label,
			Category: "Identity 权限管理", LifecycleStatus: actioncontract.LifecycleActive,
		}
	}
	return definition
}

func NewStandaloneIdentityAuthorizationSliceRegistry() (*IdentityActionRegistry, error) {
	return NewIdentityActionRegistry(IdentityBuiltinAuthorizationActions())
}
