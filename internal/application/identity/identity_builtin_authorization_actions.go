package identity

import (
	"strings"

	actioncontract "github.com/domainry/domainry-foundation/action"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
)

const IdentityBuiltinAuthorizationOwner = identitycontract.IdentityBuiltinAuthorizationOwner

type identityBuiltinActionSpec struct {
	key, capabilityLabel string
	operationLabel       string
	method, route, label string
	page                 *identitymodel.IdentityPageActionBinding
	authorization        actioncontract.Authorization
	exposures            []actioncontract.Exposure
	permission           bool
}

func IdentityBuiltinAuthorizationActions() []identitymodel.IdentityActionDefinition {
	accounts := page("/admin/security/accounts", "账号管理")
	accountDetail := page("/admin/security/accounts/$userId", "账号详情")
	organizationUnits := page("/admin/org/organization-units", "组织机构管理")
	roles := page("/admin/org/roles", "角色管理")
	menus := page("/admin/org/menus", "菜单管理")
	fieldPermissions := page("/admin/org/field-permissions", "字段权限")
	metadata := page("/admin/system/metadata", "元数据")

	specs := []identityBuiltinActionSpec{
		anonymousAction("auth.discovery.jwks", "认证发现", "读取 JWKS", "GET", "/.well-known/jwks.json", "读取 JSON Web Key Set"),
		anonymousAction("auth.discovery.openid_configuration", "认证发现", "读取 OpenID 配置", "GET", "/.well-known/openid-configuration", "读取 OpenID Connect 配置"),
		anonymousAction("auth.login", "认证", "登录", "POST", "/auth/login", "密码登录"),
		anonymousAction("auth.guest", "认证", "访客登录", "POST", "/auth/guest", "访客登录"),
		anonymousAction("auth.refresh", "认证", "刷新会话", "POST", "/auth/refresh", "刷新访问会话"),
		anonymousAction("auth.logout", "认证", "退出", "POST", "/auth/logout", "撤销刷新会话并退出"),
		authPrincipalAction("auth.session.get", "浏览器会话", "读取会话", "GET", "/auth/session", "读取当前浏览器会话"),
		anonymousAction("auth.code.exchange", "认证码", "交换认证码", "POST", "/auth/code/exchange", "交换一次性认证码"),
		authPrincipalAction("auth.sessions.revoke_others", "会话安全", "撤销其它会话", "POST", "/auth/sessions/revoke-others", "撤销当前用户的其它会话"),
		authPrincipalAction("auth.change_password", "认证安全", "修改密码", "POST", "/auth/change-password", "修改当前用户密码"),
		authPermissionAction(identitycontract.IdentityActionAuthResetPassword, "认证安全", "重置密码", "POST", "/auth/reset-password", "重置用户密码"),
		anonymousAction("auth.providers.list", "认证提供方", "列出", "GET", "/auth/providers", "列出可用认证提供方"),
		authAnonymousAction("auth.providers.setup_check", "认证提供方", "配置检查", "GET", "/auth/providers/{provider}/setup-check", "检查认证提供方配置"),
		authPermissionAction(identitycontract.IdentityActionAuthProvidersSetup, "认证提供方", "配置", "PUT", "/auth/providers/{provider}/setup", "配置认证提供方"),
		anonymousAction("auth.providers.start_get", "认证提供方", "发起登录", "GET", "/auth/providers/{provider}/start", "发起认证提供方登录"),
		anonymousAction("auth.providers.start_post", "认证提供方", "发起登录", "POST", "/auth/providers/{provider}/start", "发起认证提供方登录"),
		anonymousAction("auth.providers.callback_get", "认证提供方", "处理回调", "GET", "/auth/providers/{provider}/callback", "处理认证提供方回调"),
		anonymousAction("auth.providers.callback_post", "认证提供方", "处理回调", "POST", "/auth/providers/{provider}/callback", "处理认证提供方回调"),
		anonymousAction("auth.providers.verify", "认证提供方", "验证", "POST", "/auth/providers/{provider}/verify", "验证认证提供方挑战"),
		anonymousAction("auth.providers.exchange", "认证提供方", "交换凭证", "POST", "/auth/providers/{provider}/exchange", "交换认证提供方凭证"),
		authPrincipalAction("auth.external_accounts.list", "外部账号", "列出", "GET", "/auth/external-accounts", "列出当前用户外部账号"),
		authPrincipalAction("auth.external_accounts.bind", "外部账号", "绑定", "POST", "/auth/external-accounts/{provider}/bind", "绑定当前用户外部账号"),
		authPrincipalAction("auth.external_accounts.unbind", "外部账号", "解绑", "DELETE", "/auth/external-accounts/{provider}/{accountID}", "解绑当前用户外部账号"),
		authPrincipalAction("auth.me.get", "当前用户", "查看", "GET", "/auth/me", "查看当前用户"),
		authPrincipalAction("auth.me.update", "当前用户", "更新", "PATCH", "/auth/me", "更新当前用户设置"),
		authPrincipalAction("auth.role_options.list", "角色选项", "列出", "GET", "/auth/role-options", "列出当前用户角色选项"),
		authPrincipalAction("auth.role_requests.list", "角色申请", "列出", "GET", "/auth/role-requests", "列出当前用户角色申请"),
		authPrincipalAction("auth.role_requests.create", "角色申请", "创建", "POST", "/auth/role-requests", "创建当前用户角色申请"),
		principalAction("identity.effective_menus.get", "有效菜单", "获取", "GET", "/identity/effective-menus", "获取当前用户有效菜单"),

		permissionAction("identity.organization_units.list", "组织机构管理", "列出", "GET", "/identity/organization-units", "列出组织机构", organizationUnits),
		permissionAction("identity.organization_units.get", "组织机构管理", "查看", "GET", "/identity/organization-units/{organizationUnitID}", "查看组织机构", nil),
		permissionAction("identity.organization_units.versions", "组织机构管理", "查看版本", "GET", "/identity/organization-units/{organizationUnitID}/versions", "查看组织机构版本", nil),
		permissionAction("identity.organization_units.create", "组织机构管理", "创建", "POST", "/identity/organization-units", "创建组织机构", nil),
		permissionAction("identity.organization_units.validate", "组织机构管理", "校验", "POST", "/identity/organization-units/{organizationUnitID}/validate", "校验组织机构定义", nil),
		permissionAction("identity.organization_units.update", "组织机构管理", "更新", "PATCH", "/identity/organization-units/{organizationUnitID}", "更新组织机构", nil),

		permissionAction("identity.users.list", "账号管理", "列出", "GET", "/identity/users", "列出用户", accounts),
		permissionAction("identity.users.search", "账号管理", "搜索", "GET", "/identity/users/search", "搜索用户", nil),
		permissionAction("identity.accounts.search", "账号管理", "账号搜索", "GET", "/identity/accounts/search", "搜索账号", nil),
		selfPageAction("identity.users.get", "账号管理", "查看", "GET", "/identity/users/{userID}", "查看用户", "identity.user.self", accountDetail),
		permissionAction("identity.users.deletion_impact", "账号管理", "删除影响", "GET", "/identity/users/{userID}/deletion-impact", "查看用户删除影响", nil),
		permissionAction("identity.users.disable_impact", "账号管理", "停用影响", "GET", "/identity/users/{userID}/disable-impact", "查看用户停用影响", nil),
		permissionAction("identity.users.versions", "账号管理", "查看版本", "GET", "/identity/users/{userID}/versions", "查看用户版本", nil),
		permissionAction("identity.users.create", "账号管理", "创建", "POST", "/identity/users", "创建用户", nil),
		permissionAction("identity.users.validate", "账号管理", "校验", "POST", "/identity/users/{userID}/validate", "校验用户定义", nil),
		permissionAction("identity.users.update", "账号管理", "更新", "PATCH", "/identity/users/{userID}", "更新用户", nil),
		permissionAction("identity.users.delete", "账号管理", "删除", "DELETE", "/identity/users/{userID}", "删除用户", nil),
		permissionAction("identity.users.disable", "账号管理", "停用", "POST", "/identity/users/{userID}/disable", "停用用户", nil),
		permissionAction("identity.users.enable", "账号管理", "启用", "POST", "/identity/users/{userID}/enable", "启用用户", nil),
		selfAction("identity.users.security_get", "账号管理", "查看安全信息", "GET", "/identity/users/{userID}/security", "查看用户安全信息", "identity.user.self"),
		selfAction("identity.users.effective_access", "账号管理", "查看有效权限", "GET", "/identity/users/{userID}/effective-access", "查看用户有效权限", "identity.user.self"),
		permissionAction("identity.users.unlock", "账号管理", "解锁", "POST", "/identity/users/{userID}/unlock", "解锁用户", nil),
		permissionAction(identitycontract.IdentityActionUsersForceLogout, "账号管理", "强制退出", "POST", "/identity/users/{userID}/force-logout", "强制用户退出", nil),
		permissionAction("identity.users.mfa_revoke", "账号管理", "撤销 MFA", "DELETE", "/identity/users/{userID}/mfa/{factorID}", "撤销用户 MFA 因子", nil),
		selfAction("identity.user_role_assignments.list", "用户角色", "列出", "GET", "/identity/users/{userID}/role-assignments", "列出用户角色分配", "identity.user.self"),
		selfAction("identity.user_role_assignments.search", "用户角色", "搜索", "GET", "/identity/users/{userID}/role-assignments/search", "搜索用户角色分配", "identity.user.self"),
		permissionAction("identity.user_role_assignments.assignable_roles", "用户角色", "可分配角色", "GET", "/identity/users/{userID}/assignable-roles", "列出用户可分配角色", nil),
		permissionAction("identity.user_role_assignments.account_and_roles_update", "用户角色", "更新账号与角色", "PUT", "/identity/users/{userID}/account-and-roles", "更新用户账号与角色", nil),
		permissionAction("identity.user_role_assignments.versions", "用户角色", "查看版本", "GET", "/identity/users/{userID}/role-assignments/versions", "查看用户角色分配版本", nil),
		permissionAction("identity.user_role_assignments.assign", "用户角色", "分配", "POST", "/identity/users/{userID}/role-assignments", "分配用户角色", nil),
		permissionAction("identity.user_role_assignments.validate", "用户角色", "校验", "POST", "/identity/users/{userID}/role-assignments/validate", "校验用户角色分配", nil),
		permissionAction("identity.user_role_assignments.revoke", "用户角色", "撤销", "DELETE", "/identity/users/{userID}/role-assignments/{roleID}", "撤销用户角色", nil),

		selfAction(identitycontract.IdentityActionProfileBindingsGet, "业务身份绑定", "查看", "GET", "/identity/profile-bindings/{objectKey}/{profileID}", "查看业务身份绑定", "identity.profile_binding.self"),
		selfAction(identitycontract.IdentityActionProfileBindingsCommand, "业务身份绑定", "执行命令", "POST", "/identity/profile-bindings/{objectKey}/{profileID}/commands", "执行业务身份绑定命令", "identity.profile_binding.self"),
		principalAction("identity.principal_context.get", "主体上下文", "获取", "GET", "/identity/principal-context", "获取当前主体上下文"),
		selfAction("identity.access.explain", "有效权限", "解释", "POST", "/identity/access/explain", "解释用户有效权限", "identity.effective_access.self"),
		permissionAction("identity.access.reverse_index", "权限治理", "反向索引", "GET", "/identity/access/reverse-index", "查看权限反向索引", nil),
		permissionAction("identity.access.reports", "权限治理", "治理报告", "GET", "/identity/access/report", "查看权限治理报告", nil),
		permissionAction("identity.access_reviews.create", "访问评审", "创建", "POST", "/identity/access-reviews", "创建访问评审", nil),
		permissionAction("identity.access_reviews.list", "访问评审", "列出", "GET", "/identity/access-reviews", "列出访问评审", nil),
		permissionAction("identity.access_review_items.decide", "访问评审项", "决策", "POST", "/identity/access-review-items/{itemID}/decision", "决策访问评审项", nil),
		permissionAction("identity.entitlements.batch", "授权批处理", "批量执行", "POST", "/identity/entitlements/batch", "批量处理授权", nil),
		permissionAction("identity.role_requests.list", "角色申请", "列出", "GET", "/identity/role-requests", "列出角色申请", nil),
		permissionAction("identity.role_requests.approve", "角色申请", "批准", "POST", "/identity/role-requests/{requestID}/approve", "批准角色申请", nil),
		permissionAction("identity.role_requests.reject", "角色申请", "拒绝", "POST", "/identity/role-requests/{requestID}/reject", "拒绝角色申请", nil),

		permissionAction(identitycontract.IdentityActionRolesList, "角色管理", "列出", "GET", "/identity/roles", "列出角色", roles),
		permissionAction(identitycontract.IdentityActionRolesSearch, "角色管理", "搜索", "GET", "/identity/roles/search", "搜索角色", nil),
		permissionAction(identitycontract.IdentityActionRolesGet, "角色管理", "查看", "GET", "/identity/roles/{roleID}", "查看角色", nil),
		permissionAction(identitycontract.IdentityActionRolesCreate, "角色管理", "创建", "POST", "/identity/roles", "创建角色", nil),
		permissionAction(identitycontract.IdentityActionRolesUpdate, "角色管理", "更新", "PATCH", "/identity/roles/{roleID}", "更新角色", nil),
		permissionAction(identitycontract.IdentityActionRolesDelete, "角色管理", "删除", "DELETE", "/identity/roles/{roleID}", "删除角色", nil),
		permissionAction(identitycontract.IdentityActionRolesGovernanceDetail, "角色管理", "治理详情", "GET", "/identity/roles/{roleID}/governance-detail", "查看角色治理详情", nil),
		permissionAction(identitycontract.IdentityActionRolesVersions, "角色管理", "查看版本", "GET", "/identity/roles/{roleID}/versions", "查看角色版本", nil),
		permissionAction(identitycontract.IdentityActionRolesImpactPreview, "角色管理", "影响预览", "POST", "/identity/roles/{roleID}/impact-preview", "预览角色变更影响", nil),
		permissionAction(identitycontract.IdentityActionRolesValidateGovernance, "角色管理", "治理校验", "POST", "/identity/governance/validate", "校验角色治理约束", nil),
		permissionAction(identitycontract.IdentityActionRolesValidate, "角色管理", "校验", "POST", "/identity/roles/{roleID}/validate", "校验角色定义", nil),

		permissionAction("identity.menus.list", "菜单管理", "列出", "GET", "/identity/menus", "列出菜单", menus),
		permissionAction("identity.menus.get", "菜单管理", "查看", "GET", "/identity/menus/{menuID}", "查看菜单", nil),
		permissionAction("identity.menus.versions", "菜单管理", "查看版本", "GET", "/identity/menus/{menuID}/versions", "查看菜单版本", nil),
		permissionAction("identity.menus.validate", "菜单管理", "校验", "POST", "/identity/menus/{menuID}/validate", "校验菜单", nil),
		permissionAction("identity.menus.upsert", "菜单管理", "保存", "PUT", "/identity/menus/{menuID}", "保存菜单", nil),
		permissionAction("identity.menus.delete", "菜单管理", "删除", "DELETE", "/identity/menus/{menuID}", "删除菜单", nil),
		permissionAction("identity.role_menus.list", "角色菜单", "列出", "GET", "/identity/roles/{roleID}/menus", "列出角色菜单", nil),
		permissionAction("identity.role_menus.versions", "角色菜单", "查看版本", "GET", "/identity/roles/{roleID}/menus/versions", "查看角色菜单版本", nil),
		permissionAction("identity.role_menus.validate", "角色菜单", "校验", "POST", "/identity/roles/{roleID}/menus/validate", "校验角色菜单", nil),
		permissionAction("identity.role_menus.publish", "角色菜单", "发布", "PUT", "/identity/roles/{roleID}/menus", "发布角色菜单", nil),

		permissionAction(identitycontract.IdentityActionPermissionsList, "功能权限管理", "列出", "GET", "/identity/permissions", "列出功能权限", nil),
		permissionAction(identitycontract.IdentityActionPermissionsSetEnabled, "功能权限管理", "设置启停状态", "PUT", "/identity/permissions/{permissionKey}/enabled", "启用或停用功能权限", nil),
		permissionAction(identitycontract.IdentityActionRolePermissionsList, "角色功能权限", "列出", "GET", "/identity/roles/{roleID}/permissions", "查看角色功能权限", nil),
		permissionAction(identitycontract.IdentityActionRolePermissionsValidate, "角色功能权限", "校验", "POST", "/identity/roles/{roleID}/permissions/validate", "校验角色功能权限", nil),
		permissionAction(identitycontract.IdentityActionRolePermissionsPublish, "角色功能权限", "发布", "PUT", "/identity/roles/{roleID}/permissions", "发布角色功能权限", nil),
		permissionAction(identitycontract.IdentityActionRoleFieldPermissionsList, "角色字段权限", "列出", "GET", "/identity/roles/{roleID}/field-permissions", "列出角色字段权限", fieldPermissions),
		permissionAction(identitycontract.IdentityActionRoleFieldPermissionsValidate, "角色字段权限", "校验", "POST", "/identity/roles/{roleID}/field-permissions/validate", "校验角色字段权限", nil),
		permissionAction(identitycontract.IdentityActionRoleFieldPermissionsPublish, "角色字段权限", "发布", "PUT", "/identity/roles/{roleID}/field-permissions", "发布角色字段权限", nil),

		principalAction("identity.permissions.effective", "功能权限", "读取当前生效权限", "GET", "/identity/permissions/effective", "读取当前主体的生效权限"),
		principalAction("identity.runtime_schema.get", "Identity Runtime Schema", "读取", "GET", "/identity/schema", "读取按当前主体过滤的 Identity Runtime Schema"),
		permissionAction("identity.platform_capabilities.get", "平台能力", "读取", "GET", "/identity/platform-capabilities", "读取 Identity 平台能力目录", nil),
	}

	out := make([]identitymodel.IdentityActionDefinition, 0, len(specs)+21)
	out = append(out, identityMetadataNonHTTPActions(metadata)...)
	out = append(out, identityHandlerDeliveryNonHTTPActions()...)
	out = append(out, identityStoreOrganizationDeliveryNonHTTPActions()...)
	out = append(out, identityOrganizationUnitDeliveryNonHTTPActions()...)
	out = append(out, identityWorkspaceUsageNonHTTPActions()...)
	for _, spec := range specs {
		out = append(out, buildIdentityBuiltinAction(spec))
	}
	return out
}

func identityOrganizationUnitDeliveryNonHTTPActions() []identitymodel.IdentityActionDefinition {
	return []identitymodel.IdentityActionDefinition{
		nonHTTPPermissionAction(identitycontract.IdentityOrganizationUnitDeliveryCreatePermission, "identity.organization_unit_delivery", "Handler 组织节点交付", "create", "创建", "在已授权父节点下原子创建通用组织节点", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(identitycontract.IdentityOrganizationUnitDeliveryResolvePermission, "identity.organization_unit_delivery", "Handler 组织节点交付", "resolve", "解析", "按持久化父节点权限解析最小组织节点投影", actioncontract.EffectRead, actioncontract.RiskLow),
	}
}

func identityWorkspaceUsageNonHTTPActions() []identitymodel.IdentityActionDefinition {
	action := nonHTTPPermissionAction(
		identitycontract.IdentityWorkspaceIdentityUsageAggregate,
		"identity.workspace_identity_usage",
		"Workspace Identity 用量",
		"aggregate",
		"聚合",
		"按宿主授权的活跃 Workspace 聚合非敏感账号分类计数",
		actioncontract.EffectRead,
		actioncontract.RiskMedium,
	)
	// The embedded installation authority validates this purpose-specific
	// credential. A Workspace principal is not sufficient.
	action.Permission = nil
	action.Authorization = actioncontract.Authorization{
		Strategy:  actioncontract.AuthorizationSigned,
		PolicyKey: identitycontract.IdentityWorkspaceIdentityUsageAggregate,
	}
	action.IdempotencyDecision = "not_applicable_current_usage_read"
	action.AuditClass = "installation_identity_usage"
	return []identitymodel.IdentityActionDefinition{action}
}

func identityStoreOrganizationDeliveryNonHTTPActions() []identitymodel.IdentityActionDefinition {
	return []identitymodel.IdentityActionDefinition{
		nonHTTPPermissionAction(identitycontract.IdentityStoreOrganizationDeliveryCreatePermission, "identity.store_organization_delivery", "Handler 门店组织交付", "create", "创建", "在公司节点下原子创建门店组织", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(identitycontract.IdentityStoreOrganizationDeliveryRenamePermission, "identity.store_organization_delivery", "Handler 门店组织交付", "rename", "改名", "原子修改门店组织名称", actioncontract.EffectWrite, actioncontract.RiskMedium),
		nonHTTPPermissionAction(identitycontract.IdentityStoreOrganizationDeliveryDisablePermission, "identity.store_organization_delivery", "Handler 门店组织交付", "disable", "停用", "原子停用门店组织", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(identitycontract.IdentityStoreOrganizationDeliveryResolvePermission, "identity.store_organization_delivery", "Handler 门店组织交付", "resolve", "解析", "读取一个最小门店组织投影", actioncontract.EffectRead, actioncontract.RiskLow),
		nonHTTPPermissionAction(identitycontract.IdentityStoreOrganizationDeliveryListPermission, "identity.store_organization_delivery", "Handler 门店组织交付", "list", "列表", "读取数据范围内的最小门店组织列表", actioncontract.EffectRead, actioncontract.RiskLow),
	}
}

func identityHandlerDeliveryNonHTTPActions() []identitymodel.IdentityActionDefinition {
	return []identitymodel.IdentityActionDefinition{
		nonHTTPPermissionAction(identitycontract.IdentityHandlerDeliveryCreatePermission, "identity.handler_delivery", "Handler 身份交付", "create", "创建", "原子创建用户、精确角色与业务身份绑定", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(identitycontract.IdentityHandlerDeliveryUpdatePermission, "identity.handler_delivery", "Handler 身份交付", "update", "更新", "原子更新用户、精确角色与业务身份绑定", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(identitycontract.IdentityHandlerDeliveryDisablePermission, "identity.handler_delivery", "Handler 身份交付", "disable", "停用", "原子停用用户并撤销会话", actioncontract.EffectWrite, actioncontract.RiskHigh),
		nonHTTPPermissionAction(identitycontract.IdentityHandlerDeliveryResolvePermission, "identity.handler_delivery", "Handler 身份交付", "resolve", "解析", "读取业务 Handler 所需的最小规范身份投影", actioncontract.EffectRead, actioncontract.RiskLow),
	}
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
		Label: label, Exposures: []actioncontract.Exposure{actioncontract.ExposureManagement},
		Authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated},
		NonHTTP:       []identitymodel.IdentityNonHTTPActionBinding{{Kind: "application_use_case", InvocationKey: key}},
		Permission: &identitymodel.IdentityPermissionDefinitionContract{
			Key: key, Owner: IdentityBuiltinAuthorizationOwner, ResourceKey: capabilityKey, OperationKey: operationKey,
			Label: capabilityLabel + " · " + operationLabel, Description: label,
			Category: "Identity 权限管理", LifecycleStatus: actioncontract.LifecycleActive,
		},
		EffectClass: effect, RiskLevel: risk, IdempotencyDecision: "application_service_contract",
		AuditClass: "identity_management", LifecycleStatus: actioncontract.LifecycleActive,
	}
}

// StandaloneIdentityAuthorizationSliceActions is kept as the assembly entry
// point while now returning the complete Identity-owned management adapter.
func StandaloneIdentityAuthorizationSliceActions() []identitymodel.IdentityActionDefinition {
	return IdentityBuiltinAuthorizationActions()
}

func permissionAction(key, capabilityLabel, operationLabel, method, route, label string, pageBinding *identitymodel.IdentityPageActionBinding) identityBuiltinActionSpec {
	return identityBuiltinActionSpec{
		key: key, capabilityLabel: capabilityLabel, operationLabel: operationLabel, method: method, route: route, label: label, page: pageBinding,
		authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated}, permission: true,
	}
}

func authPermissionAction(key, capabilityLabel, operationLabel, method, route, label string) identityBuiltinActionSpec {
	spec := permissionAction(key, capabilityLabel, operationLabel, method, route, label, nil)
	spec.exposures = []actioncontract.Exposure{actioncontract.ExposureManagement}
	return spec
}

func principalAction(key, capabilityLabel, operationLabel, method, route, label string) identityBuiltinActionSpec {
	return identityBuiltinActionSpec{
		key: key, capabilityLabel: capabilityLabel, operationLabel: operationLabel, method: method, route: route, label: label,
		authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated},
	}
}

func anonymousAction(key, capabilityLabel, operationLabel, method, route, label string) identityBuiltinActionSpec {
	return identityBuiltinActionSpec{
		key: key, capabilityLabel: capabilityLabel, operationLabel: operationLabel, method: method, route: route, label: label,
		authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAnonymous},
		exposures:     []actioncontract.Exposure{actioncontract.ExposurePublic},
	}
}

func authAnonymousAction(key, capabilityLabel, operationLabel, method, route, label string) identityBuiltinActionSpec {
	spec := anonymousAction(key, capabilityLabel, operationLabel, method, route, label)
	spec.exposures = []actioncontract.Exposure{actioncontract.ExposureManagement}
	return spec
}

func authPrincipalAction(key, capabilityLabel, operationLabel, method, route, label string) identityBuiltinActionSpec {
	spec := principalAction(key, capabilityLabel, operationLabel, method, route, label)
	spec.exposures = []actioncontract.Exposure{actioncontract.ExposurePublic}
	return spec
}

func selfAction(key, capabilityLabel, operationLabel, method, route, label, policy string) identityBuiltinActionSpec {
	return identityBuiltinActionSpec{
		key: key, capabilityLabel: capabilityLabel, operationLabel: operationLabel, method: method, route: route, label: label,
		authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated, PolicyKey: policy}, permission: true,
	}
}

func selfPageAction(key, capabilityLabel, operationLabel, method, route, label, policy string, pageBinding *identitymodel.IdentityPageActionBinding) identityBuiltinActionSpec {
	spec := selfAction(key, capabilityLabel, operationLabel, method, route, label, policy)
	spec.page = pageBinding
	return spec
}

func page(route, label string) *identitymodel.IdentityPageActionBinding {
	return &identitymodel.IdentityPageActionBinding{Route: route, Label: label}
}

func buildIdentityBuiltinAction(spec identityBuiltinActionSpec) identitymodel.IdentityActionDefinition {
	key := strings.TrimSpace(spec.key)
	separator := strings.LastIndexByte(key, '.')
	if separator <= 0 || separator == len(key)-1 {
		panic("invalid Identity builtin Action key " + key)
	}
	capabilityKey, operationKey := key[:separator], key[separator+1:]
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
		exposures = []actioncontract.Exposure{actioncontract.ExposureManagement}
	}
	definition := identitymodel.IdentityActionDefinition{
		Key: key, Owner: IdentityBuiltinAuthorizationOwner, SourceKind: "builtin_http",
		CapabilityKey: capabilityKey, CapabilityLabel: spec.capabilityLabel, OperationKey: operationKey, OperationLabel: spec.operationLabel,
		Label: spec.label, Exposures: exposures, Authorization: spec.authorization,
		HTTP:        &identitymodel.IdentityHTTPActionBinding{Method: spec.method, RouteTemplate: spec.route, DisplayRouteTemplate: displayRoute},
		EffectClass: effect, RiskLevel: risk, IdempotencyDecision: idempotency,
		AuditClass: "identity_management", LifecycleStatus: actioncontract.LifecycleActive,
	}
	if spec.page != nil {
		definition.Pages = []identitymodel.IdentityPageActionBinding{*spec.page}
	}
	if spec.permission {
		definition.Permission = &identitymodel.IdentityPermissionDefinitionContract{
			Key: key, Owner: IdentityBuiltinAuthorizationOwner, ResourceKey: capabilityKey, OperationKey: operationKey,
			Label: strings.TrimSpace(spec.capabilityLabel) + " · " + strings.TrimSpace(spec.operationLabel), Description: spec.label,
			Category: "Identity 权限管理", LifecycleStatus: actioncontract.LifecycleActive,
		}
	}
	return definition
}

func NewStandaloneIdentityAuthorizationSliceRegistry() (*IdentityActionRegistry, error) {
	return NewIdentityActionRegistry(IdentityBuiltinAuthorizationActions())
}
