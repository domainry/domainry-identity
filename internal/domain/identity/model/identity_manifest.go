package identitymodel

import localizationmodel "github.com/domainry/domainry-identity/internal/domain/localization/model"

type RoleSchema struct {
	Key                   string                             `json:"key"`
	Name                  string                             `json:"name"`
	Description           string                             `json:"description,omitempty"`
	I18n                  localizationmodel.LocalizedTextMap `json:"i18n,omitempty"`
	Permissions           []RolePermission                   `json:"permissions"`
	FieldPermissions      []FieldPermission                  `json:"field_permissions,omitempty"`
	ReferencePermissions  []ReferencePermission              `json:"reference_permissions,omitempty"`
	ExportRules           []ExportRule                       `json:"export_rules,omitempty"`
	Audience              IdentityRoleAudience               `json:"audience,omitempty"`
	RequiredBindingKey    string                             `json:"required_binding_key,omitempty"`
	AssignmentMode        IdentityRoleAssignmentMode         `json:"assignment_mode,omitempty"`
	RiskLevel             IdentityRoleRiskLevel              `json:"risk_level,omitempty"`
	ConflictRoleKeys      []string                           `json:"conflict_role_keys,omitempty"`
	GrantableRoleKeys     []string                           `json:"grantable_role_keys,omitempty"`
	PermissionSetKeys     []string                           `json:"permission_set_keys,omitempty"`
	PermissionSetGroups   []string                           `json:"permission_set_group_keys,omitempty"`
	GuardrailKeys         []string                           `json:"guardrail_keys,omitempty"`
	Guardrails            []IdentityGuardrailPolicy          `json:"guardrails,omitempty"`
	ProvisionToWorkspaces bool                               `json:"provision_to_workspaces,omitempty"`
}

type IdentityRoleAudience string

const (
	IdentityRoleAudienceAny      IdentityRoleAudience = "any"
	IdentityRoleAudienceUser     IdentityRoleAudience = "user"
	IdentityRoleAudienceBusiness IdentityRoleAudience = "business_profile"
	IdentityRoleAudienceService  IdentityRoleAudience = "service"
)

type IdentityRoleAssignmentMode string

const (
	IdentityRoleAssignmentManual        IdentityRoleAssignmentMode = "manual"
	IdentityRoleAssignmentRequestOnly   IdentityRoleAssignmentMode = "request_only"
	IdentityRoleAssignmentSystemManaged IdentityRoleAssignmentMode = "system_managed"
)

type IdentityRoleRiskLevel string

const (
	IdentityRoleRiskNormal     IdentityRoleRiskLevel = "normal"
	IdentityRoleRiskElevated   IdentityRoleRiskLevel = "elevated"
	IdentityRoleRiskPrivileged IdentityRoleRiskLevel = "privileged"
)

type ManifestIdentityUserSchema struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	GivenName     string              `json:"given_name,omitempty"`
	MiddleName    string              `json:"middle_name,omitempty"`
	FamilyName    string              `json:"family_name,omitempty"`
	NamePrefix    string              `json:"name_prefix,omitempty"`
	NameSuffix    string              `json:"name_suffix,omitempty"`
	NativeName    string              `json:"native_name,omitempty"`
	NameLocale    string              `json:"name_locale,omitempty"`
	AccountType   IdentityAccountType `json:"account_type,omitempty"`
	Locale        string              `json:"locale,omitempty"`
	Timezone      string              `json:"timezone,omitempty"`
	OrgID         string              `json:"org_id,omitempty"`
	SupportOrgID  string              `json:"support_org_id,omitempty"`
	ManagerUserID string              `json:"manager_user_id,omitempty"`
	WorkerNo      string              `json:"worker_no,omitempty"`
	WorkerType    IdentityWorkerType  `json:"worker_type,omitempty"`
	WorkStatus    IdentityWorkStatus  `json:"work_status,omitempty"`
	StartDate     string              `json:"start_date,omitempty"`
	EndDate       string              `json:"end_date,omitempty"`
	Email         string              `json:"email"`
	Phone         string              `json:"phone,omitempty"`
	Status        string              `json:"status,omitempty"`
	RoleKeys      []string            `json:"role_keys"`
}
type ManifestIdentityOrganizationUnitSchema struct {
	ID        string                       `json:"id"`
	Code      string                       `json:"code"`
	Name      string                       `json:"name"`
	NodeType  IdentityOrganizationUnitType `json:"node_type"`
	ParentID  *string                      `json:"parent_id,omitempty"`
	SortOrder int                          `json:"sort_order,omitempty"`
	Status    string                       `json:"status,omitempty"`
}
type ManifestIdentityUserRoleAssignmentSchema struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}
type ManifestIdentityBootstrapSchema struct {
	Version             string                                     `json:"version"`
	OrganizationUnits   []ManifestIdentityOrganizationUnitSchema   `json:"organization_units,omitempty"`
	Users               []ManifestIdentityUserSchema               `json:"users,omitempty"`
	UserRoleAssignments []ManifestIdentityUserRoleAssignmentSchema `json:"user_role_assignments,omitempty"`
	Menus               []IdentityMenu                             `json:"menus,omitempty"`
	RoleMenus           []IdentityRoleMenuAssignment               `json:"role_menus,omitempty"`
	RoleMenuSets        []ManifestIdentityRoleMenuSetSchema        `json:"role_menu_sets,omitempty"`
	ProfileBindings     []ManifestIdentityProfileBindingSeedSchema `json:"profile_bindings,omitempty"`
}

// ManifestIdentityProfileBindingSeedSchema is the compiler-resolved startup
// intent for an active demo or acceptance profile binding. Runtime applies it
// only after the referenced business seed record exists.
type ManifestIdentityProfileBindingSeedSchema struct {
	BindingKey     string `json:"binding_key"`
	ObjectKey      string `json:"object_key"`
	ProfileID      string `json:"profile_id"`
	IdentityUserID string `json:"identity_user_id"`
	IdentityField  string `json:"identity_field"`
}

type ManifestIdentityRoleMenuSetSchema struct {
	RoleID  string   `json:"role_id"`
	MenuIDs []string `json:"menu_ids"`
}

// RolePermission is one exact Action Permission grant. DataScope belongs to
// the grant, so two actions on the same resource can use different scopes.
type RolePermission struct {
	PermissionKey string            `json:"permission_key"`
	DataScope     IdentityDataScope `json:"data_scope"`
	AuditDenial   bool              `json:"audit_denial,omitempty"`
}
type FieldPermission struct {
	ObjectKey string                      `json:"object_key"`
	FieldKey  string                      `json:"field_key"`
	Read      bool                        `json:"read"`
	Write     bool                        `json:"write"`
	Export    bool                        `json:"export"`
	Masked    bool                        `json:"masked,omitempty"`
	Reason    string                      `json:"reason,omitempty"`
	Policies  []ContextualFieldPolicyRule `json:"policies,omitempty"`
}
type ReferencePermission struct {
	SourceObjectKey  string   `json:"source_object_key"`
	RelationFieldKey string   `json:"relation_field_key"`
	TargetObjectKey  string   `json:"target_object_key"`
	DisplayFields    []string `json:"display_fields,omitempty"`
	Mode             string   `json:"mode,omitempty"`
	Reason           string   `json:"reason,omitempty"`
}
type ExportRule struct {
	ObjectKey string   `json:"object_key"`
	Mode      string   `json:"mode"`
	Fields    []string `json:"fields"`
}
