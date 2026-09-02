package identitymodel

// IdentityGrantSource explains one stable path that contributes to effective
// access. It contains identifiers and lifecycle facts only; it never contains
// record values or business-profile claims.
type IdentityGrantSource struct {
	Type               string `json:"type"`
	Key                string `json:"key"`
	RoleID             string `json:"role_id,omitempty"`
	RoleKey            string `json:"role_key,omitempty"`
	PermissionSetKey   string `json:"permission_set_key,omitempty"`
	PermissionSetGroup string `json:"permission_set_group_key,omitempty"`
	AssignmentSource   string `json:"assignment_source,omitempty"`
	BindingKey         string `json:"binding_key,omitempty"`
	ProfileID          string `json:"profile_id,omitempty"`
	ValidFrom          string `json:"valid_from,omitempty"`
	ValidUntil         string `json:"valid_until,omitempty"`
	ExpiresAt          string `json:"expires_at,omitempty"`
}

type IdentityEffectivePermissionGrant struct {
	Key       string                `json:"key"`
	ObjectKey string                `json:"object_key,omitempty"`
	Action    string                `json:"action,omitempty"`
	Sources   []IdentityGrantSource `json:"sources"`
}

type IdentityEffectiveDataAccess struct {
	ObjectKey   string                    `json:"object_key"`
	Allowed     bool                      `json:"allowed"`
	Scope       string                    `json:"scope"`
	Scopes      []string                  `json:"scopes"`
	Predicate   *IdentityPolicyExpression `json:"predicate,omitempty"`
	AuditDenial bool                      `json:"audit_denial,omitempty"`
	Sources     []IdentityGrantSource     `json:"sources"`
}

type IdentityEffectiveFieldAccess struct {
	ObjectKey string                      `json:"object_key"`
	FieldKey  string                      `json:"field_key"`
	Read      bool                        `json:"read"`
	Write     bool                        `json:"write"`
	Export    bool                        `json:"export"`
	Masked    bool                        `json:"masked,omitempty"`
	Reason    string                      `json:"reason,omitempty"`
	Policies  []ContextualFieldPolicyRule `json:"policies,omitempty"`
	Sensitive bool                        `json:"sensitive,omitempty"`
	Sources   []IdentityGrantSource       `json:"sources"`
}

type IdentityEffectiveAccessSnapshot struct {
	UserID                string                             `json:"user_id"`
	Known                 bool                               `json:"known"`
	AuthorizationRevision string                             `json:"authorization_revision,omitempty"`
	OrgID                 string                             `json:"org_id,omitempty"`
	SupportOrgID          string                             `json:"support_org_id,omitempty"`
	SupportOrgScopeIDs    []string                           `json:"support_org_scope_ids,omitempty"`
	OrganizationPath      string                             `json:"organization_path,omitempty"`
	BusinessProfiles      []BusinessProfileReference         `json:"business_profiles"`
	RoleAssignments       []IdentityUserRoleAssignment       `json:"role_assignments"`
	RoleKeys              []string                           `json:"role_keys"`
	PermissionSetKeys     []string                           `json:"permission_set_keys"`
	PermissionSetGroups   []string                           `json:"permission_set_group_keys"`
	GuardrailKeys         []string                           `json:"guardrail_keys"`
	Permissions           []IdentityEffectivePermissionGrant `json:"permissions"`
	DataAccess            []IdentityEffectiveDataAccess      `json:"data_access"`
	FieldAccess           []IdentityEffectiveFieldAccess     `json:"field_access"`
	ReferencePermissions  []ReferencePermission              `json:"reference_permissions"`
	ExportRules           []ExportRule                       `json:"export_rules"`
	Menus                 []IdentityMenu                     `json:"menus"`
}

type IdentityAccessExplainRequest struct {
	UserID    string `json:"user_id"`
	ObjectKey string `json:"object_key,omitempty"`
	Action    string `json:"action,omitempty"`
	FieldKey  string `json:"field_key,omitempty"`
	RecordID  string `json:"record_id,omitempty"`
}

type IdentityAccessReason struct {
	Code     string                 `json:"code"`
	Effect   string                 `json:"effect"`
	Layer    string                 `json:"layer"`
	Subject  string                 `json:"subject,omitempty"`
	Details  map[string]string      `json:"details,omitempty"`
	Sources  []IdentityGrantSource  `json:"sources,omitempty"`
	Children []IdentityAccessReason `json:"children,omitempty"`
}

type IdentityAccessExplainResult struct {
	UserID                string               `json:"user_id"`
	ObjectKey             string               `json:"object_key,omitempty"`
	Action                string               `json:"action,omitempty"`
	FieldKey              string               `json:"field_key,omitempty"`
	RecordID              string               `json:"record_id,omitempty"`
	Allowed               bool                 `json:"allowed"`
	AuthorizationRevision string               `json:"authorization_revision,omitempty"`
	Reason                IdentityAccessReason `json:"reason"`
}

type IdentityRoleChangeImpactRequest struct {
	RoleKey string     `json:"role_key"`
	Role    RoleSchema `json:"role"`
}

type IdentityRoleChangeImpact struct {
	RoleKey              string   `json:"role_key"`
	AffectedUserCount    int      `json:"affected_user_count"`
	ProfileTypes         []string `json:"profile_types"`
	AddedPermissions     []string `json:"added_permissions"`
	RemovedPermissions   []string `json:"removed_permissions"`
	AffectedObjects      []string `json:"affected_objects"`
	AffectedActions      []string `json:"affected_actions"`
	SensitiveFields      []string `json:"sensitive_fields"`
	HighRiskCapabilities []string `json:"high_risk_capabilities"`
}

type IdentityGovernanceReports struct {
	OrphanPermissions   []string                     `json:"orphan_permissions"`
	RolesWithoutMembers []string                     `json:"roles_without_members"`
	ExpiredEntitlements []IdentityUserRoleAssignment `json:"expired_entitlements"`
	UnboundAssignments  []IdentityUserRoleAssignment `json:"unbound_assignments"`
	AuthorizationDrift  []string                     `json:"authorization_drift"`
}

type IdentityAccessReverseIndex struct {
	UserRoles         map[string][]string `json:"user_roles"`
	RolePermissions   map[string][]string `json:"role_permissions"`
	PermissionRoles   map[string][]string `json:"permission_roles"`
	ObjectActionRoles map[string][]string `json:"object_action_roles"`
}
