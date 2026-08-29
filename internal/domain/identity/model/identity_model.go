package identitymodel

type IdentityStatus string

const (
	IdentityStatusActive   IdentityStatus = "active"
	IdentityStatusDisabled IdentityStatus = "disabled"
	IdentityStatusDeleted  IdentityStatus = "deleted"
)

type IdentityDataScope string

type IdentityAccountType string

const (
	IdentityAccountHuman      IdentityAccountType = "human"
	IdentityAccountService    IdentityAccountType = "service"
	IdentityAccountAutomation IdentityAccountType = "automation"
)

type IdentityDepartment struct {
	ID                       string         `json:"id"`
	Name                     string         `json:"name"`
	ParentID                 *string        `json:"parent_id,omitempty"`
	LeaderWorkforceProfileID string         `json:"leader_workforce_profile_id,omitempty"`
	Path                     string         `json:"path"`
	AncestorIDs              []string       `json:"ancestor_ids"`
	Depth                    int            `json:"depth"`
	SortOrder                int            `json:"sort_order"`
	Status                   IdentityStatus `json:"status,omitempty"`
}

type IdentityUser struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	GivenName   string              `json:"given_name,omitempty"`
	MiddleName  string              `json:"middle_name,omitempty"`
	FamilyName  string              `json:"family_name,omitempty"`
	NamePrefix  string              `json:"name_prefix,omitempty"`
	NameSuffix  string              `json:"name_suffix,omitempty"`
	NativeName  string              `json:"native_name,omitempty"`
	NameLocale  string              `json:"name_locale,omitempty"`
	Email       string              `json:"email"`
	Phone       string              `json:"phone,omitempty"`
	AccountType IdentityAccountType `json:"account_type"`
	Locale      string              `json:"locale,omitempty"`
	Timezone    string              `json:"timezone,omitempty"`
	Status      IdentityStatus      `json:"status"`
	Version     int64               `json:"version"`
	CreatedAt   string              `json:"created_at"`
	UpdatedAt   string              `json:"updated_at"`
}

type IdentityUserPage struct {
	Items    []IdentityUser `json:"items"`
	PageSize int            `json:"page_size"`
	Total    int            `json:"total"`
	HasNext  bool           `json:"has_next"`
	NextID   string         `json:"next_id,omitempty"`
}

type IdentityUserDeletionImpact struct {
	UserID                        string                        `json:"user_id"`
	ProfileBindings               []IdentityProfileBinding      `json:"profile_bindings"`
	WorkforceProfileIDs           []string                      `json:"workforce_profile_ids"`
	ActiveRoleIDs                 []string                      `json:"active_role_ids"`
	BusinessProfileReferences     []IdentityUserRecordReference `json:"business_profile_references"`
	OwnedRecordReferences         []IdentityUserRecordReference `json:"owned_record_references"`
	PendingApprovalTaskIDs        []string                      `json:"pending_approval_task_ids"`
	RetainedAuditEventIDs         []string                      `json:"retained_audit_event_ids"`
	ActiveLegalHoldIDs            []string                      `json:"active_legal_hold_ids"`
	Blockers                      []string                      `json:"blockers"`
	CredentialsAndSessionsRevoked bool                          `json:"credentials_and_sessions_revoked"`
	CanDelete                     bool                          `json:"can_delete"`
}

type IdentityUserDisableImpact struct {
	UserID                   string                   `json:"user_id"`
	ProfileBindings          []IdentityProfileBinding `json:"profile_bindings"`
	WorkforceProfileIDs      []string                 `json:"workforce_profile_ids"`
	ActiveEntitlementRoleIDs []string                 `json:"active_entitlement_role_ids"`
	SessionsWillBeRevoked    bool                     `json:"sessions_will_be_revoked"`
	BusinessFactsPreserved   bool                     `json:"business_facts_preserved"`
}

type IdentityUserRecordReference struct {
	ObjectKey string `json:"object_key"`
	FieldKey  string `json:"field_key"`
	Count     int    `json:"count"`
}

type IdentityPermissionDefinition struct {
	Key                   string                          `json:"key"`
	Label                 string                          `json:"label"`
	System                string                          `json:"system"`
	Resource              string                          `json:"resource"`
	ResourceLabel         string                          `json:"resource_label"`
	Action                string                          `json:"action"`
	Category              string                          `json:"category"`
	Description           string                          `json:"description,omitempty"`
	SourceType            string                          `json:"source_type,omitempty"`
	SourceActionKey       string                          `json:"source_action_key,omitempty"`
	ObjectKey             string                          `json:"object_key,omitempty"`
	ActionLabel           string                          `json:"action_label,omitempty"`
	AuthorizationStrategy string                          `json:"authorization_strategy,omitempty"`
	RiskLevel             string                          `json:"risk_level,omitempty"`
	ApprovalRequired      bool                            `json:"approval_required,omitempty"`
	AssuranceRequired     []string                        `json:"assurance_required,omitempty"`
	LifecycleStatus       string                          `json:"lifecycle_status,omitempty"`
	ActionUsages          []IdentityActionPermissionUsage `json:"action_usages,omitempty"`
}

type IdentityActionPermissionUsage struct {
	ActionKey             string   `json:"action_key"`
	ObjectKey             string   `json:"object_key"`
	ActionLabel           string   `json:"action_label"`
	AuthorizationStrategy string   `json:"authorization_strategy"`
	RiskLevel             string   `json:"risk_level"`
	ApprovalRequired      bool     `json:"approval_required"`
	AssuranceRequired     []string `json:"assurance_required"`
	LifecycleStatus       string   `json:"lifecycle_status"`
}

type IdentityRole struct {
	ID          string         `json:"id"`
	Key         string         `json:"key"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	Status      IdentityStatus `json:"status"`
}

type IdentityRolePage struct {
	Items    []IdentityRole `json:"items"`
	PageSize int            `json:"page_size"`
	Total    int            `json:"total"`
	HasNext  bool           `json:"has_next"`
	NextID   string         `json:"next_id,omitempty"`
}

type IdentityMenu struct {
	ID          string         `json:"id"`
	Key         string         `json:"key"`
	Label       string         `json:"label"`
	Description string         `json:"description,omitempty"`
	Route       string         `json:"route,omitempty"`
	Icon        string         `json:"icon,omitempty"`
	ParentID    string         `json:"parent_id,omitempty"`
	SortOrder   int            `json:"sort_order"`
	Status      IdentityStatus `json:"status"`
}

type IdentityRoleMenuAssignment struct {
	RoleID string `json:"role_id"`
	MenuID string `json:"menu_id"`
}

type IdentityDataScopePolicy struct {
	Resource    string                    `json:"resource"`
	Scope       IdentityDataScope         `json:"scope"`
	AuditDenial bool                      `json:"audit_denial,omitempty"`
	Predicate   *IdentityPolicyExpression `json:"predicate,omitempty"`
}

type IdentityFieldPermission struct {
	Resource string                      `json:"resource"`
	Field    string                      `json:"field"`
	Visible  bool                        `json:"visible"`
	Editable bool                        `json:"editable"`
	Masked   bool                        `json:"masked,omitempty"`
	Policies []ContextualFieldPolicyRule `json:"policies,omitempty"`
}

type IdentityUserRoleAssignment struct {
	UserID             string  `json:"user_id"`
	RoleID             string  `json:"role_id"`
	WorkforceProfileID string  `json:"workforce_profile_id,omitempty"`
	BindingKey         string  `json:"binding_key,omitempty"`
	ProfileID          string  `json:"profile_id,omitempty"`
	Source             string  `json:"source,omitempty"`
	Status             string  `json:"status,omitempty"`
	ValidFrom          string  `json:"valid_from,omitempty"`
	ValidUntil         string  `json:"valid_until,omitempty"`
	GrantedBy          string  `json:"granted_by,omitempty"`
	GrantReason        string  `json:"grant_reason,omitempty"`
	RevokedBy          string  `json:"revoked_by,omitempty"`
	RevokedAt          string  `json:"revoked_at,omitempty"`
	RevokeReason       string  `json:"revoke_reason,omitempty"`
	CreatedAt          string  `json:"created_at,omitempty"`
	UpdatedAt          string  `json:"updated_at,omitempty"`
	ExpiresAt          *string `json:"expires_at,omitempty"`
}

type IdentityUserRoleAssignmentPage struct {
	Items    []IdentityUserRoleAssignment `json:"items"`
	PageSize int                          `json:"page_size"`
	Total    int                          `json:"total"`
	HasNext  bool                         `json:"has_next"`
	NextID   string                       `json:"next_id,omitempty"`
}

type IdentityRoleRequest struct {
	ID              string   `json:"id"`
	UserID          string   `json:"user_id"`
	RequestedBy     string   `json:"requested_by,omitempty"`
	Provider        string   `json:"provider,omitempty"`
	ProviderSubject string   `json:"provider_subject,omitempty"`
	RoleIDs         []string `json:"role_ids"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
	ReviewedBy      string   `json:"reviewed_by,omitempty"`
	ReviewedAt      string   `json:"reviewed_at,omitempty"`
	ReviewNote      string   `json:"review_note,omitempty"`
}

type IdentityRolePermissionAssignment struct {
	RoleID        string `json:"role_id"`
	PermissionKey string `json:"permission_key"`
}

type IdentityCredential struct {
	UserID             string `json:"user_id"`
	PasswordHash       string `json:"password_hash"`
	PasswordUpdatedAt  string `json:"password_updated_at,omitempty"`
	FailedLoginCount   int    `json:"failed_login_count"`
	LockedUntil        string `json:"locked_until,omitempty"`
	LastLoginAt        string `json:"last_login_at,omitempty"`
	MustChangePassword bool   `json:"must_change_password"`
}

type AuthRefreshToken struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	SessionID    string `json:"session_id"`
	Audience     string `json:"audience"`
	TokenHash    string `json:"token_hash"`
	ExpiresAt    string `json:"expires_at"`
	RevokedAt    string `json:"revoked_at,omitempty"`
	ReplacedByID string `json:"replaced_by_id,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	LastUsedAt   string `json:"last_used_at,omitempty"`
}

type IdentityExternalAccount struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	Provider        string `json:"provider"`
	ProviderSubject string `json:"provider_subject"`
	Email           string `json:"email,omitempty"`
	Phone           string `json:"phone,omitempty"`
	DisplayName     string `json:"display_name,omitempty"`
	AvatarURL       string `json:"avatar_url,omitempty"`
	Metadata        string `json:"metadata,omitempty"`
	LinkedAt        string `json:"linked_at,omitempty"`
}

type IdentityMFAFactor struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	Type        string `json:"type"`
	Label       string `json:"label,omitempty"`
	Provider    string `json:"provider,omitempty"`
	ProviderRef string `json:"provider_ref,omitempty"`
	Status      string `json:"status"`
	VerifiedAt  string `json:"verified_at,omitempty"`
	LastUsedAt  string `json:"last_used_at,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}
