package identitymodel

const IdentityPrincipalContextContractV1 = "domainry-principal-context-v1"

type IdentityPrincipalBusinessProfileContext struct {
	BindingKey  string   `json:"binding_key"`
	ObjectKey   string   `json:"object_key"`
	RecordID    string   `json:"record_id"`
	SurfaceKeys []string `json:"surface_keys"`
	Active      bool     `json:"active"`
}

type IdentityPrincipalRequestContext struct {
	Key                    string            `json:"key"`
	SubjectKind            string            `json:"subject_kind"`
	WorkforceProfileID     string            `json:"workforce_profile_id,omitempty"`
	SurfaceKey             string            `json:"surface_key,omitempty"`
	BusinessProfileKey     string            `json:"business_profile_key,omitempty"`
	BusinessProfileID      string            `json:"business_profile_id,omitempty"`
	CanonicalRequestHeader map[string]string `json:"canonical_request_headers"`
}

// IdentityPrincipalContext is the authenticated, non-secret context contract
// consumed by Runtime clients and project-owned verification tests. It exposes only facts
// and selectors already resolved by Runtime; callers never derive canonical
// identifiers from Handler code or Runtime-owned persistence tables.
type IdentityPrincipalContext struct {
	ContractVersion       string                                    `json:"contract_version"`
	Known                 bool                                      `json:"known"`
	WorkspaceID           string                                    `json:"workspace_id"`
	UserID                string                                    `json:"user_id"`
	RoleKey               string                                    `json:"role_key,omitempty"`
	AuthorizationRevision string                                    `json:"authorization_revision,omitempty"`
	WorkforceProfileID    string                                    `json:"workforce_profile_id,omitempty"`
	DepartmentID          string                                    `json:"department_id,omitempty"`
	DepartmentPath        string                                    `json:"department_path,omitempty"`
	ReportingPath         string                                    `json:"reporting_path,omitempty"`
	ReportingUserIDs      []string                                  `json:"reporting_user_ids"`
	OrganizationScopes    IdentityOrganizationScopeFacts            `json:"organization_scopes"`
	SurfaceKey            string                                    `json:"surface_key,omitempty"`
	BusinessProfiles      []IdentityPrincipalBusinessProfileContext `json:"business_profiles"`
	RequestContexts       []IdentityPrincipalRequestContext         `json:"request_contexts"`
}
