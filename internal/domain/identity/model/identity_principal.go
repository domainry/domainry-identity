package identitymodel

type BusinessClaimValue struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type BusinessProfileReference struct {
	BindingKey string                        `json:"binding_key"`
	ObjectKey  string                        `json:"object_key"`
	RecordID   string                        `json:"record_id"`
	Claims     map[string]BusinessClaimValue `json:"claims,omitempty"`
}

type Principal struct {
	UserID                string
	TenantID              string
	WorkspaceID           string
	SystemScope           SystemScope
	OrgID                 string
	OrgScopeIDs           []string
	SupportOrgID          string
	SupportOrgScopeIDs    []string
	ReportingScopeUserIDs []string
	OrganizationPath      string
	RequestID             string
	CorrelationID         string
	CausationID           string
	Role                  RoleSchema
	Known                 bool
	BusinessProfiles      []BusinessProfileReference
	ActiveBusinessProfile *BusinessProfileReference
	BusinessClaims        map[string]BusinessClaimValue
	AuthorizationRevision string
	AutomationDepth       int
	VisitedRuleKeys       []string
}
