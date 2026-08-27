package identitymodel

type BusinessClaimValue struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type BusinessProfileReference struct {
	BindingKey  string                        `json:"binding_key"`
	ObjectKey   string                        `json:"object_key"`
	RecordID    string                        `json:"record_id"`
	SurfaceKeys []string                      `json:"surface_keys"`
	Claims      map[string]BusinessClaimValue `json:"claims,omitempty"`
}

type IdentityOrganizationScopeFacts struct {
	TeamIDs      []string `json:"team_ids"`
	StoreIDs     []string `json:"store_ids"`
	TerritoryIDs []string `json:"territory_ids"`
	WarehouseIDs []string `json:"warehouse_ids"`
}

type Principal struct {
	UserID                string
	WorkspaceID           string
	WorkforceProfileID    string
	SystemScope           SystemScope
	DepartmentID          string
	DepartmentPath        string
	ReportingPath         string
	ReportingUserIDs      []string
	TeamIDs               []string
	StoreIDs              []string
	TerritoryIDs          []string
	WarehouseIDs          []string
	RequestID             string
	CorrelationID         string
	CausationID           string
	Role                  RoleSchema
	Known                 bool
	BusinessProfiles      []BusinessProfileReference
	ActiveBusinessProfile *BusinessProfileReference
	BusinessClaims        map[string]BusinessClaimValue
	SurfaceKey            string
	AuthorizationRevision string
	AutomationDepth       int
	VisitedRuleKeys       []string
}
