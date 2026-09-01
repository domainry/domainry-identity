package identitymodel

type IdentityActionAuthorizationStrategy string

const (
	IdentityActionStaticAll IdentityActionAuthorizationStrategy = "static_all"
)

type IdentityHTTPActionBinding struct {
	Method               string `json:"method"`
	RouteTemplate        string `json:"route_template"`
	DisplayRouteTemplate string `json:"display_route_template,omitempty"`
}

type IdentityPageActionBinding struct {
	Route string `json:"route"`
	Label string `json:"label,omitempty"`
}

type IdentityOwnedPermissionDefinition struct {
	Key         string `json:"key"`
	ResourceKey string `json:"resource_key"`
	ActionKey   string `json:"action_key"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category"`
}

// IdentityActionDefinition is the S0 code-owned executable authorization
// declaration. It intentionally remains internal to Identity until Batch B
// promotes the validated shape into the shared Foundation contract.
type IdentityActionDefinition struct {
	Key                   string                              `json:"key"`
	Owner                 string                              `json:"owner"`
	SourceKind            string                              `json:"source_kind"`
	CapabilityKey         string                              `json:"capability_key"`
	CapabilityLabel       string                              `json:"capability_label"`
	OperationKey          string                              `json:"operation_key"`
	OperationLabel        string                              `json:"operation_label"`
	Label                 string                              `json:"label"`
	Exposure              string                              `json:"exposure"`
	AuthorizationStrategy IdentityActionAuthorizationStrategy `json:"authorization_strategy"`
	HTTP                  IdentityHTTPActionBinding           `json:"http"`
	Page                  *IdentityPageActionBinding          `json:"page,omitempty"`
	RequiredPermissions   []string                            `json:"required_permissions"`
	OwnedPermissions      []IdentityOwnedPermissionDefinition `json:"owned_permissions,omitempty"`
	RiskLevel             string                              `json:"risk_level"`
	ApprovalRequired      bool                                `json:"approval_required"`
	AssuranceRequired     []string                            `json:"assurance_required,omitempty"`
	AuditClass            string                              `json:"audit_class"`
	LifecycleStatus       string                              `json:"lifecycle_status"`
}
