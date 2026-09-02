package contract

import identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

type IdentityFeaturePermissionSnapshot struct {
	RoleKey   string                              `json:"role_key"`
	UserID    string                              `json:"user_id,omitempty"`
	Objects   []IdentityFeatureObjectPermissions  `json:"objects"`
	Actions   []IdentityFeatureActionPermission   `json:"actions"`
	Functions []IdentityFeatureFunctionPermission `json:"function_permissions,omitempty"`
	Data      []IdentityDataScopePermission       `json:"data_permissions,omitempty"`
	Fields    []IdentityFieldPermissionSnapshot   `json:"field_permissions,omitempty"`
	Exports   []IdentityExportPermissionSnapshot  `json:"export_permissions,omitempty"`
}

type IdentityFeatureObjectPermissions struct {
	ObjectKey string                              `json:"object_key"`
	Actions   []IdentityFeaturePermissionDecision `json:"actions"`
}

type IdentityFeatureActionPermission struct {
	Key               string   `json:"key"`
	ObjectKey         string   `json:"object_key"`
	Label             string   `json:"label,omitempty"`
	Kind              string   `json:"kind"`
	PermissionKey     string   `json:"permission_key"`
	DataScope         string   `json:"data_scope"`
	Allowed           bool     `json:"allowed"`
	Reason            string   `json:"reason"`
	AssuranceRequired []string `json:"assurance_required"`
}

type IdentityFeatureFunctionPermission struct {
	Key      string                            `json:"key"`
	Decision IdentityFeaturePermissionDecision `json:"decision"`
}

type IdentityFeaturePermissionDecision struct {
	Key           string `json:"key"`
	ObjectKey     string `json:"object_key,omitempty"`
	Action        string `json:"action,omitempty"`
	PermissionKey string `json:"permission_key,omitempty"`
	DataScope     string `json:"data_scope,omitempty"`
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason"`
}

type IdentityDataScopePermission struct {
	ObjectKey  string                    `json:"object_key"`
	OwnerField string                    `json:"owner_field,omitempty"`
	OrgIDField string                    `json:"org_id_field,omitempty"`
	Context    IdentityDataScopeContext  `json:"context,omitempty"`
	Policy     IdentityDataScopeDecision `json:"policy"`
}

type IdentityDataScopeContext struct {
	OrgID                 string   `json:"org_id,omitempty"`
	OrgScopeIDs           []string `json:"org_scope_ids,omitempty"`
	SupportOrgID          string   `json:"support_org_id,omitempty"`
	SupportOrgScopeIDs    []string `json:"support_org_scope_ids,omitempty"`
	ReportingScopeUserIDs []string `json:"reporting_scope_user_ids,omitempty"`
}

type IdentityDataScopeDecision struct {
	Scope     string                                  `json:"scope"`
	Predicate *identitymodel.IdentityPolicyExpression `json:"predicate,omitempty"`
	Allowed   bool                                    `json:"allowed"`
	Reason    string                                  `json:"reason"`
}

type IdentityFieldPermissionSnapshot struct {
	ObjectKey string                      `json:"object_key"`
	FieldKey  string                      `json:"field_key"`
	FieldType string                      `json:"field_type,omitempty"`
	Read      IdentityFieldAccessDecision `json:"read"`
	Write     IdentityFieldAccessDecision `json:"write"`
	Export    IdentityFieldAccessDecision `json:"export"`
	Masked    bool                        `json:"masked,omitempty"`
	Source    string                      `json:"source"`
}

type IdentityFieldAccessDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type IdentityExportPermissionSnapshot struct {
	ObjectKey string                          `json:"object_key"`
	Allowed   bool                            `json:"allowed"`
	Reason    string                          `json:"reason"`
	DataScope string                          `json:"data_scope"`
	Fields    []IdentityExportFieldPermission `json:"fields"`
}

type IdentityExportFieldPermission struct {
	FieldKey  string                      `json:"field_key"`
	FieldType string                      `json:"field_type,omitempty"`
	Export    IdentityFieldAccessDecision `json:"export"`
	Masked    bool                        `json:"masked,omitempty"`
}
