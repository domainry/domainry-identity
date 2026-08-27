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
	ObjectKey           string                    `json:"object_key"`
	OwnerField          string                    `json:"owner_field,omitempty"`
	DepartmentIDField   string                    `json:"department_id_field,omitempty"`
	DepartmentPathField string                    `json:"department_path_field,omitempty"`
	TeamField           string                    `json:"team_field,omitempty"`
	StoreField          string                    `json:"store_field,omitempty"`
	TerritoryField      string                    `json:"territory_field,omitempty"`
	WarehouseField      string                    `json:"warehouse_field,omitempty"`
	Context             IdentityDataScopeContext  `json:"context,omitempty"`
	Read                IdentityDataScopeDecision `json:"read"`
	Write               IdentityDataScopeDecision `json:"write"`
}

type IdentityDataScopeContext struct {
	TeamIDs        []string `json:"team_ids,omitempty"`
	StoreIDs       []string `json:"store_ids,omitempty"`
	TerritoryIDs   []string `json:"territory_ids,omitempty"`
	WarehouseIDs   []string `json:"warehouse_ids,omitempty"`
	DepartmentPath string   `json:"department_path,omitempty"`
	ReportingPath  string   `json:"reporting_path,omitempty"`
}

type IdentityDataScopeDecision struct {
	Action    string                                  `json:"action"`
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
