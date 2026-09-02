package contract

import identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

const IdentityAuthoringContractVersion = "runtime-authoring-v1"

type IdentityGovernanceValidationIssue struct {
	Section         string            `json:"section"`
	FieldPath       string            `json:"field_path"`
	ErrorCode       string            `json:"error_code"`
	MessageKey      string            `json:"message_key"`
	CapabilityKey   string            `json:"capability_key"`
	ContractVersion string            `json:"contract_version"`
	Params          map[string]string `json:"params,omitempty"`
}

type IdentityGovernanceValidationRequest struct {
	User             *identitymodel.IdentityUser               `json:"user,omitempty"`
	OrganizationUnit *identitymodel.IdentityOrganizationUnit   `json:"organization_unit,omitempty"`
	RoleAssignment   *identitymodel.IdentityUserRoleAssignment `json:"role_assignment,omitempty"`
	Role             *identitymodel.IdentityRole               `json:"role,omitempty"`
	RoleID           string                                    `json:"role_id,omitempty"`
	PermissionKeys   []string                                  `json:"permission_keys,omitempty"`
	DataScopes       []identitymodel.IdentityDataScopePolicy   `json:"data_scopes,omitempty"`
	FieldPermissions []identitymodel.IdentityFieldPermission   `json:"field_permissions,omitempty"`
	Menu             *identitymodel.IdentityMenu               `json:"menu,omitempty"`
	MenuIDs          []string                                  `json:"menu_ids,omitempty"`
}

type IdentityGovernanceValidationResult struct {
	Valid           bool                                `json:"valid"`
	Errors          []IdentityGovernanceValidationIssue `json:"errors"`
	ContractVersion string                              `json:"contract_version"`
}
