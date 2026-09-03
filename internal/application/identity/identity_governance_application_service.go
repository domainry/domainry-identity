package identity

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"

	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identitydomain "github.com/domainry/domainry-identity/internal/domain/identity/service"
)

type IdentityGovernanceApplicationService struct {
	objects       func() map[string]definitionmodel.ObjectSchema
	repository    identityrepository.IdentityRepository
	permissions   func() map[string]identitymodel.IdentityPermissionDefinition
	configuration *identitydomain.IdentityConfigurationDomainService
}

func NewIdentityGovernanceApplicationService(repository identityrepository.IdentityRepository, permissions map[string]identitymodel.IdentityPermissionDefinition, objects func() map[string]definitionmodel.ObjectSchema) *IdentityGovernanceApplicationService {
	return NewIdentityGovernanceApplicationServiceWithPermissionSource(repository, func() map[string]identitymodel.IdentityPermissionDefinition { return permissions }, objects)
}

func NewIdentityGovernanceApplicationServiceWithPermissionSource(repository identityrepository.IdentityRepository, permissions func() map[string]identitymodel.IdentityPermissionDefinition, objects func() map[string]definitionmodel.ObjectSchema) *IdentityGovernanceApplicationService {
	return &IdentityGovernanceApplicationService{objects: objects, repository: repository, permissions: permissions, configuration: identitydomain.NewIdentityConfigurationDomainService(repository)}
}

func (validator *IdentityGovernanceApplicationService) Validate(ctx context.Context, request identitycontract.IdentityGovernanceValidationRequest, principal identitymodel.Principal) (identitycontract.IdentityGovernanceValidationResult, error) {
	if err := identityAuthorizeQuery(principal); err != nil {
		return identitycontract.IdentityGovernanceValidationResult{}, err
	}
	if validator == nil || validator.repository == nil || validator.objects == nil {
		return identitycontract.IdentityGovernanceValidationResult{}, internalError("validate identity governance", nil)
	}
	issues := make([]identitycontract.IdentityGovernanceValidationIssue, 0)
	configuration := validator.configuration.ForWorkspace(principal.WorkspaceID)
	if request.User != nil {
		userIssues, err := configuration.ValidateUserConfiguration(ctx, *request.User)
		if err != nil {
			return identitycontract.IdentityGovernanceValidationResult{}, err
		}
		issues = append(issues, userIssues...)
	}
	if request.OrganizationUnit != nil {
		organizationUnitIssues, err := configuration.ValidateOrganizationUnitConfiguration(ctx, *request.OrganizationUnit)
		if err != nil {
			return identitycontract.IdentityGovernanceValidationResult{}, err
		}
		issues = append(issues, organizationUnitIssues...)
	}
	if request.RoleAssignment != nil {
		assignmentIssues, err := configuration.ValidateRoleAssignmentConfiguration(ctx, *request.RoleAssignment)
		if err != nil {
			return identitycontract.IdentityGovernanceValidationResult{}, err
		}
		issues = append(issues, assignmentIssues...)
	}
	if request.Role != nil {
		roleIssues, err := validator.validateRole(ctx, principal.WorkspaceID, *request.Role)
		if err != nil {
			return identitycontract.IdentityGovernanceValidationResult{}, err
		}
		issues = append(issues, roleIssues...)
	}
	roleID := strings.TrimSpace(request.RoleID)
	if roleID != "" {
		roleIssues, err := validator.validateRoleReference(ctx, principal.WorkspaceID, roleID)
		if err != nil {
			return identitycontract.IdentityGovernanceValidationResult{}, err
		}
		issues = append(issues, roleIssues...)
	}
	issues = append(issues, validator.validatePermissions(request.Permissions)...)
	issues = append(issues, validator.validateFieldPermissions(request.FieldPermissions)...)
	if request.Menu != nil {
		menuIssues, err := validator.validateMenu(ctx, principal.WorkspaceID, *request.Menu)
		if err != nil {
			return identitycontract.IdentityGovernanceValidationResult{}, err
		}
		issues = append(issues, menuIssues...)
	}
	menuIssues, err := validator.validateMenuReferences(ctx, principal.WorkspaceID, request.MenuIDs)
	if err != nil {
		return identitycontract.IdentityGovernanceValidationResult{}, err
	}
	issues = append(issues, menuIssues...)
	return identitycontract.IdentityGovernanceValidationResult{Valid: len(issues) == 0, Errors: issues, ContractVersion: identitycontract.IdentityAuthoringContractVersion}, nil
}

func (validator *IdentityGovernanceApplicationService) ValidateRolePermissions(ctx context.Context, roleID string, permissions []identitymodel.RolePermission, principal identitymodel.Principal) error {
	return validator.firstError(ctx, identitycontract.IdentityGovernanceValidationRequest{RoleID: roleID, Permissions: permissions}, principal)
}

func (validator *IdentityGovernanceApplicationService) ValidateRoleFieldPermissions(ctx context.Context, roleID string, values []identitymodel.IdentityFieldPermission, principal identitymodel.Principal) error {
	return validator.firstError(ctx, identitycontract.IdentityGovernanceValidationRequest{RoleID: roleID, FieldPermissions: values}, principal)
}

func (validator *IdentityGovernanceApplicationService) ValidateRoleMenus(ctx context.Context, roleID string, menuIDs []string, principal identitymodel.Principal) error {
	return validator.firstError(ctx, identitycontract.IdentityGovernanceValidationRequest{RoleID: roleID, MenuIDs: menuIDs}, principal)
}

func (validator *IdentityGovernanceApplicationService) ValidateMenu(ctx context.Context, menu identitymodel.IdentityMenu, principal identitymodel.Principal) error {
	return validator.firstError(ctx, identitycontract.IdentityGovernanceValidationRequest{Menu: &menu}, principal)
}

func (validator *IdentityGovernanceApplicationService) ValidateRole(ctx context.Context, role identitymodel.IdentityRole, principal identitymodel.Principal) error {
	return validator.firstError(ctx, identitycontract.IdentityGovernanceValidationRequest{Role: &role}, principal)
}

func (validator *IdentityGovernanceApplicationService) ValidateUser(ctx context.Context, user identitymodel.IdentityUser, principal identitymodel.Principal) error {
	return validator.firstError(ctx, identitycontract.IdentityGovernanceValidationRequest{User: &user}, principal)
}

func (validator *IdentityGovernanceApplicationService) ValidateOrganizationUnit(ctx context.Context, organizationUnit identitymodel.IdentityOrganizationUnit, principal identitymodel.Principal) error {
	return validator.firstError(ctx, identitycontract.IdentityGovernanceValidationRequest{OrganizationUnit: &organizationUnit}, principal)
}

func (validator *IdentityGovernanceApplicationService) ValidateUserRoleAssignment(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, principal identitymodel.Principal) error {
	return validator.firstError(ctx, identitycontract.IdentityGovernanceValidationRequest{RoleAssignment: &assignment}, principal)
}

func (validator *IdentityGovernanceApplicationService) firstError(ctx context.Context, request identitycontract.IdentityGovernanceValidationRequest, principal identitymodel.Principal) error {
	result, err := validator.Validate(ctx, request, principal)
	if err != nil || len(result.Errors) == 0 {
		return err
	}
	issue := result.Errors[0]
	params := make(map[string]string, len(issue.Params)+1)
	for key, value := range issue.Params {
		params[key] = value
	}
	params["field_path"] = issue.FieldPath
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		values = append(values, key, params[key])
	}
	return identityGovernanceBadRequest(issue.ErrorCode, values...)
}

func identityGovernanceBadRequest(code string, params ...string) error {
	values := map[string]string{}
	for index := 0; index+1 < len(params); index += 2 {
		if key := strings.TrimSpace(params[index]); key != "" {
			values[key] = params[index+1]
		}
	}
	return &apperror.AppError{Kind: apperror.KindBadRequest, Code: code, Params: values}
}

func identityGovernanceIssue(section, fieldPath, code, capability string, params map[string]string) identitycontract.IdentityGovernanceValidationIssue {
	return identitycontract.IdentityGovernanceValidationIssue{Section: section, FieldPath: fieldPath, ErrorCode: code, MessageKey: code, CapabilityKey: capability, ContractVersion: identitycontract.IdentityAuthoringContractVersion, Params: params}
}

func (validator *IdentityGovernanceApplicationService) validateRoleReference(ctx context.Context, workspaceID, roleID string) ([]identitycontract.IdentityGovernanceValidationIssue, error) {
	roles, err := validator.repository.ListIdentityRoles(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		if role.ID == roleID {
			return nil, nil
		}
	}
	return []identitycontract.IdentityGovernanceValidationIssue{identityGovernanceIssue("role", "role_id", "backend.identity.role_not_found", "identity.role", map[string]string{"role": roleID, "actual": roleID})}, nil
}

func (validator *IdentityGovernanceApplicationService) validatePermissions(values []identitymodel.RolePermission) []identitycontract.IdentityGovernanceValidationIssue {
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	seen := map[string]bool{}
	permissions := map[string]identitymodel.IdentityPermissionDefinition{}
	if validator.permissions != nil {
		permissions = validator.permissions()
	}
	allowed := make([]string, 0, len(permissions))
	for key, permission := range permissions {
		if permission.DefinitionStatus == identitymodel.IdentityPermissionDefinitionActive && permission.Enabled {
			allowed = append(allowed, key)
		}
	}
	sort.Strings(allowed)
	for index, grant := range values {
		key := strings.TrimSpace(grant.PermissionKey)
		path := fmt.Sprintf("permissions[%d]", index)
		if key == "" {
			issues = append(issues, identityGovernanceIssue("permissions", path+".permission_key", "backend.identity.permission_not_found", "identity.role_permission", map[string]string{"actual": grant.PermissionKey, "allowed": strings.Join(allowed, ",")}))
		} else if seen[key] {
			issues = append(issues, identityGovernanceIssue("permissions", path+".permission_key", "backend.identity.permission_duplicate", "identity.role_permission", map[string]string{"actual": grant.PermissionKey}))
		} else if permission, exists := permissions[key]; !exists {
			issues = append(issues, identityGovernanceIssue("permissions", path+".permission_key", "backend.identity.permission_not_found", "identity.role_permission", map[string]string{"permission": key, "actual": key, "allowed": strings.Join(allowed, ",")}))
		} else if permission.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive {
			issues = append(issues, identityGovernanceIssue("permissions", path+".permission_key", "backend.identity.permission_retired", "identity.role_permission", map[string]string{"permission": key, "actual": key, "allowed": strings.Join(allowed, ",")}))
		} else if !permission.Enabled {
			issues = append(issues, identityGovernanceIssue("permissions", path+".permission_key", "backend.identity.permission_disabled", "identity.role_permission", map[string]string{"permission": key, "actual": key, "allowed": strings.Join(allowed, ",")}))
		}
		if _, valid := identitymodel.CanonicalIdentityDataScope(string(grant.DataScope)); !valid {
			issues = append(issues, identityGovernanceIssue("permissions", path+".data_scope", "backend.identity.data_scope_invalid", "identity.role_permission", map[string]string{"actual": string(grant.DataScope), "allowed": strings.Join(identitymodel.AuthoringDataScopeValues(), ",")}))
		}
		seen[key] = true
	}
	return issues
}

func internalError(operation string, err error) error {
	return &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.internal", Params: map[string]string{"operation": operation}, Err: err}
}

func (validator *IdentityGovernanceApplicationService) businessObjects() map[string]definitionmodel.ObjectSchema {
	values := validator.objects()
	objects := make(map[string]definitionmodel.ObjectSchema, len(values))
	for key, object := range values {
		objects[key] = object
	}
	return objects
}
