package service

import (
	"context"
	"net/mail"
	"sort"
	"strings"
	"time"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type IdentityConfigurationDomainService struct {
	repository identityrepository.IdentityRepository
	workspace  string
}

func (s *IdentityConfigurationDomainService) ForWorkspace(workspaceID string) *IdentityConfigurationDomainService {
	return &IdentityConfigurationDomainService{repository: s.repository, workspace: workspaceID}
}

func NewIdentityConfigurationDomainService(repository identityrepository.IdentityRepository) *IdentityConfigurationDomainService {
	return &IdentityConfigurationDomainService{repository: repository}
}

func (s *IdentityConfigurationDomainService) ValidateUserConfiguration(ctx context.Context, user identitymodel.IdentityUser) ([]identitycontract.IdentityGovernanceValidationIssue, error) {
	user.ID, user.Name = strings.TrimSpace(user.ID), strings.TrimSpace(user.Name)
	user.Email = strings.ToLower(strings.TrimSpace(user.Email))
	issues := make([]identitycontract.IdentityGovernanceValidationIssue, 0)
	if user.ID == "" {
		issues = append(issues, identityConfigurationIssue("user.id", "backend.identity.user_required", "identity.user", map[string]string{"actual": user.ID}))
	} else if strings.Contains(user.ID, "/") {
		issues = append(issues, identityConfigurationIssue("user.id", "backend.identity.user_path_unsafe", "identity.user", map[string]string{"actual": user.ID}))
	}
	if user.Name == "" {
		issues = append(issues, identityConfigurationIssue("user.name", "backend.identity.user_name_required", "identity.user", map[string]string{"actual": user.Name}))
	}
	if user.Email == "" {
		issues = append(issues, identityConfigurationIssue("user.email", "backend.identity.user_email_required", "identity.user", map[string]string{"actual": user.Email}))
	} else if address, err := mail.ParseAddress(user.Email); err != nil || !strings.EqualFold(address.Address, user.Email) {
		issues = append(issues, identityConfigurationIssue("user.email", "backend.identity.user_email_invalid", "identity.user", map[string]string{"actual": user.Email, "expected": "email"}))
	}
	if user.Status != "" && user.Status != identitymodel.IdentityStatusActive && user.Status != identitymodel.IdentityStatusDisabled {
		issues = append(issues, identityConfigurationIssue("user.status", "backend.identity.user_status_invalid", "identity.user", map[string]string{"actual": string(user.Status), "allowed": "active,disabled"}))
	}
	if user.AccountType != "" && user.AccountType != identitymodel.IdentityAccountHuman && user.AccountType != identitymodel.IdentityAccountService && user.AccountType != identitymodel.IdentityAccountAutomation {
		issues = append(issues, identityConfigurationIssue("user.account_type", "backend.identity.user_account_type_invalid", "identity.user", map[string]string{"actual": string(user.AccountType), "allowed": "human,service,automation"}))
	}
	if timezone := strings.TrimSpace(user.Timezone); timezone != "" {
		if _, err := time.LoadLocation(timezone); err != nil {
			issues = append(issues, identityConfigurationIssue("user.timezone", "backend.identity.user_timezone_invalid", "identity.user", map[string]string{"actual": timezone, "expected": "IANA timezone"}))
		}
	}
	users, err := s.repository.ListIdentityUsers(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	issues = append(issues, validateUserUniqueness(user, users)...)
	return issues, nil
}

func validateUserUniqueness(user identitymodel.IdentityUser, users []identitymodel.IdentityUser) []identitycontract.IdentityGovernanceValidationIssue {
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	for _, existing := range users {
		if existing.ID == user.ID {
			continue
		}
		if user.Email != "" && strings.EqualFold(strings.TrimSpace(existing.Email), user.Email) {
			issues = append(issues, identityConfigurationIssue("user.email", "backend.identity.user_email_exists", "identity.user", map[string]string{"actual": user.Email}))
		}
	}
	return issues
}

func (s *IdentityConfigurationDomainService) ValidateDepartmentConfiguration(ctx context.Context, department identitymodel.IdentityDepartment) ([]identitycontract.IdentityGovernanceValidationIssue, error) {
	department.ID, department.Name = strings.TrimSpace(department.ID), strings.TrimSpace(department.Name)
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	if department.ID == "" {
		issues = append(issues, identityConfigurationIssue("department.id", "backend.identity.department_id_required", "identity.department", map[string]string{"actual": department.ID}))
	}
	if department.Name == "" {
		issues = append(issues, identityConfigurationIssue("department.name", "backend.identity.department_name_required", "identity.department", map[string]string{"actual": department.Name}))
	}
	if department.Status != "" && department.Status != identitymodel.IdentityStatusActive && department.Status != identitymodel.IdentityStatusDisabled {
		issues = append(issues, identityConfigurationIssue("department.status", "backend.identity.department_status_invalid", "identity.department", map[string]string{"actual": string(department.Status), "allowed": "active,disabled"}))
	}
	departments, err := s.repository.ListIdentityDepartments(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	issues = append(issues, validateDepartmentParent(department, departments)...)
	for _, existing := range departments {
		if existing.ID != department.ID && identityConfigurationParentID(existing.ParentID) == identityConfigurationParentID(department.ParentID) && strings.EqualFold(strings.TrimSpace(existing.Name), department.Name) {
			issues = append(issues, identityConfigurationIssue("department.name", "backend.identity.department_name_exists", "identity.department", map[string]string{"actual": department.Name}))
		}
	}
	return issues, nil
}

func validateDepartmentParent(department identitymodel.IdentityDepartment, departments []identitymodel.IdentityDepartment) []identitycontract.IdentityGovernanceValidationIssue {
	parentID := identityConfigurationParentID(department.ParentID)
	if parentID == "" {
		return nil
	}
	if parentID == department.ID {
		return []identitycontract.IdentityGovernanceValidationIssue{identityConfigurationIssue("department.parent_id", "backend.identity.department_parent_self", "identity.department", map[string]string{"actual": parentID})}
	}
	byID := make(map[string]identitymodel.IdentityDepartment, len(departments))
	for _, existing := range departments {
		byID[existing.ID] = existing
	}
	parent, exists := byID[parentID]
	if !exists {
		return []identitycontract.IdentityGovernanceValidationIssue{identityConfigurationIssue("department.parent_id", "backend.identity.parent_department_not_found", "identity.department", map[string]string{"actual": parentID})}
	}
	seen := map[string]bool{department.ID: true}
	for {
		if seen[parent.ID] {
			return []identitycontract.IdentityGovernanceValidationIssue{identityConfigurationIssue("department.parent_id", "backend.identity.department_cycle", "identity.department", map[string]string{"actual": parentID})}
		}
		seen[parent.ID] = true
		nextID := identityConfigurationParentID(parent.ParentID)
		if nextID == "" {
			return nil
		}
		next, exists := byID[nextID]
		if !exists {
			return nil
		}
		parent = next
	}
}

func (s *IdentityConfigurationDomainService) ValidateRoleAssignmentConfiguration(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment) ([]identitycontract.IdentityGovernanceValidationIssue, error) {
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	if _, exists, err := s.repository.GetIdentityUser(ctx, s.workspace, strings.TrimSpace(assignment.UserID)); err != nil {
		return nil, err
	} else if !exists {
		issues = append(issues, identityConfigurationIssue("role_assignment.user_id", "backend.identity.user_not_found", "identity.user_role_assignment", map[string]string{"actual": assignment.UserID}))
	}
	if _, exists, err := s.identityRoleByID(ctx, strings.TrimSpace(assignment.RoleID)); err != nil {
		return nil, err
	} else if !exists {
		issues = append(issues, identityConfigurationIssue("role_assignment.role_id", "backend.identity.role_not_found", "identity.user_role_assignment", map[string]string{"actual": assignment.RoleID}))
	}
	if assignment.ExpiresAt != nil && strings.TrimSpace(*assignment.ExpiresAt) != "" {
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(*assignment.ExpiresAt)); err != nil {
			issues = append(issues, identityConfigurationIssue("role_assignment.expires_at", "backend.identity.assignment_expires_at_invalid", "identity.user_role_assignment", map[string]string{"actual": *assignment.ExpiresAt, "expected": time.RFC3339}))
		}
	}
	for fieldPath, value := range map[string]string{
		"role_assignment.valid_from":  assignment.ValidFrom,
		"role_assignment.valid_until": assignment.ValidUntil,
		"role_assignment.revoked_at":  assignment.RevokedAt,
	} {
		if value = strings.TrimSpace(value); value != "" {
			if _, err := time.Parse(time.RFC3339, value); err != nil {
				issues = append(issues, identityConfigurationIssue(fieldPath, "backend.identity.assignment_time_invalid", "identity.user_role_assignment", map[string]string{"actual": value, "expected": time.RFC3339}))
			}
		}
	}
	if source := strings.TrimSpace(assignment.Source); source != "" && !map[string]bool{"manual": true, "profile_binding": true, "idp_sync": true, "governance_request": true, "import": true, "bootstrap": true}[source] {
		issues = append(issues, identityConfigurationIssue("role_assignment.source", "backend.identity.assignment_source_invalid", "identity.user_role_assignment", map[string]string{"actual": source}))
	}
	if status := strings.TrimSpace(assignment.Status); status != "" && !map[string]bool{"pending": true, "active": true, "suspended": true, "revoked": true, "expired": true}[status] {
		issues = append(issues, identityConfigurationIssue("role_assignment.status", "backend.identity.assignment_status_invalid", "identity.user_role_assignment", map[string]string{"actual": status}))
	}
	return issues, nil
}

func (s *IdentityConfigurationDomainService) identityRoleByID(ctx context.Context, roleID string) (identitymodel.IdentityRole, bool, error) {
	roles, err := s.repository.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityRole{}, false, err
	}
	for _, role := range roles {
		if role.ID == roleID {
			return role, true, nil
		}
	}
	return identitymodel.IdentityRole{}, false, nil
}

func (s *IdentityConfigurationDomainService) FirstConfigurationError(issues []identitycontract.IdentityGovernanceValidationIssue) error {
	if len(issues) == 0 {
		return nil
	}
	issue := issues[0]
	values := []string{"field_path", issue.FieldPath}
	keys := make([]string, 0, len(issue.Params))
	for key := range issue.Params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, key, issue.Params[key])
	}
	return badRequest(issue.ErrorCode, values...)
}

func identityConfigurationIssue(fieldPath, code, capability string, params map[string]string) identitycontract.IdentityGovernanceValidationIssue {
	section, _, _ := strings.Cut(fieldPath, ".")
	return identitycontract.IdentityGovernanceValidationIssue{Section: section, FieldPath: fieldPath, ErrorCode: code, MessageKey: code, CapabilityKey: capability, ContractVersion: identitycontract.IdentityAuthoringContractVersion, Params: params}
}

func identityConfigurationParentID(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
