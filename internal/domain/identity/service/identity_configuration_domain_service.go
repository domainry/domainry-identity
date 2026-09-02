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
	if user.WorkerType != "" && user.WorkerType != identitymodel.IdentityWorkerEmployee && user.WorkerType != identitymodel.IdentityWorkerContractor && user.WorkerType != identitymodel.IdentityWorkerPartnerStaff && user.WorkerType != identitymodel.IdentityWorkerTemporary {
		issues = append(issues, identityConfigurationIssue("user.worker_type", "backend.identity.user_worker_type_invalid", "identity.user", map[string]string{"actual": string(user.WorkerType)}))
	}
	if user.WorkStatus != "" && user.WorkStatus != identitymodel.IdentityWorkPending && user.WorkStatus != identitymodel.IdentityWorkActive && user.WorkStatus != identitymodel.IdentityWorkSuspended && user.WorkStatus != identitymodel.IdentityWorkTerminated {
		issues = append(issues, identityConfigurationIssue("user.work_status", "backend.identity.user_work_status_invalid", "identity.user", map[string]string{"actual": string(user.WorkStatus)}))
	}
	for field, value := range map[string]string{"user.start_date": user.StartDate, "user.end_date": user.EndDate} {
		if value = strings.TrimSpace(value); value != "" {
			if _, err := time.Parse("2006-01-02", value); err != nil {
				issues = append(issues, identityConfigurationIssue(field, "backend.identity.user_work_date_invalid", "identity.user", map[string]string{"actual": value}))
			}
		}
	}
	if strings.TrimSpace(user.StartDate) != "" && strings.TrimSpace(user.EndDate) != "" && user.EndDate < user.StartDate {
		issues = append(issues, identityConfigurationIssue("user.end_date", "backend.identity.user_work_period_invalid", "identity.user", nil))
	}
	organizationUnitID := strings.TrimSpace(user.OrgID)
	supportOrganizationUnitID := strings.TrimSpace(user.SupportOrgID)
	if organizationUnitID != "" || supportOrganizationUnitID != "" {
		units, err := s.repository.ListIdentityOrganizationUnits(ctx, s.workspace)
		if err != nil {
			return nil, err
		}
		unitsByID := make(map[string]identitymodel.IdentityOrganizationUnit, len(units))
		for _, unit := range units {
			unitsByID[strings.TrimSpace(unit.ID)] = unit
		}
		if _, found := unitsByID[organizationUnitID]; organizationUnitID != "" && !found {
			issues = append(issues, identityConfigurationIssue("user.org_id", "backend.identity.organization_unit_not_found", "identity.user", map[string]string{"actual": organizationUnitID}))
		}
		if unit, found := unitsByID[supportOrganizationUnitID]; supportOrganizationUnitID != "" && (!found || unit.Status == identitymodel.IdentityStatusDisabled) {
			issues = append(issues, identityConfigurationIssue("user.support_org_id", "backend.identity.support_organization_unit_not_found", "identity.user", map[string]string{"actual": supportOrganizationUnitID}))
		}
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
	managerUserID := strings.TrimSpace(user.ManagerUserID)
	if managerUserID != "" {
		if managerUserID == user.ID {
			issues = append(issues, identityConfigurationIssue("user.manager_user_id", "backend.identity.user_manager_self_reference", "identity.user", map[string]string{"actual": managerUserID}))
		} else {
			byID := make(map[string]identitymodel.IdentityUser, len(users))
			for _, existing := range users {
				byID[existing.ID] = existing
			}
			manager, found := byID[managerUserID]
			if !found || manager.Status != identitymodel.IdentityStatusActive || manager.WorkStatus == identitymodel.IdentityWorkTerminated {
				issues = append(issues, identityConfigurationIssue("user.manager_user_id", "backend.identity.user_manager_invalid", "identity.user", map[string]string{"actual": managerUserID}))
			} else {
				visited := map[string]bool{user.ID: true}
				for cursor := managerUserID; cursor != ""; {
					if visited[cursor] {
						issues = append(issues, identityConfigurationIssue("user.manager_user_id", "backend.identity.user_reporting_cycle", "identity.user", map[string]string{"actual": managerUserID}))
						break
					}
					visited[cursor] = true
					ancestor, exists := byID[cursor]
					if !exists {
						issues = append(issues, identityConfigurationIssue("user.manager_user_id", "backend.identity.user_manager_invalid", "identity.user", map[string]string{"actual": cursor}))
						break
					}
					cursor = strings.TrimSpace(ancestor.ManagerUserID)
				}
			}
		}
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
		if strings.TrimSpace(user.WorkerNo) != "" && strings.EqualFold(strings.TrimSpace(existing.WorkerNo), strings.TrimSpace(user.WorkerNo)) {
			issues = append(issues, identityConfigurationIssue("user.worker_no", "backend.identity.user_worker_no_exists", "identity.user", map[string]string{"actual": user.WorkerNo}))
		}
	}
	return issues
}

func (s *IdentityConfigurationDomainService) ValidateOrganizationUnitConfiguration(ctx context.Context, organizationUnit identitymodel.IdentityOrganizationUnit) ([]identitycontract.IdentityGovernanceValidationIssue, error) {
	organizationUnit.ID, organizationUnit.Code, organizationUnit.Name = strings.TrimSpace(organizationUnit.ID), strings.TrimSpace(organizationUnit.Code), strings.TrimSpace(organizationUnit.Name)
	issues := []identitycontract.IdentityGovernanceValidationIssue{}
	if organizationUnit.ID == "" {
		issues = append(issues, identityConfigurationIssue("organization_unit.id", "backend.identity.org_id_required", "identity.organization_unit", map[string]string{"actual": organizationUnit.ID}))
	}
	if organizationUnit.Code == "" {
		issues = append(issues, identityConfigurationIssue("organization_unit.code", "backend.identity.organization_unit_code_required", "identity.organization_unit", nil))
	}
	if organizationUnit.Name == "" {
		issues = append(issues, identityConfigurationIssue("organization_unit.name", "backend.identity.organization_unit_name_required", "identity.organization_unit", map[string]string{"actual": organizationUnit.Name}))
	}
	if !validOrganizationUnitType(organizationUnit.NodeType) {
		issues = append(issues, identityConfigurationIssue("organization_unit.node_type", "backend.identity.organization_unit_type_invalid", "identity.organization_unit", map[string]string{"actual": string(organizationUnit.NodeType)}))
	}
	if organizationUnit.Status != "" && organizationUnit.Status != identitymodel.IdentityStatusActive && organizationUnit.Status != identitymodel.IdentityStatusDisabled {
		issues = append(issues, identityConfigurationIssue("organization_unit.status", "backend.identity.organization_unit_status_invalid", "identity.organization_unit", map[string]string{"actual": string(organizationUnit.Status), "allowed": "active,disabled"}))
	}
	organizationUnits, err := s.repository.ListIdentityOrganizationUnits(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	issues = append(issues, validateOrganizationUnitParent(organizationUnit, organizationUnits)...)
	for _, existing := range organizationUnits {
		if existing.ID != organizationUnit.ID && identityConfigurationParentID(existing.ParentID) == identityConfigurationParentID(organizationUnit.ParentID) && strings.EqualFold(strings.TrimSpace(existing.Name), organizationUnit.Name) {
			issues = append(issues, identityConfigurationIssue("organization_unit.name", "backend.identity.organization_unit_name_exists", "identity.organization_unit", map[string]string{"actual": organizationUnit.Name}))
		}
		if existing.ID != organizationUnit.ID && strings.EqualFold(strings.TrimSpace(existing.Code), organizationUnit.Code) {
			issues = append(issues, identityConfigurationIssue("organization_unit.code", "backend.identity.organization_unit_code_exists", "identity.organization_unit", map[string]string{"actual": organizationUnit.Code}))
		}
	}
	return issues, nil
}

func validateOrganizationUnitParent(organizationUnit identitymodel.IdentityOrganizationUnit, organizationUnits []identitymodel.IdentityOrganizationUnit) []identitycontract.IdentityGovernanceValidationIssue {
	parentID := identityConfigurationParentID(organizationUnit.ParentID)
	if parentID == "" {
		return nil
	}
	if parentID == organizationUnit.ID {
		return []identitycontract.IdentityGovernanceValidationIssue{identityConfigurationIssue("organization_unit.parent_id", "backend.identity.organization_unit_parent_self", "identity.organization_unit", map[string]string{"actual": parentID})}
	}
	byID := make(map[string]identitymodel.IdentityOrganizationUnit, len(organizationUnits))
	for _, existing := range organizationUnits {
		byID[existing.ID] = existing
	}
	parent, exists := byID[parentID]
	if !exists {
		return []identitycontract.IdentityGovernanceValidationIssue{identityConfigurationIssue("organization_unit.parent_id", "backend.identity.parent_organization_unit_not_found", "identity.organization_unit", map[string]string{"actual": parentID})}
	}
	seen := map[string]bool{organizationUnit.ID: true}
	for {
		if seen[parent.ID] {
			return []identitycontract.IdentityGovernanceValidationIssue{identityConfigurationIssue("organization_unit.parent_id", "backend.identity.organization_unit_cycle", "identity.organization_unit", map[string]string{"actual": parentID})}
		}
		seen[parent.ID] = true
		nextID := identityConfigurationParentID(parent.ParentID)
		if nextID == "" {
			return nil
		}
		next, exists := byID[nextID]
		if !exists {
			return []identitycontract.IdentityGovernanceValidationIssue{identityConfigurationIssue("organization_unit.parent_id", "backend.identity.parent_organization_unit_not_found", "identity.organization_unit", map[string]string{"actual": nextID})}
		}
		parent = next
	}
}

func validOrganizationUnitType(value identitymodel.IdentityOrganizationUnitType) bool {
	switch value {
	case identitymodel.IdentityOrganizationUnitCompany, identitymodel.IdentityOrganizationUnitRegion, identitymodel.IdentityOrganizationUnitStore, identitymodel.IdentityOrganizationUnitDepartment, identitymodel.IdentityOrganizationUnitTeam, identitymodel.IdentityOrganizationUnitWarehouse:
		return true
	default:
		return false
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
