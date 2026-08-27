package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func (s *IdentityDomainService) ListDepartments(ctx context.Context) ([]identitymodel.IdentityDepartment, error) {
	return s.repo.ListIdentityDepartments(ctx, s.workspace)
}

func (s *IdentityDomainService) UpsertDepartment(ctx context.Context, department identitymodel.IdentityDepartment) error {
	department.ID = strings.TrimSpace(department.ID)
	department.Name = strings.TrimSpace(department.Name)
	department.LeaderWorkforceProfileID = strings.TrimSpace(department.LeaderWorkforceProfileID)
	issues, err := s.validation.ValidateDepartmentConfiguration(ctx, department)
	if err != nil {
		return err
	}
	if err := s.validation.FirstConfigurationError(issues); err != nil {
		return err
	}
	if department.Status == "" {
		department.Status = identitymodel.IdentityStatusActive
	}
	departments, err := s.repo.ListIdentityDepartments(ctx, s.workspace)
	if err != nil {
		return err
	}
	byID := map[string]identitymodel.IdentityDepartment{}
	for _, item := range departments {
		byID[item.ID] = item
	}
	if department.ParentID != nil {
		parentID := strings.TrimSpace(*department.ParentID)
		if parentID == "" {
			department.ParentID = nil
		} else {
			parent, ok := byID[parentID]
			if !ok {
				return badRequest("backend.identity.parent_department_not_found", "department", parentID)
			}
			for {
				if parent.ID == department.ID {
					return badRequest("backend.identity.department_cycle")
				}
				if parent.ParentID == nil || strings.TrimSpace(*parent.ParentID) == "" {
					break
				}
				nextParent, ok := byID[strings.TrimSpace(*parent.ParentID)]
				if !ok {
					break
				}
				parent = nextParent
			}
		}
	}
	for _, existingDepartment := range departments {
		if existingDepartment.ID == department.ID {
			continue
		}
		if identityParentID(existingDepartment.ParentID) == identityParentID(department.ParentID) &&
			strings.EqualFold(strings.TrimSpace(existingDepartment.Name), department.Name) {
			return badRequest("backend.identity.department_name_exists", "department", department.Name)
		}
	}
	existing, hadExisting := byID[department.ID]
	parentChanged := hadExisting && identityParentID(existing.ParentID) != identityParentID(department.ParentID)
	if strings.TrimSpace(department.Path) == "" || parentChanged {
		department.AncestorIDs = []string{}
		department.Depth = 0
		department.Path = "/" + department.ID
		if department.ParentID != nil {
			parent := byID[strings.TrimSpace(*department.ParentID)]
			department.AncestorIDs = append(append([]string{}, parent.AncestorIDs...), parent.ID)
			department.Depth = len(department.AncestorIDs)
			department.Path = strings.TrimRight(parent.Path, "/") + "/" + department.ID
		}
	}
	if err := s.validateDepartmentLeader(ctx, department); err != nil {
		return err
	}
	if err := s.repo.UpsertIdentityDepartment(ctx, s.workspace, department); err != nil {
		return err
	}
	if hadExisting && existing.Path != "" && existing.Path != department.Path {
		if err := s.rebuildDepartmentPathReferences(ctx, existing.Path, department.Path, departments); err != nil {
			return err
		}
	}
	return nil
}

func (s *IdentityDomainService) validateDepartmentLeader(ctx context.Context, department identitymodel.IdentityDepartment) error {
	if department.LeaderWorkforceProfileID == "" {
		return nil
	}
	repository := s.workforceRepository()
	if repository == nil {
		return badRequest("backend.identity.workforce_unavailable")
	}
	profile, found, err := repository.GetIdentityWorkforceProfile(ctx, s.workspace, department.LeaderWorkforceProfileID)
	if err != nil {
		return err
	}
	if !found || profile.WorkStatus != identitymodel.IdentityWorkActive {
		return badRequest("backend.identity.department_leader_not_active", "workforce_profile", department.LeaderWorkforceProfileID)
	}
	assignments, err := repository.ListIdentityWorkforceAssignments(ctx, s.workspace, profile.ID)
	if err != nil {
		return err
	}
	for _, assignment := range assignments {
		if assignment.OrganizationUnitID == department.ID && assignment.Status == identitymodel.IdentityStatusActive &&
			assignment.AssignmentType == identitymodel.IdentityWorkforceAssignmentPrimary {
			return nil
		}
	}
	return badRequest("backend.identity.department_leader_assignment_required", "department", department.ID, "workforce_profile", department.LeaderWorkforceProfileID)
}

func (s *IdentityDomainService) rebuildDepartmentPathReferences(ctx context.Context, oldPath string, newPath string, departments []identitymodel.IdentityDepartment) error {
	oldPath = strings.TrimRight(strings.TrimSpace(oldPath), "/")
	newPath = strings.TrimRight(strings.TrimSpace(newPath), "/")
	if oldPath == "" || newPath == "" || oldPath == newPath {
		return nil
	}
	for _, child := range departments {
		if child.Path == oldPath || !strings.HasPrefix(strings.TrimRight(child.Path, "/"), oldPath+"/") {
			continue
		}
		child.Path = newPath + strings.TrimPrefix(strings.TrimRight(child.Path, "/"), oldPath)
		if err := s.repo.UpsertIdentityDepartment(ctx, s.workspace, child); err != nil {
			return err
		}
	}
	return nil
}

func (s *IdentityDomainService) ListUsers(ctx context.Context) ([]identitymodel.IdentityUser, error) {
	return s.repo.ListIdentityUsers(ctx, s.workspace)
}

func (s *IdentityDomainService) UserByID(ctx context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	return s.userByID(ctx, strings.TrimSpace(userID))
}

func (s *IdentityDomainService) UserByLogin(ctx context.Context, login string) (identitymodel.IdentityUser, bool, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return identitymodel.IdentityUser{}, false, nil
	}
	users, err := s.repo.ListIdentityUsers(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	for _, user := range users {
		if strings.ToLower(strings.TrimSpace(user.ID)) == login || strings.ToLower(strings.TrimSpace(user.Email)) == login {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}

func (s *IdentityDomainService) UpsertUser(ctx context.Context, user identitymodel.IdentityUser) error {
	user, err := s.prepareUser(ctx, user)
	if err != nil {
		return err
	}
	return s.repo.UpsertIdentityUser(ctx, s.workspace, user)
}

func (s *IdentityDomainService) prepareUser(ctx context.Context, user identitymodel.IdentityUser) (identitymodel.IdentityUser, error) {
	user.ID = strings.TrimSpace(user.ID)
	user.Name = strings.TrimSpace(user.Name)
	user.GivenName = strings.TrimSpace(user.GivenName)
	user.MiddleName = strings.TrimSpace(user.MiddleName)
	user.FamilyName = strings.TrimSpace(user.FamilyName)
	user.NamePrefix = strings.TrimSpace(user.NamePrefix)
	user.NameSuffix = strings.TrimSpace(user.NameSuffix)
	user.NativeName = strings.TrimSpace(user.NativeName)
	user.NameLocale = strings.TrimSpace(user.NameLocale)
	user.AccountType = identitymodel.IdentityAccountType(strings.ToLower(strings.TrimSpace(string(user.AccountType))))
	if user.AccountType == "" {
		user.AccountType = identitymodel.IdentityAccountHuman
	}
	user.Locale = strings.TrimSpace(user.Locale)
	user.Timezone = strings.TrimSpace(user.Timezone)
	user.Email = strings.ToLower(strings.TrimSpace(user.Email))
	issues, err := s.validation.ValidateUserConfiguration(ctx, user)
	if err != nil {
		return identitymodel.IdentityUser{}, err
	}
	if err := s.validation.FirstConfigurationError(issues); err != nil {
		return identitymodel.IdentityUser{}, err
	}
	users, err := s.repo.ListIdentityUsers(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityUser{}, err
	}
	for _, existing := range users {
		if existing.ID != user.ID {
			continue
		}
		if strings.TrimSpace(user.Locale) == "" {
			user.Locale = existing.Locale
		}
		if user.Version < 1 {
			user.Version = existing.Version
		}
		break
	}
	if strings.TrimSpace(user.Locale) == "" {
		user.Locale = "en-US"
	}
	if user.Version < 1 {
		user.Version = 1
	}
	for _, existing := range users {
		if existing.ID != user.ID && strings.EqualFold(strings.TrimSpace(existing.Email), user.Email) {
			return identitymodel.IdentityUser{}, badRequest("backend.identity.user_email_exists", "email", user.Email)
		}
	}
	user.Phone = strings.TrimSpace(user.Phone)
	return user, nil
}

// UpdateUserLocale changes only the authenticated user's locale through a
// workspace-scoped compare-and-swap.
func (s *IdentityDomainService) UpdateUserLocale(ctx context.Context, workspaceID, userID, locale string, expectedVersion int64) (identitymodel.IdentityUser, error) {
	workspace, err := identitymodel.NewWorkspaceCommandScope(workspaceID)
	if err != nil {
		return identitymodel.IdentityUser{}, forbidden("backend.workspace_scope_required")
	}
	userID = strings.TrimSpace(userID)
	locale = strings.TrimSpace(locale)
	if userID == "" {
		return identitymodel.IdentityUser{}, forbidden("auth.token_required")
	}
	if locale == "" {
		return identitymodel.IdentityUser{}, badRequest("backend.identity.user_locale_required")
	}
	if expectedVersion < 1 {
		return identitymodel.IdentityUser{}, badRequest("backend.identity.user_version_required")
	}
	localeRepo, ok := s.repo.(identityrepository.IdentityUserLocaleRepository)
	if !ok {
		return identitymodel.IdentityUser{}, internalError("update identity user locale", fmt.Errorf("identity locale repository is unavailable"))
	}
	updated, matched, err := localeRepo.UpdateIdentityUserLocale(ctx, workspace.WorkspaceID().String(), userID, locale, expectedVersion)
	if err != nil {
		return identitymodel.IdentityUser{}, err
	}
	if matched {
		return updated, nil
	}
	if _, found, err := s.repo.GetIdentityUser(ctx, workspace.WorkspaceID().String(), userID); err != nil {
		return identitymodel.IdentityUser{}, err
	} else if !found {
		return identitymodel.IdentityUser{}, notFound("backend.identity.user_not_found", "user", userID)
	}
	return identitymodel.IdentityUser{}, conflict("backend.identity.user_version_conflict", "user", userID)
}

func identityParentID(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func (s *IdentityDomainService) RemoveUser(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return badRequest("backend.identity.user_required", "user", "")
	}
	bindings, err := s.repo.ListIdentityProfileBindingsByUser(ctx, s.workspace, userID)
	if err != nil {
		return err
	}
	if len(bindings) > 0 {
		profiles := make([]string, 0, len(bindings))
		for _, binding := range bindings {
			profiles = append(profiles, binding.ObjectKey+":"+binding.ProfileID)
		}
		return conflict(
			"backend.identity.user_profile_bindings_exist",
			"user", userID,
			"profiles", strings.Join(profiles, ","),
		)
	}
	return s.repo.RemoveIdentityUser(ctx, s.workspace, userID)
}

func (s *IdentityDomainService) UserDeletionImpact(ctx context.Context, userID string) (identitymodel.IdentityUserDeletionImpact, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return identitymodel.IdentityUserDeletionImpact{}, badRequest("backend.identity.user_required")
	}
	if _, found, err := s.userByID(ctx, userID); err != nil {
		return identitymodel.IdentityUserDeletionImpact{}, err
	} else if !found {
		return identitymodel.IdentityUserDeletionImpact{}, notFound("backend.identity.user_not_found", "user", userID)
	}
	bindings, err := s.repo.ListIdentityProfileBindingsByUser(ctx, s.workspace, userID)
	if err != nil {
		return identitymodel.IdentityUserDeletionImpact{}, err
	}
	assignments, err := s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, userID)
	if err != nil {
		return identitymodel.IdentityUserDeletionImpact{}, err
	}
	roleIDs := []string{}
	for _, assignment := range assignments {
		if identityAssignmentActive(assignment, time.Now()) {
			roleIDs = append(roleIDs, assignment.RoleID)
		}
	}
	workforceIDs := []string{}
	if workforce := s.workforceRepository(); workforce != nil {
		profiles, err := workforce.ListIdentityWorkforceProfiles(ctx, s.workspace)
		if err != nil {
			return identitymodel.IdentityUserDeletionImpact{}, err
		}
		for _, profile := range profiles {
			if profile.IdentityUserID == userID {
				workforceIDs = append(workforceIDs, profile.ID)
			}
		}
	}
	sort.Strings(roleIDs)
	sort.Strings(workforceIDs)
	sort.Slice(bindings, func(left, right int) bool {
		if bindings[left].ObjectKey == bindings[right].ObjectKey {
			return bindings[left].ProfileID < bindings[right].ProfileID
		}
		return bindings[left].ObjectKey < bindings[right].ObjectKey
	})
	return identitymodel.IdentityUserDeletionImpact{
		UserID: userID, ProfileBindings: bindings, WorkforceProfileIDs: workforceIDs, ActiveRoleIDs: roleIDs,
		CredentialsAndSessionsRevoked: true, CanDelete: len(bindings) == 0,
	}, nil
}

func (s *IdentityDomainService) SetUserStatus(ctx context.Context, userID string, status identitymodel.IdentityStatus) error {
	return s.repo.SetIdentityUserStatus(ctx, s.workspace, userID, status)
}

func (s *IdentityDomainService) userByID(ctx context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	users, err := s.repo.ListIdentityUsers(ctx, s.workspace)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	for _, user := range users {
		if user.ID == userID {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}
