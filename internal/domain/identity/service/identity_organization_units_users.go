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

func (s *IdentityDomainService) ListOrganizationUnits(ctx context.Context) ([]identitymodel.IdentityOrganizationUnit, error) {
	return s.repo.ListIdentityOrganizationUnits(ctx, s.workspace)
}

func (s *IdentityDomainService) UpsertOrganizationUnit(ctx context.Context, organizationUnit identitymodel.IdentityOrganizationUnit) error {
	organizationUnit.ID = strings.TrimSpace(organizationUnit.ID)
	organizationUnit.Code = strings.TrimSpace(organizationUnit.Code)
	organizationUnit.Name = strings.TrimSpace(organizationUnit.Name)
	issues, err := s.validation.ValidateOrganizationUnitConfiguration(ctx, organizationUnit)
	if err != nil {
		return err
	}
	if err := s.validation.FirstConfigurationError(issues); err != nil {
		return err
	}
	if organizationUnit.Status == "" {
		organizationUnit.Status = identitymodel.IdentityStatusActive
	}
	organizationUnits, err := s.repo.ListIdentityOrganizationUnits(ctx, s.workspace)
	if err != nil {
		return err
	}
	byID := map[string]identitymodel.IdentityOrganizationUnit{}
	for _, item := range organizationUnits {
		byID[item.ID] = item
	}
	if organizationUnit.ParentID != nil {
		parentID := strings.TrimSpace(*organizationUnit.ParentID)
		if parentID == "" {
			organizationUnit.ParentID = nil
		} else {
			organizationUnit.ParentID = &parentID
			parent, ok := byID[parentID]
			if !ok {
				return badRequest("backend.identity.parent_organization_unit_not_found", "organization_unit", parentID)
			}
			for {
				if parent.ID == organizationUnit.ID {
					return badRequest("backend.identity.organization_unit_cycle")
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
	for _, existingOrganizationUnit := range organizationUnits {
		if existingOrganizationUnit.ID == organizationUnit.ID {
			continue
		}
		if identityParentID(existingOrganizationUnit.ParentID) == identityParentID(organizationUnit.ParentID) &&
			strings.EqualFold(strings.TrimSpace(existingOrganizationUnit.Name), organizationUnit.Name) {
			return badRequest("backend.identity.organization_unit_name_exists", "organization_unit", organizationUnit.Name)
		}
	}
	updates, err := identityOrganizationUnitSubtreeUpdates(organizationUnit, organizationUnits)
	if err != nil {
		return err
	}
	return s.repo.UpsertIdentityOrganizationUnitsAtomically(ctx, s.workspace, updates)
}

func identityOrganizationUnitSubtreeUpdates(root identitymodel.IdentityOrganizationUnit, existing []identitymodel.IdentityOrganizationUnit) ([]identitymodel.IdentityOrganizationUnit, error) {
	byID := make(map[string]identitymodel.IdentityOrganizationUnit, len(existing)+1)
	for _, item := range existing {
		byID[item.ID] = item
	}
	// Hierarchy facts are owned by Identity and are never accepted from callers.
	root.Path, root.AncestorIDs, root.Depth = "", nil, 0
	byID[root.ID] = root

	children := make(map[string][]string, len(byID))
	for id, item := range byID {
		if parentID := identityParentID(item.ParentID); parentID != "" {
			children[parentID] = append(children[parentID], id)
		}
	}
	for parentID := range children {
		sort.Strings(children[parentID])
	}

	derived := make(map[string]identitymodel.IdentityOrganizationUnit, len(byID))
	visiting := make(map[string]bool, len(byID))
	var derive func(string) (identitymodel.IdentityOrganizationUnit, error)
	derive = func(id string) (identitymodel.IdentityOrganizationUnit, error) {
		if item, ok := derived[id]; ok {
			return item, nil
		}
		item, ok := byID[id]
		if !ok {
			return identitymodel.IdentityOrganizationUnit{}, badRequest("backend.identity.parent_organization_unit_not_found", "organization_unit", id)
		}
		if visiting[id] {
			return identitymodel.IdentityOrganizationUnit{}, badRequest("backend.identity.organization_unit_cycle")
		}
		visiting[id] = true
		parentID := identityParentID(item.ParentID)
		if parentID == "" {
			item.Path = "/" + item.ID
			item.AncestorIDs = []string{}
			item.Depth = 0
		} else {
			parent, err := derive(parentID)
			if err != nil {
				return identitymodel.IdentityOrganizationUnit{}, err
			}
			item.AncestorIDs = append(append([]string{}, parent.AncestorIDs...), parent.ID)
			item.Depth = len(item.AncestorIDs)
			item.Path = strings.TrimRight(parent.Path, "/") + "/" + item.ID
		}
		visiting[id] = false
		derived[id] = item
		return item, nil
	}

	updates := make([]identitymodel.IdentityOrganizationUnit, 0, len(byID))
	queue := []string{root.ID}
	seen := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		item, err := derive(id)
		if err != nil {
			return nil, err
		}
		updates = append(updates, item)
		queue = append(queue, children[id]...)
	}
	sort.Slice(updates, func(left, right int) bool {
		if updates[left].Depth == updates[right].Depth {
			return updates[left].ID < updates[right].ID
		}
		return updates[left].Depth < updates[right].Depth
	})
	return updates, nil
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
	existing, hadExisting, err := s.repo.GetIdentityUser(ctx, s.workspace, strings.TrimSpace(user.ID))
	if err != nil {
		return err
	}
	user, err = s.prepareUser(ctx, user)
	if err != nil {
		return err
	}
	updates := []identitymodel.IdentityUser{user}
	if hadExisting && existing.ReportingPath != user.ReportingPath {
		descendants, err := s.rebuildUserReportingPathReferences(ctx, existing.ReportingPath, user.ReportingPath)
		if err != nil {
			return err
		}
		updates = append(updates, descendants...)
	}
	return s.repo.UpsertIdentityUsersAtomically(ctx, s.workspace, updates)
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
	user.OrgID = strings.TrimSpace(user.OrgID)
	user.SupportOrgID = strings.TrimSpace(user.SupportOrgID)
	user.ManagerUserID = strings.TrimSpace(user.ManagerUserID)
	user.WorkerNo = strings.TrimSpace(user.WorkerNo)
	user.WorkerType = identitymodel.IdentityWorkerType(strings.TrimSpace(string(user.WorkerType)))
	user.WorkStatus = identitymodel.IdentityWorkStatus(strings.TrimSpace(string(user.WorkStatus)))
	if user.AccountType == identitymodel.IdentityAccountHuman && user.WorkerType == "" {
		user.WorkerType = identitymodel.IdentityWorkerEmployee
	}
	if user.AccountType == identitymodel.IdentityAccountHuman && user.WorkStatus == "" {
		user.WorkStatus = identitymodel.IdentityWorkActive
	}
	user.StartDate = strings.TrimSpace(user.StartDate)
	user.EndDate = strings.TrimSpace(user.EndDate)
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
	user.ReportingPath = "/" + user.ID
	if user.ManagerUserID != "" {
		byID := make(map[string]identitymodel.IdentityUser, len(users))
		for _, existing := range users {
			byID[existing.ID] = existing
		}
		managerPath := identityUserReportingPath(user.ManagerUserID, byID)
		if managerPath != "" {
			user.ReportingPath = strings.TrimRight(managerPath, "/") + "/" + user.ID
		}
	}
	user.Phone = strings.TrimSpace(user.Phone)
	return user, nil
}

func identityUserReportingPath(userID string, users map[string]identitymodel.IdentityUser) string {
	path := []string{}
	visited := map[string]bool{}
	for cursor := strings.TrimSpace(userID); cursor != "" && !visited[cursor]; {
		visited[cursor] = true
		user, found := users[cursor]
		if !found {
			break
		}
		path = append(path, user.ID)
		cursor = strings.TrimSpace(user.ManagerUserID)
	}
	for left, right := 0, len(path)-1; left < right; left, right = left+1, right-1 {
		path[left], path[right] = path[right], path[left]
	}
	if len(path) == 0 {
		return ""
	}
	return "/" + strings.Join(path, "/")
}

func (s *IdentityDomainService) rebuildUserReportingPathReferences(ctx context.Context, oldPath, newPath string) ([]identitymodel.IdentityUser, error) {
	oldPath = strings.TrimRight(strings.TrimSpace(oldPath), "/")
	newPath = strings.TrimRight(strings.TrimSpace(newPath), "/")
	if oldPath == "" || newPath == "" || oldPath == newPath {
		return nil, nil
	}
	users, err := s.repo.ListIdentityUsers(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	descendants := []identitymodel.IdentityUser{}
	for _, descendant := range users {
		path := strings.TrimRight(strings.TrimSpace(descendant.ReportingPath), "/")
		if !strings.HasPrefix(path, oldPath+"/") {
			continue
		}
		descendant.ReportingPath = newPath + strings.TrimPrefix(path, oldPath)
		descendants = append(descendants, descendant)
	}
	return descendants, nil
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
	users, err := s.repo.ListIdentityUsers(ctx, s.workspace)
	if err != nil {
		return err
	}
	for _, user := range users {
		if strings.TrimSpace(user.ManagerUserID) == userID {
			return conflict("backend.identity.user_direct_reports_exist", "user", userID, "direct_report", user.ID)
		}
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
	sort.Strings(roleIDs)
	sort.Slice(bindings, func(left, right int) bool {
		if bindings[left].ObjectKey == bindings[right].ObjectKey {
			return bindings[left].ProfileID < bindings[right].ProfileID
		}
		return bindings[left].ObjectKey < bindings[right].ObjectKey
	})
	return identitymodel.IdentityUserDeletionImpact{
		UserID: userID, ProfileBindings: bindings, ActiveRoleIDs: roleIDs,
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
