package identity

import (
	"context"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type IdentityUserDirectorySecuritySummary struct {
	MFAEnabled     bool   `json:"mfa_enabled"`
	Locked         bool   `json:"locked"`
	ActiveSessions int    `json:"active_sessions"`
	LastLoginAt    string `json:"last_login_at,omitempty"`
}

func (s *IdentityApplicationService) ListWorkforceProfilesForPrincipal(ctx context.Context, principal identitymodel.Principal) ([]identitymodel.IdentityWorkforceProfile, error) {
	if err := identityAuthorizeQuery(principal); err != nil {
		return nil, err
	}
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return nil, err
	}
	profiles, err := scoped.ListWorkforceProfiles(ctx)
	if err != nil {
		return nil, err
	}
	assignments, err := scoped.workforceRepository.ListIdentityWorkforceAssignments(ctx, scoped.WorkspaceID(), "")
	if err != nil {
		return nil, err
	}
	departments, err := scoped.Repository().ListIdentityDepartments(ctx, scoped.WorkspaceID())
	if err != nil {
		return nil, err
	}
	assignmentsByProfile := map[string][]identitymodel.IdentityWorkforceAssignment{}
	for _, assignment := range assignments {
		assignmentsByProfile[assignment.WorkforceProfileID] = append(assignmentsByProfile[assignment.WorkforceProfileID], assignment)
	}
	departmentsByID := map[string]identitymodel.IdentityDepartment{}
	for _, department := range departments {
		departmentsByID[department.ID] = department
	}
	result := make([]identitymodel.IdentityWorkforceProfile, 0, len(profiles))
	for _, profile := range profiles {
		if identityWorkforceReadScopeAllows(principal, profile, assignmentsByProfile[profile.ID], departmentsByID) {
			result = append(result, profile)
		}
	}
	return result, nil
}

// ListWorkforceApplicationProjection provides the formal application read
// model for Foundation workforce data. Position names remain owned by the
// Party catalog and are resolved through the formal /foundation/positions
// contract using PrimaryAssignment.PositionID.
func (s *IdentityApplicationService) ListWorkforceApplicationProjection(ctx context.Context, principal identitymodel.Principal, queries ...identitymodel.IdentityWorkforceProjectionQuery) (identitymodel.IdentityWorkforceProjectionPage, error) {
	if err := identityAuthorizeQuery(principal); err != nil {
		return identitymodel.IdentityWorkforceProjectionPage{}, err
	}
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceProjectionPage{}, err
	}
	if scoped.workforceRepository == nil {
		return identitymodel.IdentityWorkforceProjectionPage{}, &apperror.AppError{Kind: apperror.KindInternal, Code: "backend.identity.workforce_unavailable"}
	}
	profiles, err := scoped.workforceRepository.ListIdentityWorkforceProfiles(ctx, scoped.WorkspaceID())
	if err != nil {
		return identitymodel.IdentityWorkforceProjectionPage{}, err
	}
	assignments, err := scoped.workforceRepository.ListIdentityWorkforceAssignments(ctx, scoped.WorkspaceID(), "")
	if err != nil {
		return identitymodel.IdentityWorkforceProjectionPage{}, err
	}
	users, err := scoped.Repository().ListIdentityUsers(ctx, scoped.WorkspaceID())
	if err != nil {
		return identitymodel.IdentityWorkforceProjectionPage{}, err
	}
	departments, err := scoped.Repository().ListIdentityDepartments(ctx, scoped.WorkspaceID())
	if err != nil {
		return identitymodel.IdentityWorkforceProjectionPage{}, err
	}
	usersByID := make(map[string]identitymodel.IdentityUser, len(users))
	for _, user := range users {
		usersByID[user.ID] = user
	}
	profilesByID := make(map[string]identitymodel.IdentityWorkforceProfile, len(profiles))
	for _, profile := range profiles {
		profilesByID[profile.ID] = profile
	}
	departmentsByID := make(map[string]identitymodel.IdentityDepartment, len(departments))
	for _, department := range departments {
		departmentsByID[department.ID] = department
	}
	assignmentsByProfile := map[string][]identitymodel.IdentityWorkforceAssignment{}
	for _, assignment := range assignments {
		assignmentsByProfile[assignment.WorkforceProfileID] = append(assignmentsByProfile[assignment.WorkforceProfileID], assignment)
	}
	positionsByID := map[string]identitymodel.IdentityWorkforcePosition{}
	if scoped.positionResolver != nil {
		positions, resolveErr := scoped.positionResolver.ListWorkforcePositions(ctx, scoped.WorkspaceID())
		if resolveErr != nil {
			return identitymodel.IdentityWorkforceProjectionPage{}, resolveErr
		}
		for _, position := range positions {
			positionsByID[position.ID] = position
		}
	}
	items := make([]identitymodel.IdentityWorkforceProjectionItem, 0, len(profiles))
	for _, profile := range profiles {
		if !identityWorkforceReadScopeAllows(principal, profile, assignmentsByProfile[profile.ID], departmentsByID) {
			continue
		}
		roles, roleErr := scoped.ResolveEffectiveRoles(ctx, profile.IdentityUserID)
		if roleErr != nil {
			return identitymodel.IdentityWorkforceProjectionPage{}, roleErr
		}
		item := identitymodel.IdentityWorkforceProjectionItem{
			Profile: profile,
			Roles:   make([]identitymodel.IdentityWorkforceRole, 0, len(roles)),
		}
		for _, role := range roles {
			item.Roles = append(item.Roles, identitymodel.IdentityWorkforceRole{ID: role.ID, Key: role.Key, Label: role.Label})
		}
		if user, ok := usersByID[profile.IdentityUserID]; ok {
			item.DisplayName, item.Email, item.Phone, item.UpdatedAt = user.Name, user.Email, user.Phone, user.UpdatedAt
		}
		if assignment, ok := workforcePrimaryAssignment(profile, assignmentsByProfile[profile.ID]); ok {
			assignmentCopy := assignment
			item.PrimaryAssignment = &assignmentCopy
			if department, found := departmentsByID[assignment.OrganizationUnitID]; found {
				departmentCopy := department
				item.Department = &departmentCopy
			}
			if position, found := positionsByID[assignment.PositionID]; found {
				positionCopy := position
				item.Position = &positionCopy
			}
			if managerProfile, found := profilesByID[assignment.ManagerWorkforceProfileID]; found {
				manager := identitymodel.IdentityWorkforceManager{WorkforceProfileID: managerProfile.ID, IdentityUserID: managerProfile.IdentityUserID}
				if managerUser, found := usersByID[managerProfile.IdentityUserID]; found {
					manager.DisplayName = managerUser.Name
				}
				item.Manager = &manager
			}
		}
		items = append(items, item)
	}
	query := identitymodel.IdentityWorkforceProjectionQuery{}
	if len(queries) > 0 {
		query = queries[0]
	}
	items = filterWorkforceApplicationProjection(items, query)
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].Profile.WorkerNo == items[right].Profile.WorkerNo {
			return items[left].Profile.ID < items[right].Profile.ID
		}
		return items[left].Profile.WorkerNo < items[right].Profile.WorkerNo
	})
	total := len(items)
	page, pageSize := query.Page, query.PageSize
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > total && total > 0 {
		pageSize = total
	}
	if pageSize == 0 {
		pageSize = 50
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return identitymodel.IdentityWorkforceProjectionPage{Items: items[start:end], Page: page, PageSize: pageSize, Total: total, HasNext: end < total}, nil
}

func filterWorkforceApplicationProjection(items []identitymodel.IdentityWorkforceProjectionItem, query identitymodel.IdentityWorkforceProjectionQuery) []identitymodel.IdentityWorkforceProjectionItem {
	needle := strings.ToLower(strings.TrimSpace(query.Search))
	departmentID := strings.TrimSpace(query.DepartmentID)
	filtered := make([]identitymodel.IdentityWorkforceProjectionItem, 0, len(items))
	for _, item := range items {
		if departmentID != "" && (item.Department == nil || item.Department.ID != departmentID) {
			continue
		}
		if query.WorkStatus != "" && item.Profile.WorkStatus != query.WorkStatus {
			continue
		}
		if needle != "" {
			values := []string{item.DisplayName, item.Email, item.Phone, item.Profile.WorkerNo}
			if item.Department != nil {
				values = append(values, item.Department.Name)
			}
			if item.Position != nil {
				values = append(values, item.Position.Name, item.Position.Code)
			}
			matched := false
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), needle) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	return filtered
}

type IdentityUserDirectorySecurityReader func(context.Context, string, string) (IdentityUserDirectorySecuritySummary, error)
type IdentityUserDirectorySecurityBatchReader func(context.Context, string, []string) (map[string]IdentityUserDirectorySecuritySummary, error)

type IdentityUserDirectoryRoleSummary struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Label  string `json:"label"`
	Source string `json:"source,omitempty"`
	Status string `json:"status,omitempty"`
}

type IdentityUserDirectoryBadge struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

type IdentityUserDirectoryEntry struct {
	User           identitymodel.IdentityUser           `json:"user"`
	Roles          []IdentityUserDirectoryRoleSummary   `json:"roles"`
	Security       IdentityUserDirectorySecuritySummary `json:"security"`
	IdentityBadges []IdentityUserDirectoryBadge         `json:"identity_badges"`
}

type IdentityUserDirectoryPage struct {
	Items    []IdentityUserDirectoryEntry `json:"items"`
	Page     int                          `json:"page"`
	PageSize int                          `json:"page_size"`
	Total    int                          `json:"total"`
	HasNext  bool                         `json:"has_next"`
}

func (s *IdentityApplicationService) SearchUserDirectory(ctx context.Context, query identitymodel.IdentityListQuery, security IdentityUserDirectorySecurityReader) (IdentityUserDirectoryPage, error) {
	if security == nil {
		return IdentityUserDirectoryPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_directory_security_unavailable", nil, nil)
	}
	return s.searchUserDirectory(ctx, query, func(ctx context.Context, workspaceID string, userIDs []string) (map[string]IdentityUserDirectorySecuritySummary, error) {
		summaries := make(map[string]IdentityUserDirectorySecuritySummary, len(userIDs))
		for _, userID := range userIDs {
			summary, err := security(ctx, workspaceID, userID)
			if err != nil {
				return nil, err
			}
			summaries[userID] = summary
		}
		return summaries, nil
	})
}

func (s *IdentityApplicationService) SearchUserDirectoryBatch(ctx context.Context, query identitymodel.IdentityListQuery, security IdentityUserDirectorySecurityBatchReader) (IdentityUserDirectoryPage, error) {
	if security == nil {
		return IdentityUserDirectoryPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_directory_security_unavailable", nil, nil)
	}
	return s.searchUserDirectory(ctx, query, security)
}

func (s *IdentityApplicationService) searchUserDirectory(ctx context.Context, query identitymodel.IdentityListQuery, security IdentityUserDirectorySecurityBatchReader) (IdentityUserDirectoryPage, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return IdentityUserDirectoryPage{}, err
	}
	users, err := scoped.SearchUsers(ctx, query)
	if err != nil {
		return IdentityUserDirectoryPage{}, err
	}
	userIDs := make([]string, 0, len(users.Items))
	for _, user := range users.Items {
		userIDs = append(userIDs, user.ID)
	}
	var facts identitymodel.IdentityUserDirectoryFacts
	if repository, ok := scoped.Repository().(identityrepository.IdentityUserDirectoryFactsRepository); ok {
		facts, err = repository.ListIdentityUserDirectoryFacts(ctx, scoped.WorkspaceID(), userIDs)
		if err != nil {
			return IdentityUserDirectoryPage{}, err
		}
	} else {
		facts.RoleAssignments, err = scoped.Repository().ListIdentityUserRoleAssignments(ctx, scoped.WorkspaceID(), "")
		if err != nil {
			return IdentityUserDirectoryPage{}, err
		}
		if s.workforceRepository != nil {
			facts.WorkforceProfiles, err = s.workforceRepository.ListIdentityWorkforceProfiles(ctx, scoped.WorkspaceID())
			if err != nil {
				return IdentityUserDirectoryPage{}, err
			}
		}
		for _, userID := range userIDs {
			bindings, listErr := scoped.Repository().ListIdentityProfileBindingsByUser(ctx, scoped.WorkspaceID(), userID)
			if listErr != nil {
				return IdentityUserDirectoryPage{}, listErr
			}
			for _, binding := range bindings {
				if binding.IdentityUserID == "" {
					binding.IdentityUserID = userID
				}
				facts.ProfileBindings = append(facts.ProfileBindings, binding)
			}
		}
	}
	roles, err := scoped.Repository().ListIdentityRoles(ctx, scoped.WorkspaceID())
	if err != nil {
		return IdentityUserDirectoryPage{}, err
	}
	roleByID := make(map[string]identitymodel.IdentityRole, len(roles))
	for _, role := range roles {
		roleByID[role.ID] = role
	}
	assignmentsByUser := make(map[string][]identitymodel.IdentityUserRoleAssignment)
	for _, assignment := range facts.RoleAssignments {
		assignmentsByUser[assignment.UserID] = append(assignmentsByUser[assignment.UserID], assignment)
	}
	workforceByUser := map[string][]identitymodel.IdentityWorkforceProfile{}
	for _, profile := range facts.WorkforceProfiles {
		workforceByUser[profile.IdentityUserID] = append(workforceByUser[profile.IdentityUserID], profile)
	}
	bindingsByUser := map[string][]identitymodel.IdentityProfileBinding{}
	for _, binding := range facts.ProfileBindings {
		bindingsByUser[binding.IdentityUserID] = append(bindingsByUser[binding.IdentityUserID], binding)
	}
	securitySummaries, err := security(ctx, scoped.WorkspaceID(), userIDs)
	if err != nil {
		return IdentityUserDirectoryPage{}, err
	}
	items := make([]IdentityUserDirectoryEntry, 0, len(users.Items))
	for _, user := range users.Items {
		entry := IdentityUserDirectoryEntry{
			User: user, Security: securitySummaries[user.ID],
			Roles: []IdentityUserDirectoryRoleSummary{}, IdentityBadges: []IdentityUserDirectoryBadge{},
		}
		for _, assignment := range assignmentsByUser[user.ID] {
			role := roleByID[assignment.RoleID]
			entry.Roles = append(entry.Roles, IdentityUserDirectoryRoleSummary{
				ID: assignment.RoleID, Key: role.Key, Label: role.Label,
				Source: assignment.Source, Status: assignment.Status,
			})
		}
		for _, profile := range workforceByUser[user.ID] {
			entry.IdentityBadges = append(entry.IdentityBadges, IdentityUserDirectoryBadge{
				Kind: "workforce", Key: string(profile.WorkerType), ID: profile.ID, Status: string(profile.WorkStatus),
			})
		}
		for _, binding := range bindingsByUser[user.ID] {
			if binding.Status == identitymodel.IdentityProfileBindingUnlinked {
				continue
			}
			entry.IdentityBadges = append(entry.IdentityBadges, IdentityUserDirectoryBadge{
				Kind: "business_profile", Key: binding.BindingKey, ID: binding.ProfileID, Status: string(binding.Status),
			})
		}
		sort.Slice(entry.Roles, func(left, right int) bool {
			return strings.Compare(entry.Roles[left].Key+entry.Roles[left].ID, entry.Roles[right].Key+entry.Roles[right].ID) < 0
		})
		sort.Slice(entry.IdentityBadges, func(left, right int) bool {
			return strings.Compare(entry.IdentityBadges[left].Kind+entry.IdentityBadges[left].Key+entry.IdentityBadges[left].ID, entry.IdentityBadges[right].Kind+entry.IdentityBadges[right].Key+entry.IdentityBadges[right].ID) < 0
		})
		items = append(items, entry)
	}
	return IdentityUserDirectoryPage{
		Items: items, Page: users.Page, PageSize: users.PageSize, Total: users.Total, HasNext: users.HasNext,
	}, nil
}
