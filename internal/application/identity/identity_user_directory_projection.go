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
	PageSize int                          `json:"page_size"`
	Total    int                          `json:"total"`
	HasNext  bool                         `json:"has_next"`
	NextID   string                       `json:"next_id,omitempty"`
}

func (s *IdentityApplicationService) SearchUserDirectory(ctx context.Context, query identitymodel.IdentityListQuery, security IdentityUserDirectorySecurityReader) (IdentityUserDirectoryPage, error) {
	if security == nil {
		return IdentityUserDirectoryPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_directory_security_unavailable", nil, nil)
	}
	return s.searchUserDirectory(ctx, query, identitymodel.Principal{}, "", func(ctx context.Context, workspaceID string, userIDs []string) (map[string]IdentityUserDirectorySecuritySummary, error) {
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

func (s *IdentityApplicationService) SearchUserDirectoryWithinDataScope(ctx context.Context, query identitymodel.IdentityListQuery, actor identitymodel.Principal, permissionKey string, security IdentityUserDirectorySecurityReader) (IdentityUserDirectoryPage, error) {
	if security == nil {
		return IdentityUserDirectoryPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_directory_security_unavailable", nil, nil)
	}
	return s.searchUserDirectory(ctx, query, actor, permissionKey, func(ctx context.Context, workspaceID string, userIDs []string) (map[string]IdentityUserDirectorySecuritySummary, error) {
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
	return s.searchUserDirectory(ctx, query, identitymodel.Principal{}, "", security)
}

func (s *IdentityApplicationService) SearchUserDirectoryBatchWithinDataScope(ctx context.Context, query identitymodel.IdentityListQuery, actor identitymodel.Principal, permissionKey string, security IdentityUserDirectorySecurityBatchReader) (IdentityUserDirectoryPage, error) {
	if security == nil {
		return IdentityUserDirectoryPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_directory_security_unavailable", nil, nil)
	}
	return s.searchUserDirectory(ctx, query, actor, permissionKey, security)
}

func (s *IdentityApplicationService) searchUserDirectory(ctx context.Context, query identitymodel.IdentityListQuery, actor identitymodel.Principal, permissionKey string, security IdentityUserDirectorySecurityBatchReader) (IdentityUserDirectoryPage, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return IdentityUserDirectoryPage{}, err
	}
	var users identitymodel.IdentityUserPage
	if strings.TrimSpace(permissionKey) == "" {
		users, err = scoped.SearchUsers(ctx, query)
	} else {
		users, err = scoped.SearchUsersWithinDataScope(ctx, query, actor, permissionKey)
	}
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
		Items: items, PageSize: users.PageSize, Total: users.Total, HasNext: users.HasNext, NextID: users.NextID,
	}, nil
}
