package identity

import (
	"context"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type IdentityUserProjectionSecuritySummary struct {
	MFAEnabled     bool   `json:"mfa_enabled"`
	Locked         bool   `json:"locked"`
	ActiveSessions int    `json:"active_sessions"`
	LastLoginAt    string `json:"last_login_at,omitempty"`
}

type IdentityUserProjectionSecurityReader func(context.Context, string, string) (IdentityUserProjectionSecuritySummary, error)
type IdentityUserProjectionSecurityBatchReader func(context.Context, string, []string) (map[string]IdentityUserProjectionSecuritySummary, error)

type IdentityUserProjectionRoleSummary struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Label  string `json:"label"`
	Source string `json:"source,omitempty"`
	Status string `json:"status,omitempty"`
}

type IdentityUserProjectionBadge struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

type IdentityUserProjectionEntry struct {
	User           identitymodel.IdentityUser            `json:"user"`
	Roles          []IdentityUserProjectionRoleSummary   `json:"roles"`
	Security       IdentityUserProjectionSecuritySummary `json:"security"`
	IdentityBadges []IdentityUserProjectionBadge         `json:"identity_badges"`
}

type IdentityUserProjectionPage struct {
	Items    []IdentityUserProjectionEntry `json:"items"`
	PageSize int                           `json:"page_size"`
	Total    int                           `json:"total"`
	HasNext  bool                          `json:"has_next"`
	NextID   string                        `json:"next_id,omitempty"`
}

func (s *IdentityApplicationService) SearchUserProjection(ctx context.Context, query identitymodel.IdentityListQuery, security IdentityUserProjectionSecurityReader) (IdentityUserProjectionPage, error) {
	if security == nil {
		return IdentityUserProjectionPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_projection_security_unavailable", nil, nil)
	}
	return s.searchUserProjection(ctx, query, identitymodel.Principal{}, "", func(ctx context.Context, workspaceID string, userIDs []string) (map[string]IdentityUserProjectionSecuritySummary, error) {
		summaries := make(map[string]IdentityUserProjectionSecuritySummary, len(userIDs))
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

func (s *IdentityApplicationService) SearchUserProjectionWithinDataScope(ctx context.Context, query identitymodel.IdentityListQuery, actor identitymodel.Principal, permissionKey string, security IdentityUserProjectionSecurityReader) (IdentityUserProjectionPage, error) {
	if security == nil {
		return IdentityUserProjectionPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_projection_security_unavailable", nil, nil)
	}
	return s.searchUserProjection(ctx, query, actor, permissionKey, func(ctx context.Context, workspaceID string, userIDs []string) (map[string]IdentityUserProjectionSecuritySummary, error) {
		summaries := make(map[string]IdentityUserProjectionSecuritySummary, len(userIDs))
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

func (s *IdentityApplicationService) SearchUserProjectionBatch(ctx context.Context, query identitymodel.IdentityListQuery, security IdentityUserProjectionSecurityBatchReader) (IdentityUserProjectionPage, error) {
	if security == nil {
		return IdentityUserProjectionPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_projection_security_unavailable", nil, nil)
	}
	return s.searchUserProjection(ctx, query, identitymodel.Principal{}, "", security)
}

func (s *IdentityApplicationService) SearchUserProjectionBatchWithinDataScope(ctx context.Context, query identitymodel.IdentityListQuery, actor identitymodel.Principal, permissionKey string, security IdentityUserProjectionSecurityBatchReader) (IdentityUserProjectionPage, error) {
	if security == nil {
		return IdentityUserProjectionPage{}, apperror.New(apperror.KindUnavailable, "backend.identity.user_projection_security_unavailable", nil, nil)
	}
	return s.searchUserProjection(ctx, query, actor, permissionKey, security)
}

func (s *IdentityApplicationService) searchUserProjection(ctx context.Context, query identitymodel.IdentityListQuery, actor identitymodel.Principal, permissionKey string, security IdentityUserProjectionSecurityBatchReader) (IdentityUserProjectionPage, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return IdentityUserProjectionPage{}, err
	}
	var users identitymodel.IdentityUserPage
	if strings.TrimSpace(permissionKey) == "" {
		users, err = scoped.SearchUsers(ctx, query)
	} else {
		users, err = scoped.SearchUsersWithinDataScope(ctx, query, actor, permissionKey)
	}
	if err != nil {
		return IdentityUserProjectionPage{}, err
	}
	userIDs := make([]string, 0, len(users.Items))
	for _, user := range users.Items {
		userIDs = append(userIDs, user.ID)
	}
	var facts identitymodel.IdentityUserProjectionFacts
	if repository, ok := scoped.Repository().(identityrepository.IdentityUserProjectionFactsRepository); ok {
		facts, err = repository.ListIdentityUserProjectionFacts(ctx, scoped.WorkspaceID(), userIDs)
		if err != nil {
			return IdentityUserProjectionPage{}, err
		}
	} else {
		facts.RoleAssignments, err = scoped.Repository().ListIdentityUserRoleAssignments(ctx, scoped.WorkspaceID(), "")
		if err != nil {
			return IdentityUserProjectionPage{}, err
		}
		for _, userID := range userIDs {
			bindings, listErr := scoped.Repository().ListIdentityProfileBindingsByUser(ctx, scoped.WorkspaceID(), userID)
			if listErr != nil {
				return IdentityUserProjectionPage{}, listErr
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
		return IdentityUserProjectionPage{}, err
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
		return IdentityUserProjectionPage{}, err
	}
	items := make([]IdentityUserProjectionEntry, 0, len(users.Items))
	for _, user := range users.Items {
		entry := IdentityUserProjectionEntry{
			User: user, Security: securitySummaries[user.ID],
			Roles: []IdentityUserProjectionRoleSummary{}, IdentityBadges: []IdentityUserProjectionBadge{},
		}
		for _, assignment := range assignmentsByUser[user.ID] {
			role := roleByID[assignment.RoleID]
			entry.Roles = append(entry.Roles, IdentityUserProjectionRoleSummary{
				ID: assignment.RoleID, Key: role.Key, Label: role.Label,
				Source: assignment.Source, Status: assignment.Status,
			})
		}
		for _, binding := range bindingsByUser[user.ID] {
			if binding.Status == identitymodel.IdentityProfileBindingUnlinked {
				continue
			}
			entry.IdentityBadges = append(entry.IdentityBadges, IdentityUserProjectionBadge{
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
	return IdentityUserProjectionPage{
		Items: items, PageSize: users.PageSize, Total: users.Total, HasNext: users.HasNext, NextID: users.NextID,
	}, nil
}
