package identity

import (
	"context"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// RoleDirectory computes all summaries from one roles query, one assignment
// query and the current published definitions; never one query per row.
type RoleDirectoryEntry struct {
	identitymodel.IdentityRole
	PermissionCount int                                      `json:"permission_count"`
	MemberCount     int                                      `json:"member_count"`
	Audience        identitymodel.IdentityRoleAudience       `json:"audience"`
	AssignmentMode  identitymodel.IdentityRoleAssignmentMode `json:"assignment_mode"`
	RiskLevel       identitymodel.IdentityRoleRiskLevel      `json:"risk_level"`
}

func (s *IdentityApplicationService) RoleDirectory(ctx context.Context) ([]RoleDirectoryEntry, error) {
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := scoped.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	assignments, err := scoped.ListUserRoleAssignments(ctx, "")
	if err != nil {
		return nil, err
	}
	members := map[string]map[string]bool{}
	for _, assignment := range assignments {
		if assignment.Status != "" && assignment.Status != "active" {
			continue
		}
		if members[assignment.RoleID] == nil {
			members[assignment.RoleID] = map[string]bool{}
		}
		members[assignment.RoleID][assignment.UserID] = true
	}
	result := make([]RoleDirectoryEntry, 0, len(roles))
	for _, role := range roles {
		definition, _ := scoped.PublishedRoleDefinition(ctx, role.Key)
		unique := map[string]bool{}
		for _, permission := range definition.Permissions {
			unique[permission.PermissionKey] = true
		}
		users := map[string]bool{}
		for id := range members[role.RoleID] {
			users[id] = true
		}
		for id := range members[role.Key] {
			users[id] = true
		}
		result = append(result, RoleDirectoryEntry{IdentityRole: role, PermissionCount: len(unique), MemberCount: len(users), Audience: definition.Audience, AssignmentMode: definition.AssignmentMode, RiskLevel: definition.RiskLevel})
	}
	return result, nil
}
