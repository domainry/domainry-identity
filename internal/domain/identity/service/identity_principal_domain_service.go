package service

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// IdentityPrincipalDomainService resolves runtime principals from identity definitions.
type IdentityPrincipalDomainService struct {
	roles          func() []identitymodel.RoleSchema
	defaultRoleKey func() string
}

func NewIdentityPrincipalDomainService(roles func() []identitymodel.RoleSchema, defaultRoleKey func() string) *IdentityPrincipalDomainService {
	return &IdentityPrincipalDomainService{roles: roles, defaultRoleKey: defaultRoleKey}
}

func (s *IdentityPrincipalDomainService) Resolve(ctx context.Context, userID, roleKey, alternateRoleKey string) identitymodel.Principal {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return identitymodel.Principal{Known: false}
	}
	workspace, err := identitymodel.NewWorkspaceID(requestcontext.WorkspaceID(ctx))
	if err != nil {
		return identitymodel.Principal{UserID: userID, Known: false}
	}
	workspaceID := workspace.String()
	if strings.TrimSpace(roleKey) == "" {
		roleKey = alternateRoleKey
	}
	if strings.TrimSpace(roleKey) == "" && s.defaultRoleKey != nil {
		roleKey = s.defaultRoleKey()
	}
	roles := []identitymodel.RoleSchema{}
	if s.roles != nil {
		roles = s.roles()
	}
	if len(roles) == 0 {
		return identitymodel.Principal{UserID: userID, WorkspaceID: workspaceID, Known: false}
	}
	for _, role := range roles {
		if role.Key == strings.TrimSpace(roleKey) {
			return identitymodel.Principal{UserID: userID, WorkspaceID: workspaceID, Role: role, Known: true}
		}
	}
	return identitymodel.Principal{UserID: userID, WorkspaceID: workspaceID, Known: false}
}
