package service

import (
	"context"
	"strings"

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

func (s *IdentityPrincipalDomainService) Resolve(_ context.Context, userID, roleKey, alternateRoleKey string) identitymodel.Principal {
	userID = valueOrDefault(userID, "admin")
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
		return identitymodel.Principal{UserID: userID, WorkspaceID: "default", Known: true, Role: identitymodel.RoleSchema{Key: "developer", Name: "Developer", Permissions: []string{"workspace.admin"}, RecordScope: "all_records"}}
	}
	for _, role := range roles {
		if role.Key == strings.TrimSpace(roleKey) {
			return identitymodel.Principal{UserID: userID, WorkspaceID: "default", Role: role, Known: true}
		}
	}
	return identitymodel.Principal{UserID: userID, WorkspaceID: "default", Known: false}
}
