package assembly

import (
	"context"
	"strings"

	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	authpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/auth"
)

type identityProfileSystemRoleResolver struct {
	identity *identityapplication.IdentityApplicationService
}

func (r identityProfileSystemRoleResolver) ResolveIdentityProfileSystemRoleIDs(ctx context.Context, bindingKey string) ([]string, error) {
	roles, err := r.identity.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	roleIDs := make([]string, 0)
	for _, role := range roles {
		definition, found := r.identity.PublishedRoleDefinition(ctx, role.Key)
		if found && role.Status == identitymodel.IdentityStatusActive && definition.AssignmentMode == identitymodel.IdentityRoleAssignmentSystemManaged && strings.TrimSpace(definition.RequiredBindingKey) == strings.TrimSpace(bindingKey) {
			roleIDs = append(roleIDs, role.ID)
		}
	}
	return roleIDs, nil
}

type identityProfileSessionRevoker struct {
	auth *authapplication.AuthApplicationService
}

func (r identityProfileSessionRevoker) RevokeIdentityProfileSessions(ctx context.Context, workspaceID, userID, _ string) error {
	_, err := r.auth.ForceLogoutUser(ctx, workspaceID, userID)
	return err
}

type identityProfileExternalClaimVerifier struct {
	store authpersistence.AuthStore
}

func (v identityProfileExternalClaimVerifier) IdentityUserHasExternalSubject(ctx context.Context, workspaceID, userID, _ string, subject string) (bool, error) {
	accounts, err := v.store.ListIdentityExternalAccounts(ctx, workspaceID, userID)
	if err != nil {
		return false, err
	}
	for _, account := range accounts {
		if strings.TrimSpace(account.ProviderSubject) == strings.TrimSpace(subject) {
			return true, nil
		}
	}
	return false, nil
}
