package assembly

import (
	"context"

	"github.com/domainry/domainry-foundation/requestcontext"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// workspaceAuthIdentity adapts the workspace-neutral Auth domain port to the
// explicitly workspace-scoped Identity application service.
type workspaceAuthIdentity struct {
	identity *identityapplication.IdentityApplicationService
}

func (a workspaceAuthIdentity) scoped(ctx context.Context) (*identityapplication.IdentityApplicationService, error) {
	workspaceID := requestcontext.WorkspaceID(ctx)
	if workspaceID == "" {
		workspaceID = identitymodel.InstallationWorkspaceID
	}
	return a.identity.ForWorkspace(workspaceID)
}

func (a workspaceAuthIdentity) AssignUserRole(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment) error {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return err
	}
	return scoped.AssignUserRole(ctx, assignment)
}

func (a workspaceAuthIdentity) ListRoles(ctx context.Context) ([]identitymodel.IdentityRole, error) {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ListRoles(ctx)
}

func (a workspaceAuthIdentity) UpsertUser(ctx context.Context, user identitymodel.IdentityUser) error {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return err
	}
	return scoped.UpsertUser(ctx, user)
}

func (a workspaceAuthIdentity) UserByID(ctx context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	return scoped.UserByID(ctx, userID)
}

func (a workspaceAuthIdentity) UserByLogin(ctx context.Context, login string) (identitymodel.IdentityUser, bool, error) {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	return scoped.UserByLogin(ctx, login)
}

func (a workspaceAuthIdentity) ActiveRolesForUser(ctx context.Context, userID string) ([]identitymodel.IdentityRole, error) {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ActiveRolesForUser(ctx, userID)
}

func (a workspaceAuthIdentity) PublishedRoleDefinition(ctx context.Context, key string) (identitymodel.RoleSchema, bool) {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return identitymodel.RoleSchema{}, false
	}
	return scoped.PublishedRoleDefinition(ctx, key)
}

func (a workspaceAuthIdentity) ResolveEffectivePermissions(ctx context.Context, userID string) ([]string, error) {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return nil, err
	}
	return scoped.ResolveEffectivePermissions(ctx, userID)
}

func (a workspaceAuthIdentity) ResolvePrincipal(ctx context.Context, userID string) (identitymodel.Principal, error) {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	return scoped.ResolvePrincipal(ctx, userID)
}

func (a workspaceAuthIdentity) ReconcileSystemManagedBusinessRoles(ctx context.Context, userID string) error {
	scoped, err := a.scoped(ctx)
	if err != nil {
		return err
	}
	return scoped.ReconcileSystemManagedBusinessRoles(ctx, userID)
}

func (a workspaceAuthIdentity) UpdateUserLocale(ctx context.Context, workspaceID, userID, locale string, expectedVersion int64) (identitymodel.IdentityUser, error) {
	scoped, err := a.identity.ForWorkspace(workspaceID)
	if err != nil {
		return identitymodel.IdentityUser{}, err
	}
	return scoped.UpdateUserLocale(ctx, workspaceID, userID, locale, expectedVersion)
}

var _ authcontract.AuthSystemManagedRoleReconciler = workspaceAuthIdentity{}
