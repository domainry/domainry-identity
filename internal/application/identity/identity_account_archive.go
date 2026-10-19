package identity

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

func (s *IdentityApplicationService) ArchiveUserWithinDataScope(ctx context.Context, userID string, expectedVersion int64, actor identitymodel.Principal) (int, error) {
	if !actor.Known || actor.UserID == strings.TrimSpace(userID) {
		return 0, apperror.New(apperror.KindForbidden, "backend.identity.user_archive_self_forbidden", nil, nil)
	}
	if expectedVersion < 1 {
		return 0, apperror.New(apperror.KindBadRequest, "backend.identity.user_version_required", nil, nil)
	}
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return 0, err
	}
	if actor.WorkspaceID != scoped.WorkspaceID() {
		return 0, apperror.New(apperror.KindForbidden, "backend.workspace_scope_required", nil, nil)
	}
	return scopedArchive(ctx, scoped.Repository(), scoped.WorkspaceID(), userID, expectedVersion, identitycontract.IdentityPermissionDataScopeFilter(actor, "identity.users.archive"))
}

// ArchiveDepartedUser is called only after a trusted IdP event has been verified
// and resolved to an existing external binding in this server-owned workspace.
func (s *IdentityApplicationService) ArchiveDepartedUser(ctx context.Context, workspaceID, userID string) (int, error) {
	scoped, err := s.ForWorkspace(workspaceID)
	if err != nil {
		return 0, err
	}
	return scopedArchive(ctx, scoped.Repository(), workspaceID, userID, 0, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func scopedArchive(ctx context.Context, repo identityrepository.IdentityRepository, workspaceID, userID string, version int64, filter identitymodel.IdentityDataScopeFilter) (int, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return 0, apperror.New(apperror.KindBadRequest, "backend.identity.user_required", nil, nil)
	}
	archive, ok := repo.(identityrepository.IdentityAccountArchiveRepository)
	if !ok {
		return 0, apperror.New(apperror.KindUnavailable, "backend.identity.user_archive_unavailable", nil, nil)
	}
	revoked, found, err := archive.ArchiveIdentityAccountWithinDataScope(ctx, workspaceID, userID, version, filter)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, apperror.New(apperror.KindNotFound, "backend.identity.user_not_found", nil, nil)
	}
	return revoked, nil
}
