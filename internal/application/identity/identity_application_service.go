package identity

import (
	"context"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identitydomain "github.com/domainry/domainry-identity/internal/domain/identity/service"
)

// IdentityApplicationService owns Identity governance and reference-projection
// use cases. Bootstrap supplies the repository during construction.
type IdentityApplicationService struct {
	*identitydomain.IdentityDomainService
	userDeletionInspector IdentityUserDeletionInspector
	pagePermissions       identityAdminPagePermissionSource
}

type identityAdminPagePermissionSource interface {
	RequiredPermissionsForPage(string) ([]string, bool)
}

func NewIdentityApplicationService(repository identityrepository.IdentityRepository, permissions []identitymodel.IdentityPermissionDefinition) *IdentityApplicationService {
	return NewIdentityApplicationServiceWithDependencies(repository, permissions, IdentityApplicationServiceDependencies{})
}

func NewIdentityApplicationServiceWithPermissionSource(repository identityrepository.IdentityRepository, source identitydomain.IdentityPermissionDefinitionSource, actions *IdentityActionRegistry) *IdentityApplicationService {
	service := NewIdentityApplicationServiceWithDependencies(repository, nil, IdentityApplicationServiceDependencies{Actions: actions})
	service.IdentityDomainService = identitydomain.NewIdentityDomainServiceWithPermissionSource(repository, source)
	return service
}

type IdentityApplicationServiceDependencies struct {
	UserDeletionInspector IdentityUserDeletionInspector
	Actions               *IdentityActionRegistry
}

func NewIdentityApplicationServiceWithDependencies(repository identityrepository.IdentityRepository, permissions []identitymodel.IdentityPermissionDefinition, dependencies IdentityApplicationServiceDependencies) *IdentityApplicationService {
	deletionInspector := dependencies.UserDeletionInspector
	if deletionInspector == nil {
		deletionInspector = identityLocalDeletionInspector{}
	}
	service := &IdentityApplicationService{
		IdentityDomainService: identitydomain.NewIdentityDomainService(repository, permissions),
		userDeletionInspector: deletionInspector,
		pagePermissions:       identityBuiltinPagePermissions{},
	}
	if dependencies.Actions != nil {
		service.pagePermissions = dependencies.Actions
	}
	return service
}

// identityLocalDeletionInspector intentionally reports no dependencies outside
// Identity. The domain service still blocks deletion for Identity-owned role
// and profile bindings; host-module business records are not part of
// this standalone service.
type identityLocalDeletionInspector struct{}

func (identityLocalDeletionInspector) InspectIdentityUserDeletion(context.Context, string, string) (IdentityUserDeletionInspection, error) {
	return IdentityUserDeletionInspection{}, nil
}

func (s *IdentityApplicationService) ForWorkspace(workspaceID string) (*IdentityApplicationService, error) {
	scoped, err := s.IdentityDomainService.ForWorkspace(workspaceID)
	if err != nil {
		return nil, err
	}
	clone := &IdentityApplicationService{IdentityDomainService: scoped, userDeletionInspector: s.userDeletionInspector, pagePermissions: s.pagePermissions}
	return clone, nil
}

func identityAuthorizeQuery(principal identitymodel.Principal) error {
	if _, err := identitymodel.NewWorkspaceQueryScope(principal.WorkspaceID); !principal.Known || err != nil {
		return &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.workspace_scope_required", Err: err}
	}
	return nil
}
