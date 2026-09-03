package auth

import (
	"context"

	"github.com/domainry/domainry-foundation/apperror"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthApplicationService) UserSecurityProfileGoverned(ctx context.Context, principal identitymodel.Principal, userID string) (authdomain.UserSecurityProfile, error) {
	if !identityUserAdministrationPermissionGranted(principal, identitycontract.IdentityUsersSecurityGetPermission) {
		return authdomain.UserSecurityProfile{}, authMutationError(apperror.KindForbidden, "auth.permission_denied")
	}
	return s.AuthDomainService.UserSecurityProfileWithinDataScope(ctx, principal.WorkspaceID, userID, identitycontract.IdentityPermissionDataScopeFilter(principal, identitycontract.IdentityUsersSecurityGetPermission))
}

func (s *AuthApplicationService) UnlockUserGoverned(ctx context.Context, principal identitymodel.Principal, userID string) error {
	if !identityUserAdministrationPermissionGranted(principal, identitycontract.IdentityUsersUnlockPermission) {
		return authMutationError(apperror.KindForbidden, "auth.permission_denied")
	}
	return s.AuthDomainService.UnlockUserWithinDataScope(ctx, principal.WorkspaceID, userID, identitycontract.IdentityPermissionDataScopeFilter(principal, identitycontract.IdentityUsersUnlockPermission))
}

func (s *AuthApplicationService) RevokeMFAFactorGoverned(ctx context.Context, principal identitymodel.Principal, userID, factorID string) error {
	if !identityUserAdministrationPermissionGranted(principal, identitycontract.IdentityUsersMFARevokePermission) {
		return authMutationError(apperror.KindForbidden, "auth.permission_denied")
	}
	return s.AuthDomainService.RevokeMFAFactorWithinDataScope(ctx, principal.WorkspaceID, userID, factorID, identitycontract.IdentityPermissionDataScopeFilter(principal, identitycontract.IdentityUsersMFARevokePermission))
}

func identityUserAdministrationPermissionGranted(principal identitymodel.Principal, permissionKey string) bool {
	return principal.Known && identitycontract.IdentityRoleHasPermissionKey(principal.Role, permissionKey)
}

func (s *AuthApplicationService) requireIdentityUserWithinDataScope(ctx context.Context, principal identitymodel.Principal, userID, permissionKey string, deniedKind apperror.ErrorKind, deniedCode string) error {
	repository, ok := s.repository.(authrepository.AuthUserDataScopeRepository)
	if !ok {
		return authMutationInternal(nil)
	}
	visible, err := repository.IdentityUserExistsWithinDataScope(ctx, principal.WorkspaceID, userID, identitycontract.IdentityPermissionDataScopeFilter(principal, permissionKey))
	if err != nil {
		return err
	}
	if !visible {
		return authMutationError(deniedKind, deniedCode)
	}
	return nil
}
