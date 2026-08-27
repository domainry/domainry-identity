package identitysdkadapter

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// sdkDirectory publishes only non-secret, read-only Runtime projections. All
// authoring commands remain behind Identity's management application service.
type sdkDirectory struct{ binding *sdkBinding }

func (adapter sdkDirectory) FindUser(ctx context.Context, request identitysdk.UserLookup) (identitysdk.User, bool, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return identitysdk.User{}, false, err
	}
	user, found, err := identity.FindUser(workspaceContext, string(request.UserID))
	return sdkDirectoryUser(user), found, sdkBoundaryError(err)
}

func (adapter sdkDirectory) FindDepartment(ctx context.Context, request identitysdk.DepartmentLookup) (identitysdk.Department, bool, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return identitysdk.Department{}, false, err
	}
	department, found, err := identity.FindDepartment(workspaceContext, strings.TrimSpace(request.DepartmentID))
	return sdkDirectoryDepartment(department), found, sdkBoundaryError(err)
}

func (adapter sdkDirectory) ListUsers(ctx context.Context, request identitysdk.DirectoryQuery) ([]identitysdk.User, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return nil, err
	}
	values, err := identity.ListDirectoryUsers(workspaceContext)
	if err != nil {
		return nil, sdkBoundaryError(err)
	}
	result := make([]identitysdk.User, 0, len(values))
	for _, value := range values {
		result = append(result, sdkDirectoryUser(value))
	}
	return result, nil
}

func (adapter sdkDirectory) ListRoles(ctx context.Context, request identitysdk.DirectoryQuery) ([]identitysdk.Role, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return nil, err
	}
	values, err := identity.ListDirectoryRoles(workspaceContext)
	if err != nil {
		return nil, sdkBoundaryError(err)
	}
	result := make([]identitysdk.Role, 0, len(values))
	for _, value := range values {
		result = append(result, sdkDirectoryRole(value))
	}
	return result, nil
}

func (adapter sdkDirectory) ListUserRoleAssignments(ctx context.Context, request identitysdk.UserRoleAssignmentQuery) ([]identitysdk.UserRoleAssignment, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return nil, err
	}
	values, err := identity.ListDirectoryUserRoleAssignments(workspaceContext, string(request.UserID))
	if err != nil {
		return nil, sdkBoundaryError(err)
	}
	result := make([]identitysdk.UserRoleAssignment, 0, len(values))
	for _, value := range values {
		result = append(result, sdkDirectoryRoleAssignment(value))
	}
	return result, nil
}

func (adapter sdkDirectory) ListWorkforce(ctx context.Context, request identitysdk.DirectoryQuery) ([]identitysdk.WorkforceEntry, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return nil, err
	}
	values, err := identity.ListDirectoryWorkforce(workspaceContext)
	if err != nil {
		return nil, sdkBoundaryError(err)
	}
	result := make([]identitysdk.WorkforceEntry, 0, len(values))
	for _, value := range values {
		result = append(result, sdkDirectoryWorkforce(value))
	}
	return result, nil
}

func (adapter sdkDirectory) scoped(ctx context.Context, scope identitysdk.ApplicationScope) (*identityapplication.IdentityApplicationService, context.Context, error) {
	if adapter.binding == nil || adapter.binding.identity == nil {
		return nil, ctx, &identitysdk.Error{Code: "identity.directory_unavailable"}
	}
	application := identitysdk.ApplicationRef{TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID, ApplicationKey: scope.ApplicationKey}
	if _, _, found, err := adapter.binding.loadCatalog(ctx, application); err != nil {
		return nil, ctx, sdkBoundaryError(err)
	} else if !found {
		return nil, ctx, &identitysdk.Error{Code: "identity.application_not_registered"}
	}
	identity, err := adapter.binding.identity.ForWorkspace(string(scope.WorkspaceID))
	if err != nil {
		return nil, ctx, sdkBoundaryError(err)
	}
	return identity, requestcontext.WithWorkspaceID(ctx, string(scope.WorkspaceID)), nil
}

func sdkDirectoryUser(value identitymodel.IdentityUser) identitysdk.User {
	return identitysdk.User{
		ID: value.ID, Name: value.Name, GivenName: value.GivenName, MiddleName: value.MiddleName, FamilyName: value.FamilyName,
		NamePrefix: value.NamePrefix, NameSuffix: value.NameSuffix, NativeName: value.NativeName, NameLocale: value.NameLocale,
		Email: value.Email, Phone: value.Phone, AccountType: string(value.AccountType), Locale: value.Locale, Timezone: value.Timezone,
		Status: string(value.Status), Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func sdkDirectoryDepartment(value identitymodel.IdentityDepartment) identitysdk.Department {
	return identitysdk.Department{
		ID: value.ID, Name: value.Name, ParentID: value.ParentID, LeaderWorkforceProfileID: value.LeaderWorkforceProfileID,
		Path: value.Path, AncestorIDs: append([]string(nil), value.AncestorIDs...), Depth: value.Depth, SortOrder: value.SortOrder, Status: string(value.Status),
	}
}

func sdkDirectoryRole(value identitymodel.IdentityRole) identitysdk.Role {
	return identitysdk.Role{ID: value.ID, Key: value.Key, Label: value.Label, Description: value.Description, Status: string(value.Status)}
}

func sdkDirectoryRoleAssignment(value identitymodel.IdentityUserRoleAssignment) identitysdk.UserRoleAssignment {
	return identitysdk.UserRoleAssignment{
		UserID: value.UserID, RoleID: value.RoleID, WorkforceProfileID: value.WorkforceProfileID, BindingKey: value.BindingKey,
		ProfileID: value.ProfileID, Source: value.Source, Status: value.Status, ValidFrom: value.ValidFrom, ValidUntil: value.ValidUntil,
		GrantedBy: value.GrantedBy, GrantReason: value.GrantReason, RevokedBy: value.RevokedBy, RevokedAt: value.RevokedAt,
		RevokeReason: value.RevokeReason, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, ExpiresAt: value.ExpiresAt,
	}
}

func sdkDirectoryWorkforce(value identitymodel.IdentityWorkforceDirectoryEntry) identitysdk.WorkforceEntry {
	return identitysdk.WorkforceEntry{
		WorkforceProfileID: value.WorkforceProfileID, IdentityUserID: value.IdentityUserID, OrganizationUnitID: value.OrganizationUnitID,
		OrganizationPath: value.OrganizationPath, ManagerIdentityUserID: value.ManagerIdentityUserID, ReportingPath: value.ReportingPath,
	}
}
