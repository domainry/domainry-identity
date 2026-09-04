package identitysdkadapter

import (
	"context"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// sdkProjection publishes only non-secret, read-only Runtime projections. All
// authoring commands remain behind Identity's management application service.
type sdkProjection struct{ binding *sdkBinding }

func (adapter sdkProjection) FindUser(ctx context.Context, request identitysdk.UserLookup) (identitysdk.User, bool, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return identitysdk.User{}, false, err
	}
	user, found, err := identity.FindUser(workspaceContext, string(request.UserID))
	return sdkProjectionUser(user), found, sdkBoundaryError(err)
}

func (adapter sdkProjection) FindOrganizationUnit(ctx context.Context, request identitysdk.OrganizationUnitLookup) (identitysdk.OrganizationUnit, bool, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return identitysdk.OrganizationUnit{}, false, err
	}
	organizationUnit, found, err := identity.FindOrganizationUnit(workspaceContext, strings.TrimSpace(request.OrgID))
	return sdkProjectionOrganizationUnit(organizationUnit), found, sdkBoundaryError(err)
}

func (adapter sdkProjection) ListUsers(ctx context.Context, request identitysdk.ProjectionQuery) ([]identitysdk.User, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return nil, err
	}
	values, err := identity.ListProjectionUsers(workspaceContext)
	if err != nil {
		return nil, sdkBoundaryError(err)
	}
	result := make([]identitysdk.User, 0, len(values))
	for _, value := range values {
		result = append(result, sdkProjectionUser(value))
	}
	return result, nil
}

func (adapter sdkProjection) ListRoles(ctx context.Context, request identitysdk.ProjectionQuery) ([]identitysdk.Role, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return nil, err
	}
	values, err := identity.ListProjectionRoles(workspaceContext)
	if err != nil {
		return nil, sdkBoundaryError(err)
	}
	result := make([]identitysdk.Role, 0, len(values))
	for _, value := range values {
		result = append(result, sdkProjectionRole(value))
	}
	return result, nil
}

func (adapter sdkProjection) ListUserRoleAssignments(ctx context.Context, request identitysdk.UserRoleAssignmentQuery) ([]identitysdk.UserRoleAssignment, error) {
	identity, workspaceContext, err := adapter.scoped(ctx, request.Application)
	if err != nil {
		return nil, err
	}
	values, err := identity.ListProjectionUserRoleAssignments(workspaceContext, string(request.UserID))
	if err != nil {
		return nil, sdkBoundaryError(err)
	}
	result := make([]identitysdk.UserRoleAssignment, 0, len(values))
	for _, value := range values {
		result = append(result, sdkProjectionRoleAssignment(value))
	}
	return result, nil
}

func (adapter sdkProjection) scoped(ctx context.Context, scope identitysdk.ApplicationScope) (*identityapplication.IdentityApplicationService, context.Context, error) {
	if adapter.binding == nil || adapter.binding.identity == nil {
		return nil, ctx, &identitysdk.Error{Code: "identity.projection_unavailable"}
	}
	application := identitysdk.ApplicationRef{TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID, ApplicationKey: scope.ApplicationKey}
	if found, err := adapter.binding.applicationRegistered(ctx, application); err != nil {
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

func sdkProjectionUser(value identitymodel.IdentityUser) identitysdk.User {
	return identitysdk.User{
		ID: value.ID, Name: value.Name, GivenName: value.GivenName, MiddleName: value.MiddleName, FamilyName: value.FamilyName,
		NamePrefix: value.NamePrefix, NameSuffix: value.NameSuffix, NativeName: value.NativeName, NameLocale: value.NameLocale,
		Email: value.Email, Phone: value.Phone, AccountType: string(value.AccountType), Locale: value.Locale, Timezone: value.Timezone,
		OrgID: value.OrgID, ManagerUserID: value.ManagerUserID, ReportingPath: value.ReportingPath,
		WorkerNo: value.WorkerNo, WorkerType: string(value.WorkerType),
		WorkStatus: string(value.WorkStatus), StartDate: value.StartDate, EndDate: value.EndDate,
		Status: string(value.Status), Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func sdkProjectionOrganizationUnit(value identitymodel.IdentityOrganizationUnit) identitysdk.OrganizationUnit {
	return identitysdk.OrganizationUnit{
		ID: value.ID, Code: value.Code, Name: value.Name, NodeType: string(value.NodeType), ParentID: value.ParentID,
		Path: value.Path, AncestorIDs: append([]string(nil), value.AncestorIDs...), Depth: value.Depth, SortOrder: value.SortOrder, Status: string(value.Status),
	}
}

func sdkProjectionRole(value identitymodel.IdentityRole) identitysdk.Role {
	return identitysdk.Role{ID: value.ID, Key: value.Key, Label: value.Label, Description: value.Description, Status: string(value.Status)}
}

func sdkProjectionRoleAssignment(value identitymodel.IdentityUserRoleAssignment) identitysdk.UserRoleAssignment {
	return identitysdk.UserRoleAssignment{
		UserID: value.UserID, RoleID: value.RoleID, BindingKey: value.BindingKey,
		ProfileID: value.ProfileID, Source: value.Source, Status: value.Status, ValidFrom: value.ValidFrom, ValidUntil: value.ValidUntil,
		GrantedBy: value.GrantedBy, GrantReason: value.GrantReason, RevokedBy: value.RevokedBy, RevokedAt: value.RevokedAt,
		RevokeReason: value.RevokeReason, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, ExpiresAt: value.ExpiresAt,
	}
}
