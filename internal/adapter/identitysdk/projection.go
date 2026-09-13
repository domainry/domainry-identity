package identitysdkadapter

import (
	"context"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityscope "github.com/domainry/domainry-identity-sdk/application"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// sdkProjection publishes only non-secret, read-only Runtime projections. All
// authoring commands remain behind Identity's management application service.
type sdkProjection struct{ binding *sdkBinding }

func (adapter sdkProjection) FindUser(ctx context.Context, request identitysdk.UserLookup) (identitysdk.User, bool, error) {
	identity, workspaceContext, err := adapter.scoped(ctx)
	if err != nil {
		return identitysdk.User{}, false, err
	}
	user, found, err := identity.FindUser(workspaceContext, string(request.UserID))
	return sdkProjectionUser(user), found, sdkBoundaryError(err)
}

func (adapter sdkProjection) FindOrganizationUnit(ctx context.Context, request identitysdk.OrganizationUnitLookup) (identitysdk.OrganizationUnit, bool, error) {
	identity, workspaceContext, err := adapter.scoped(ctx)
	if err != nil {
		return identitysdk.OrganizationUnit{}, false, err
	}
	organizationUnit, found, err := identity.FindOrganizationUnit(workspaceContext, strings.TrimSpace(request.OrgID))
	return sdkProjectionOrganizationUnit(organizationUnit), found, sdkBoundaryError(err)
}

func (adapter sdkProjection) ResolveDisplayNames(ctx context.Context, request identitysdk.DisplayNameQuery) (identitysdk.DisplayNameResult, error) {
	identity, workspaceContext, err := adapter.scoped(ctx)
	if err != nil {
		return identitysdk.DisplayNameResult{}, err
	}
	userIDs := sdkDisplayNameIDSet(request.UserIDs)
	organizationUnitIDs := sdkDisplayNameIDSet(request.OrganizationUnitIDs)
	if len(userIDs) > 1000 || len(organizationUnitIDs) > 1000 {
		return identitysdk.DisplayNameResult{}, &identitysdk.Error{Code: "identity.display_name_query_too_large"}
	}
	result := identitysdk.DisplayNameResult{Users: []identitysdk.DisplayName{}, OrganizationUnits: []identitysdk.DisplayName{}}
	users, organizationUnits, err := identity.ResolveProjectionDisplayNames(workspaceContext, sdkDisplayNameIDs(userIDs), sdkDisplayNameIDs(organizationUnitIDs))
	if err != nil {
		return identitysdk.DisplayNameResult{}, sdkBoundaryError(err)
	}
	for _, user := range users {
		result.Users = append(result.Users, sdkDisplayName(user.ID, user.Name))
	}
	for _, organizationUnit := range organizationUnits {
		result.OrganizationUnits = append(result.OrganizationUnits, sdkDisplayName(organizationUnit.ID, organizationUnit.Name))
	}
	sort.Slice(result.Users, func(left, right int) bool { return result.Users[left].ID < result.Users[right].ID })
	sort.Slice(result.OrganizationUnits, func(left, right int) bool {
		return result.OrganizationUnits[left].ID < result.OrganizationUnits[right].ID
	})
	return result, nil
}

func sdkDisplayNameIDs(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if values[value] {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func sdkDisplayNameIDSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result[value] = true
		}
	}
	return result
}

func sdkDisplayName(id, name string) identitysdk.DisplayName {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)
	if name == "" {
		name = id
	}
	return identitysdk.DisplayName{ID: id, Name: name}
}

func (adapter sdkProjection) ListUsers(ctx context.Context, request identitysdk.ProjectionQuery) ([]identitysdk.User, error) {
	identity, workspaceContext, err := adapter.scoped(ctx)
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
	identity, workspaceContext, err := adapter.scoped(ctx)
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
	identity, workspaceContext, err := adapter.scoped(ctx)
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

func (adapter sdkProjection) scoped(ctx context.Context) (*identityapplication.IdentityApplicationService, context.Context, error) {
	if adapter.binding == nil || adapter.binding.identity == nil {
		return nil, ctx, &identitysdk.Error{Code: "identity.projection_unavailable"}
	}
	scope, ok := identityscope.ScopeFromContext(ctx)
	if !ok {
		return nil, ctx, &identitysdk.Error{Code: "identity.application_scope_required"}
	}
	application := identitysdk.ApplicationRef{WorkspaceID: scope.WorkspaceID, ApplicationKey: scope.ApplicationKey}
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

var _ identitysdk.DisplayNameProjection = sdkProjection{}
