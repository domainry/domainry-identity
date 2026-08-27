package identitysdkadapter

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type sdkPrincipalResolver struct{ binding *sdkBinding }

func (adapter sdkPrincipalResolver) Resolve(ctx context.Context, request identitysdk.PrincipalResolutionRequest) (identitysdk.PrincipalResolution, error) {
	identity, workspaceContext, err := (sdkDirectory{binding: adapter.binding}).scoped(ctx, request.Application)
	if err != nil {
		return identitysdk.PrincipalResolution{}, err
	}
	var principal identitymodel.Principal
	if roleKey := strings.TrimSpace(request.RoleKey); roleKey != "" {
		principal, err = identity.ResolvePrincipalForRole(workspaceContext, string(request.SubjectID), roleKey)
	} else {
		principal, err = identity.ResolvePrincipal(workspaceContext, string(request.SubjectID))
	}
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	user, found, err := identity.FindUser(workspaceContext, principal.UserID)
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	if !found {
		return identitysdk.PrincipalResolution{}, &identitysdk.Error{Code: "identity.subject_not_found"}
	}
	roles, err := identity.ResolveEffectiveRoles(workspaceContext, principal.UserID)
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	snapshot, err := adapter.binding.access.Snapshot(workspaceContext, principal.UserID, principal)
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	catalog, receipt, found, err := adapter.binding.loadCatalog(ctx, identitysdk.ApplicationRef{
		TenantID: request.Application.TenantID, WorkspaceID: request.Application.WorkspaceID, ApplicationKey: request.Application.ApplicationKey,
	})
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	if !found {
		return identitysdk.PrincipalResolution{}, &identitysdk.Error{Code: "identity.catalog_not_published"}
	}
	bundle := sdkAccessBundle(snapshot, principal, string(receipt.Revision), adapter.binding.clock.Now().UTC())
	bundle = resolveCatalogRoleAccess(bundle, catalog, principal.Role)
	bundle, err = accessBundleForCatalog(bundle, catalog)
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	result := identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: principal.Known,
		WorkspaceID: principal.WorkspaceID, UserID: principal.UserID, RoleKey: principal.Role.Key,
		AuthorizationRevision: principal.AuthorizationRevision, WorkforceProfileID: principal.WorkforceProfileID,
		DepartmentID: principal.DepartmentID, DepartmentPath: principal.DepartmentPath, ReportingPath: principal.ReportingPath,
		ReportingUserIDs: append([]string(nil), principal.ReportingUserIDs...),
		OrganizationScopes: identitysdk.OrganizationScopes{
			TeamIDs: append([]string(nil), principal.TeamIDs...), StoreIDs: append([]string(nil), principal.StoreIDs...),
			TerritoryIDs: append([]string(nil), principal.TerritoryIDs...), WarehouseIDs: append([]string(nil), principal.WarehouseIDs...),
		},
		User: sdkDirectoryUser(user), Permissions: append([]string(nil), principal.Role.Permissions...), AccessBundle: &bundle,
	}
	for _, role := range roles {
		result.Roles = append(result.Roles, sdkDirectoryRole(role))
	}
	return identitysdk.PrincipalResolution{Principal: result, AccessBundle: bundle}, nil
}
