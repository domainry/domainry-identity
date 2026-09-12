package identitysdkadapter

import (
	"context"
	"net/http"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type sdkPrincipalResolver struct{ binding *sdkBinding }

func (adapter sdkPrincipalResolver) Resolve(ctx context.Context, request identitysdk.PrincipalResolutionRequest) (identitysdk.PrincipalResolution, error) {
	identity, workspaceContext, err := (sdkProjection{binding: adapter.binding}).scoped(ctx, request.Application)
	if err != nil {
		return identitysdk.PrincipalResolution{}, err
	}
	if request.Workload != nil {
		return adapter.resolveWorkflowWorkload(workspaceContext, request, identity)
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
	principal.TenantID = string(request.Application.TenantID)
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
	bundle := sdkAccessBundle(snapshot, principal, adapter.binding.clock.Now().UTC())
	result := identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: principal.Known,
		WorkspaceID: principal.WorkspaceID, UserID: principal.UserID, RoleKey: principal.Role.Key,
		AuthorizationRevision: principal.AuthorizationRevision,
		OrgID:                 principal.OrgID, OrgScopeIDs: append([]string(nil), principal.OrgScopeIDs...),
		SupportOrgID: principal.SupportOrgID, SupportOrgScopeIDs: append([]string(nil), principal.SupportOrgScopeIDs...),
		ReportingScopeUserIDs: append([]string(nil), principal.ReportingScopeUserIDs...),
		User:                  sdkProjectionUser(user), Permissions: identitymodel.RolePermissionKeys(principal.Role.Permissions), AccessBundle: &bundle,
	}
	for _, role := range roles {
		result.Roles = append(result.Roles, sdkProjectionRole(role))
	}
	return identitysdk.PrincipalResolution{Principal: result, AccessBundle: bundle}, nil
}

func (adapter sdkPrincipalResolver) resolveWorkflowWorkload(ctx context.Context, request identitysdk.PrincipalResolutionRequest, identity interface {
	WorkflowWorkloadBinding(context.Context, string, string) (identitymodel.IdentityWorkflowWorkloadBinding, bool, error)
	BuildWorkflowWorkloadPrincipal(context.Context, identitymodel.IdentityWorkflowWorkloadBinding) (identitymodel.Principal, error)
}) (identitysdk.PrincipalResolution, error) {
	workload := request.Workload
	workflowKey := strings.TrimSpace(workload.WorkflowKey)
	subjectID := identitysdk.WorkflowWorkloadSubjectID(workflowKey)
	if subjectID == "" || request.SubjectID != subjectID || strings.TrimSpace(request.RoleKey) == "" || strings.TrimSpace(workload.DefinitionVersionID) == "" || workload.DefinitionVersion <= 0 || strings.TrimSpace(workload.ReleaseDigest) == "" {
		return identitysdk.PrincipalResolution{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.workflow_workload_resolution_invalid"}
	}
	binding, found, err := identity.WorkflowWorkloadBinding(ctx, string(request.Application.ApplicationKey), workflowKey)
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	if !found || binding.Status != identitysdk.WorkflowWorkloadBindingActive {
		return identitysdk.PrincipalResolution{}, &identitysdk.Error{StatusCode: http.StatusNotFound, Code: "identity.workflow_workload_not_found"}
	}
	if binding.RoleKey != strings.TrimSpace(request.RoleKey) {
		return identitysdk.PrincipalResolution{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.workflow_workload_role_mismatch"}
	}
	if binding.DefinitionVersionID != strings.TrimSpace(workload.DefinitionVersionID) || binding.DefinitionVersion != workload.DefinitionVersion {
		return identitysdk.PrincipalResolution{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.workflow_workload_version_mismatch"}
	}
	if binding.ReleaseID != strings.TrimSpace(workload.ReleaseID) || binding.ReleaseDigest != strings.TrimSpace(workload.ReleaseDigest) {
		return identitysdk.PrincipalResolution{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.workflow_workload_release_digest_mismatch"}
	}
	principal, err := identity.BuildWorkflowWorkloadPrincipal(ctx, binding)
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	principal.TenantID = string(request.Application.TenantID)
	if !principal.Known {
		return identitysdk.PrincipalResolution{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.workflow_workload_role_unavailable"}
	}
	snapshot, err := adapter.binding.access.SnapshotWorkflowWorkload(ctx, principal)
	if err != nil {
		return identitysdk.PrincipalResolution{}, sdkBoundaryError(err)
	}
	bundle := sdkAccessBundle(snapshot, principal, adapter.binding.clock.Now().UTC())
	result := identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: true, WorkspaceID: principal.WorkspaceID, UserID: principal.UserID, RoleKey: principal.Role.Key,
		AuthorizationRevision: principal.AuthorizationRevision, Permissions: identitymodel.RolePermissionKeys(principal.Role.Permissions), AccessBundle: &bundle,
		User:     sdkProjectionUser(identitymodel.IdentityUser{ID: principal.UserID, Name: workflowKey, AccountType: identitymodel.IdentityAccountService, Status: identitymodel.IdentityStatusActive}),
		Roles:    []identitysdk.Role{sdkProjectionRole(identitymodel.IdentityRole{ID: principal.Role.Key, Key: principal.Role.Key, Label: principal.Role.Name, Status: identitymodel.IdentityStatusActive})},
		Workload: &identitysdk.WorkflowWorkloadPrincipalContext{WorkflowKey: workflowKey, DefinitionVersionID: workload.DefinitionVersionID, DefinitionVersion: workload.DefinitionVersion, ReleaseID: workload.ReleaseID, ReleaseDigest: workload.ReleaseDigest, TaskID: strings.TrimSpace(workload.TaskID), SourceEventID: strings.TrimSpace(workload.SourceEventID), InitiatorSubjectID: workload.InitiatorSubjectID},
	}
	return identitysdk.PrincipalResolution{Principal: result, AccessBundle: bundle}, nil
}
