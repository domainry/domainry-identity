package identitysdkadapter

import (
	"context"
	"net/http"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityscope "github.com/domainry/domainry-identity-sdk/application"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type sdkWorkflowWorkloads struct{ binding *sdkBinding }

func (adapter sdkWorkflowWorkloads) ApplyWorkflowWorkloadBindings(ctx context.Context, request identitysdk.ApplyWorkflowWorkloadBindingsRequest) (identitysdk.ApplyWorkflowWorkloadBindingsResult, error) {
	if adapter.binding == nil || adapter.binding.identity == nil {
		return identitysdk.ApplyWorkflowWorkloadBindingsResult{}, &identitysdk.Error{StatusCode: http.StatusNotImplemented, Code: "identity.workflow_workload_unavailable"}
	}
	if err := request.Validate(); err != nil {
		return identitysdk.ApplyWorkflowWorkloadBindingsResult{}, err
	}
	registered, err := adapter.binding.applicationRegistered(ctx, identitysdk.ApplicationRef{TenantID: request.Application.TenantID, WorkspaceID: request.Application.WorkspaceID, ApplicationKey: request.Application.ApplicationKey})
	if err != nil {
		return identitysdk.ApplyWorkflowWorkloadBindingsResult{}, sdkBoundaryError(err)
	}
	if !registered {
		return identitysdk.ApplyWorkflowWorkloadBindingsResult{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.application_not_registered"}
	}
	scoped, workspaceContext, err := (sdkProjection{binding: adapter.binding}).scoped(identityscope.WithScope(ctx, request.Application))
	if err != nil {
		return identitysdk.ApplyWorkflowWorkloadBindingsResult{}, err
	}
	release := identitymodel.IdentityWorkflowWorkloadRelease{
		WorkspaceID: string(request.Application.WorkspaceID), ApplicationKey: string(request.Application.ApplicationKey), ReleaseID: strings.TrimSpace(request.ReleaseID), ReleaseDigest: strings.TrimSpace(request.ReleaseDigest),
	}
	for _, binding := range request.Bindings {
		release.Bindings = append(release.Bindings, identitymodel.IdentityWorkflowWorkloadBinding{
			WorkflowKey: binding.WorkflowKey, DefinitionVersionID: binding.DefinitionVersionID, DefinitionVersion: binding.DefinitionVersion, RoleKey: binding.RoleKey, ActionKeys: append([]string(nil), binding.ActionKeys...),
		})
	}
	applied, err := scoped.ApplyWorkflowWorkloadRelease(workspaceContext, release)
	if err != nil {
		return identitysdk.ApplyWorkflowWorkloadBindingsResult{}, sdkBoundaryError(err)
	}
	result := identitysdk.ApplyWorkflowWorkloadBindingsResult{Bindings: make([]identitysdk.WorkflowWorkloadBinding, 0, len(applied))}
	for _, binding := range applied {
		result.Bindings = append(result.Bindings, sdkWorkflowWorkloadBinding(request.Application, binding))
	}
	return result, nil
}

func (adapter sdkWorkflowWorkloads) GetWorkflowWorkloadBinding(ctx context.Context, request identitysdk.GetWorkflowWorkloadBindingRequest) (identitysdk.WorkflowWorkloadBinding, error) {
	if err := request.Validate(); err != nil {
		return identitysdk.WorkflowWorkloadBinding{}, err
	}
	scoped, workspaceContext, err := (sdkProjection{binding: adapter.binding}).scoped(identityscope.WithScope(ctx, request.Application))
	if err != nil {
		return identitysdk.WorkflowWorkloadBinding{}, err
	}
	binding, found, err := scoped.WorkflowWorkloadBinding(workspaceContext, string(request.Application.ApplicationKey), strings.TrimSpace(request.WorkflowKey))
	if err != nil {
		return identitysdk.WorkflowWorkloadBinding{}, sdkBoundaryError(err)
	}
	if !found || binding.Status != identitysdk.WorkflowWorkloadBindingActive {
		return identitysdk.WorkflowWorkloadBinding{}, &identitysdk.Error{StatusCode: http.StatusNotFound, Code: "identity.workflow_workload_not_found"}
	}
	if binding.DefinitionVersionID != strings.TrimSpace(request.DefinitionVersionID) {
		return identitysdk.WorkflowWorkloadBinding{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.workflow_workload_version_mismatch"}
	}
	if binding.ReleaseDigest != strings.TrimSpace(request.ReleaseDigest) {
		return identitysdk.WorkflowWorkloadBinding{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.workflow_workload_release_digest_mismatch"}
	}
	return sdkWorkflowWorkloadBinding(request.Application, binding), nil
}

func sdkWorkflowWorkloadBinding(application identitysdk.ApplicationScope, binding identitymodel.IdentityWorkflowWorkloadBinding) identitysdk.WorkflowWorkloadBinding {
	return identitysdk.WorkflowWorkloadBinding{
		Application: application, SubjectID: identitysdk.SubjectID(binding.SubjectID), WorkflowKey: binding.WorkflowKey, DefinitionVersionID: binding.DefinitionVersionID, DefinitionVersion: binding.DefinitionVersion,
		RoleKey: binding.RoleKey, ActionKeys: append([]string(nil), binding.ActionKeys...), ReleaseID: binding.ReleaseID, ReleaseDigest: binding.ReleaseDigest, SourceKind: binding.SourceKind, SourceID: binding.SourceID, Status: binding.Status, CreatedAt: binding.CreatedAt, UpdatedAt: binding.UpdatedAt, DeactivatedAt: binding.DeactivatedAt,
	}
}

var _ identitysdk.WorkflowWorkloadIdentity = sdkWorkflowWorkloads{}
