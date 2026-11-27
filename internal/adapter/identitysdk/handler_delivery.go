package identitysdkadapter

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityscope "github.com/domainry/domainry-identity-sdk/application"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type sdkHandlerDelivery struct {
	binding *sdkBinding
}

func (binding *sdkBinding) HandlerDelivery() identitysdk.HandlerDelivery {
	return sdkHandlerDelivery{binding: binding}
}

func (adapter sdkHandlerDelivery) DeliverIdentity(ctx context.Context, request identitysdk.HandlerDeliveryRequest) (identitysdk.HandlerDeliveryResult, error) {
	if adapter.binding == nil || adapter.binding.handlerDelivery == nil {
		return identitysdk.HandlerDeliveryResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.handler_delivery_unavailable"}
	}
	scoped, workloadPrincipal, applicationKey, scopeErr := adapter.authorize(ctx, request.AccessToken, request.WorkloadAuthority, true)
	if scopeErr != nil {
		return identitysdk.HandlerDeliveryResult{}, scopeErr
	}
	adapter.binding = scoped
	result, err := adapter.binding.handlerDelivery.Deliver(ctx, identityapplication.IdentityHandlerDeliveryRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, VerifiedWorkloadPrincipal: workloadPrincipal, ApplicationKey: applicationKey, IdempotencyKey: request.IdempotencyKey,
		Operation: identitymodel.IdentityHandlerUserOperation(request.User.Operation), User: internalHandlerUser(request.User.User),
		ExpectedVersion: request.User.ExpectedVersion, LoginMode: identitymodel.IdentityHandlerLoginMode(request.User.LoginMode),
		RoleKeys: append([]string(nil), request.RoleKeys...), ProfileBinding: internalHandlerProfileBinding(request.ProfileBinding),
	})
	return sdkHandlerDeliveryResult(result), sdkBoundaryError(err)
}

func (adapter sdkHandlerDelivery) ResolveBoundIdentity(ctx context.Context, request identitysdk.HandlerBoundIdentityRequest) (identitysdk.HandlerBoundIdentity, error) {
	if adapter.binding == nil || adapter.binding.handlerDelivery == nil {
		return identitysdk.HandlerBoundIdentity{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.handler_delivery_unavailable"}
	}
	scoped, workloadPrincipal, applicationKey, scopeErr := adapter.authorize(ctx, request.AccessToken, request.WorkloadAuthority, false)
	if scopeErr != nil {
		return identitysdk.HandlerBoundIdentity{}, scopeErr
	}
	adapter.binding = scoped

	result, err := adapter.binding.handlerDelivery.ResolveBoundIdentity(ctx, identityapplication.IdentityHandlerBoundIdentityRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, VerifiedWorkloadPrincipal: workloadPrincipal, ApplicationKey: applicationKey, UserID: request.UserID,
		ProfileBinding: internalHandlerProfileBindingSelector(request.ProfileBinding),
	})
	if err != nil {
		return identitysdk.HandlerBoundIdentity{}, sdkBoundaryError(err)
	}
	projection := identitysdk.HandlerBoundIdentity{
		UserID: result.UserID, DisplayName: result.DisplayName, Status: string(result.Status), Active: result.Active,
		Version: result.Version, OrganizationID: result.OrganizationID, SupportOrganizationID: result.SupportOrganizationID,
		OrganizationPath: result.OrganizationPath, OrganizationScopeIDs: append([]string(nil), result.OrganizationScopeIDs...),
		SupportOrgScopeIDs: append([]string(nil), result.SupportOrgScopeIDs...), ManagerUserID: result.ManagerUserID,
		ReportingPath: result.ReportingPath, ReportingScopeUserIDs: append([]string(nil), result.ReportingScopeUserIDs...),
		RoleKeys: append([]string(nil), result.RoleKeys...),
	}
	if result.ProfileBinding != nil {
		projection.ProfileBinding = &identitysdk.HandlerProfileBinding{
			BindingKey: result.ProfileBinding.BindingKey, ObjectKey: result.ProfileBinding.ObjectKey, ProfileID: result.ProfileBinding.ProfileID,
			IdentityUserID: result.ProfileBinding.IdentityUserID, Status: string(result.ProfileBinding.Status), Version: result.ProfileBinding.Version,
		}
	}
	return projection, nil
}

func (adapter sdkHandlerDelivery) authorize(ctx context.Context, accessToken string, workload *identitysdk.HandlerWorkloadAuthority, mutable bool) (*sdkBinding, *identitymodel.Principal, string, error) {
	accessToken = strings.TrimSpace(accessToken)
	if (accessToken != "") == (workload != nil) {
		return nil, nil, "", &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.handler_delivery_authority_invalid"}
	}
	if workload == nil {
		scoped, err := adapter.binding.forToken(ctx, accessToken)
		if err != nil {
			return nil, nil, "", err
		}
		if mutable {
			claims, err := scoped.auth.VerifyAccessToken(ctx, accessToken)
			if err != nil {
				return nil, nil, "", sdkBoundaryError(err)
			}
			if err := scoped.requireMutableWorkspace(ctx, identitysdk.WorkspaceID(claims.WorkspaceID)); err != nil {
				return nil, nil, "", err
			}
		}
		return scoped, nil, "", nil
	}
	scope, ok := identityscope.ScopeFromContext(ctx)
	if !ok || workload.WorkspaceID != scope.WorkspaceID || !scope.WorkspaceID.Valid() || !scope.ApplicationKey.Valid() || strings.TrimSpace(adapter.binding.descriptor.Audience) != string(scope.ApplicationKey) {
		return nil, nil, "", &identitysdk.Error{Class: identitysdk.ErrorClassForbidden, Code: "identity.handler_delivery_application_scope_mismatch"}
	}
	scoped, err := adapter.binding.forApplication(ctx, identitysdk.ApplicationRef{WorkspaceID: scope.WorkspaceID, ApplicationKey: scope.ApplicationKey})
	if err != nil {
		return nil, nil, "", err
	}
	if mutable {
		if err := scoped.requireMutableWorkspace(ctx, scope.WorkspaceID); err != nil {
			return nil, nil, "", err
		}
	}
	identity, workspaceContext, err := (sdkProjection{binding: scoped}).scoped(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	principalRequest := identitysdk.PrincipalResolutionRequest{
		SubjectID: workload.SubjectID,
		RoleKey:   strings.TrimSpace(workload.RoleKey),
		Workload: &identitysdk.WorkflowWorkloadResolution{
			WorkflowKey: strings.TrimSpace(workload.WorkflowKey), DefinitionVersionID: strings.TrimSpace(workload.DefinitionVersionID), DefinitionVersion: workload.DefinitionVersion,
			ReleaseID: strings.TrimSpace(workload.ReleaseID), ReleaseDigest: strings.TrimSpace(workload.ReleaseDigest), TaskID: strings.TrimSpace(workload.TaskID),
			SourceEventID: strings.TrimSpace(workload.SourceEventID), InitiatorSubjectID: workload.InitiatorSubjectID,
		},
	}
	principal, _, err := (sdkPrincipalResolver{binding: scoped}).resolveWorkflowWorkloadPrincipal(identityscope.WithScope(workspaceContext, scope), principalRequest, identity)
	if err != nil {
		return nil, nil, "", err
	}
	return scoped, &principal, string(scope.ApplicationKey), nil
}

func internalHandlerProfileBindingSelector(value *identitysdk.HandlerProfileBindingSelector) *identityapplication.IdentityHandlerProfileBindingSelector {
	if value == nil {
		return nil
	}
	return &identityapplication.IdentityHandlerProfileBindingSelector{BindingKey: value.BindingKey, ObjectKey: value.ObjectKey, ProfileID: value.ProfileID}
}

func internalHandlerProfileBinding(value *identitysdk.HandlerProfileBindingMutation) *identityapplication.IdentityHandlerProfileBindingRequest {
	if value == nil {
		return nil
	}
	return &identityapplication.IdentityHandlerProfileBindingRequest{
		BindingKey: value.BindingKey, ObjectKey: value.ObjectKey, ProfileID: value.ProfileID,
		ExpectedVersion: value.ExpectedVersion, Reason: value.Reason, ApprovalID: value.ApprovalID,
	}
}

func internalHandlerUser(value identitysdk.User) identitymodel.IdentityUser {
	return identitymodel.IdentityUser{
		ID: value.ID, UserID: value.UserID, Name: value.Name, GivenName: value.GivenName, MiddleName: value.MiddleName, FamilyName: value.FamilyName,
		NamePrefix: value.NamePrefix, NameSuffix: value.NameSuffix, NativeName: value.NativeName, NameLocale: value.NameLocale,
		Email: value.Email, Phone: value.Phone, AccountType: identitymodel.IdentityAccountType(value.AccountType), Locale: value.Locale,
		Timezone: value.Timezone, OrgID: value.OrgID, SupportOrgID: value.SupportOrgID, ManagerUserID: value.ManagerUserID,
		ReportingPath: value.ReportingPath, WorkerNo: value.WorkerNo, WorkerType: identitymodel.IdentityWorkerType(value.WorkerType),
		WorkStatus: identitymodel.IdentityWorkStatus(value.WorkStatus), StartDate: value.StartDate, EndDate: value.EndDate,
		Status: identitymodel.IdentityStatus(value.Status), Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func sdkHandlerUser(value identitymodel.IdentityUser) identitysdk.User {
	return identitysdk.User{
		ID: value.ID, UserID: value.UserID, Name: value.Name, GivenName: value.GivenName, MiddleName: value.MiddleName, FamilyName: value.FamilyName,
		NamePrefix: value.NamePrefix, NameSuffix: value.NameSuffix, NativeName: value.NativeName, NameLocale: value.NameLocale,
		Email: value.Email, Phone: value.Phone, AccountType: string(value.AccountType), Locale: value.Locale, Timezone: value.Timezone,
		OrgID: value.OrgID, SupportOrgID: value.SupportOrgID, ManagerUserID: value.ManagerUserID, ReportingPath: value.ReportingPath,
		WorkerNo: value.WorkerNo, WorkerType: string(value.WorkerType), WorkStatus: string(value.WorkStatus), StartDate: value.StartDate,
		EndDate: value.EndDate, Status: string(value.Status), Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func sdkHandlerDeliveryResult(value identitymodel.IdentityHandlerDeliveryResult) identitysdk.HandlerDeliveryResult {
	result := identitysdk.HandlerDeliveryResult{
		DeliveryID: value.DeliveryID, User: sdkHandlerUser(value.User), RoleKeys: append([]string(nil), value.RoleKeys...),
		RevokedSessions: value.RevokedSessions, Replayed: value.Replayed,
	}
	if value.ProfileBinding != nil {
		result.ProfileBinding = &identitysdk.HandlerProfileBinding{
			BindingKey: value.ProfileBinding.BindingKey, ObjectKey: value.ProfileBinding.ObjectKey, ProfileID: value.ProfileBinding.ProfileID,
			IdentityUserID: value.ProfileBinding.IdentityUserID, Status: string(value.ProfileBinding.Status), Version: value.ProfileBinding.Version,
		}
	}
	if value.InitialPassword != "" {
		result.InitialCredential = &identitysdk.HandlerInitialCredential{
			InitialPassword: value.InitialPassword, MustChangePassword: value.MustChangePassword, NoStore: value.NoStore,
		}
	}
	return result
}

var _ identitysdk.HandlerDelivery = sdkHandlerDelivery{}
var _ identitysdk.HandlerDeliveryBinding = (*sdkBinding)(nil)
