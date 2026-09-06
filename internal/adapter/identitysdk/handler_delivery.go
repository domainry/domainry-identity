package identitysdkadapter

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
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
		return identitysdk.HandlerDeliveryResult{}, &identitysdk.Error{Code: "identity.handler_delivery_unavailable"}
	}
	claims, err := adapter.binding.auth.VerifyAccessToken(ctx, strings.TrimSpace(request.AccessToken))
	if err != nil {
		return identitysdk.HandlerDeliveryResult{}, sdkBoundaryError(err)
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, identitysdk.WorkspaceID(claims.WorkspaceID)); err != nil {
		return identitysdk.HandlerDeliveryResult{}, err
	}
	result, err := adapter.binding.handlerDelivery.Deliver(ctx, identityapplication.IdentityHandlerDeliveryRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, IdempotencyKey: request.IdempotencyKey,
		Operation: identitymodel.IdentityHandlerUserOperation(request.User.Operation), User: internalHandlerUser(request.User.User),
		ExpectedVersion: request.User.ExpectedVersion, LoginMode: identitymodel.IdentityHandlerLoginMode(request.User.LoginMode),
		RoleKeys: append([]string(nil), request.RoleKeys...), ProfileBinding: internalHandlerProfileBinding(request.ProfileBinding),
	})
	return sdkHandlerDeliveryResult(result), sdkBoundaryError(err)
}

func (adapter sdkHandlerDelivery) ResolveBoundIdentity(ctx context.Context, request identitysdk.HandlerBoundIdentityRequest) (identitysdk.HandlerBoundIdentity, error) {
	if adapter.binding == nil || adapter.binding.handlerDelivery == nil {
		return identitysdk.HandlerBoundIdentity{}, &identitysdk.Error{Code: "identity.handler_delivery_unavailable"}
	}
	result, err := adapter.binding.handlerDelivery.ResolveBoundIdentity(ctx, identityapplication.IdentityHandlerBoundIdentityRequest{
		ContractVersion: request.ContractVersion, AccessToken: request.AccessToken, UserID: request.UserID,
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
		ID: value.ID, Name: value.Name, GivenName: value.GivenName, MiddleName: value.MiddleName, FamilyName: value.FamilyName,
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
		ID: value.ID, Name: value.Name, GivenName: value.GivenName, MiddleName: value.MiddleName, FamilyName: value.FamilyName,
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
