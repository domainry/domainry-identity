package identitysdkadapter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityevaluator "github.com/domainry/domainry-identity-sdk/authorization/evaluator"
	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type BindingDependencies struct {
	WorkspaceResolver     identitysdk.WorkspaceResolver
	Config                config.Config
	Authentication        *authapplication.AuthApplicationService
	ProviderConfiguration *authapplication.AuthProviderApplicationService
	ProviderFlows         *authapplication.AuthProviderFlowApplicationService
	ProviderCallback      authcontract.AuthProviderCallbackAdapter
	EffectiveAccess       *identityapplication.IdentityEffectiveAccessApplicationService
	Identity              *identityapplication.IdentityApplicationService
	Applications          *authapplication.AuthApplicationRegistrationService
	Permissions           *identityapplication.IdentityPermissionCatalogApplicationService
	HandlerDelivery       *identityapplication.IdentityHandlerDeliveryApplicationService
	StoreOrganizations    *identityapplication.IdentityStoreOrganizationDeliveryApplicationService
	OrganizationUnits     *identityapplication.IdentityOrganizationUnitDeliveryApplicationService
	Clock                 identitysdk.Clock
	MutationFence         IdentityMutationFence
	LoginTransactions     FederatedLoginTransactionReader
}

type sdkBinding struct {
	workspaceResolver  identitysdk.WorkspaceResolver
	descriptor         identitysdk.Descriptor
	auth               *authapplication.AuthApplicationService
	providers          *authapplication.AuthProviderApplicationService
	flows              *authapplication.AuthProviderFlowApplicationService
	providerCallback   authcontract.AuthProviderCallbackAdapter
	access             *identityapplication.IdentityEffectiveAccessApplicationService
	identity           *identityapplication.IdentityApplicationService
	applications       *authapplication.AuthApplicationRegistrationService
	permissions        *identityapplication.IdentityPermissionCatalogApplicationService
	handlerDelivery    *identityapplication.IdentityHandlerDeliveryApplicationService
	storeOrganizations *identityapplication.IdentityStoreOrganizationDeliveryApplicationService
	organizationUnits  *identityapplication.IdentityOrganizationUnitDeliveryApplicationService
	clock              identitysdk.Clock
	mutationFence      IdentityMutationFence
	loginTransactions  FederatedLoginTransactionReader
	capabilities       *modulecapability.StaticBinding
}

func NewBinding(dependencies BindingDependencies) (identitysdk.Binding, error) {
	if dependencies.Authentication == nil || dependencies.ProviderConfiguration == nil || dependencies.ProviderFlows == nil ||
		dependencies.ProviderCallback == nil || dependencies.EffectiveAccess == nil || dependencies.Identity == nil ||
		dependencies.Applications == nil || dependencies.Permissions == nil || dependencies.HandlerDelivery == nil || dependencies.StoreOrganizations == nil || dependencies.OrganizationUnits == nil || dependencies.MutationFence == nil || dependencies.LoginTransactions == nil {
		return nil, errors.New("complete Identity SDK Binding dependencies are required")
	}
	if dependencies.Clock == nil {
		dependencies.Clock = sdkSystemClock{}
	}
	binding := &sdkBinding{descriptor: identitysdk.Descriptor{
		ProtocolVersion: identitysdk.CurrentProtocolVersion, BundleVersion: identitysdk.CurrentPolicyBundleVersion, AuthorizationVersion: identitysdk.CurrentAuthorizationContractVersion,
		Mode: identitysdk.DeploymentModeModule, Issuer: defaultString(dependencies.Config.AuthIssuer, "http://localhost:8081"), Audience: defaultString(dependencies.Config.AuthAudience, "domainry-runtime"),
		Capabilities: []string{"authentication", "challenge_authentication", "action_assurance", "token_verification", "authorization", "principal_resolution", "workflow_workload_identity", "identity_projection", "handler_delivery", "store_organization_delivery", "organization_unit_delivery", "application_registration", "permission_reconciliation", "credentials", "oidc", "saml"},
	}, auth: dependencies.Authentication, providers: dependencies.ProviderConfiguration, flows: dependencies.ProviderFlows,
		providerCallback: dependencies.ProviderCallback, access: dependencies.EffectiveAccess, identity: dependencies.Identity,
		workspaceResolver: dependencies.WorkspaceResolver, applications: dependencies.Applications, permissions: dependencies.Permissions, handlerDelivery: dependencies.HandlerDelivery, storeOrganizations: dependencies.StoreOrganizations, organizationUnits: dependencies.OrganizationUnits, clock: dependencies.Clock,
		mutationFence: dependencies.MutationFence, loginTransactions: dependencies.LoginTransactions}
	capabilities, err := NewCapabilityBinding()
	if err != nil {
		return nil, fmt.Errorf("assemble Identity capability binding: %w", err)
	}
	binding.capabilities = capabilities
	return binding, nil
}

func (binding *sdkBinding) Descriptor() identitysdk.Descriptor { return binding.descriptor }
func (binding *sdkBinding) CapabilitySummary(ctx context.Context) (modulecapability.ModuleSummary, error) {
	return binding.capabilities.CapabilitySummary(ctx)
}
func (binding *sdkBinding) CapabilityCategory(ctx context.Context, key string) (modulecapability.CategoryDocument, error) {
	return binding.capabilities.CapabilityCategory(ctx, key)
}
func (binding *sdkBinding) ValidateCapabilityCandidate(ctx context.Context, request modulecapability.ValidationRequest) (modulecapability.ValidationResult, error) {
	return binding.capabilities.ValidateCapabilityCandidate(ctx, request)
}
func (binding *sdkBinding) Authentication() identitysdk.Authentication {
	return sdkAuthentication{binding}
}
func (binding *sdkBinding) ChallengeAuthentication() identitysdk.ChallengeAuthentication {
	return sdkAuthentication{binding}
}
func (binding *sdkBinding) ActionAssurance() identitysdk.ActionAssurance {
	return sdkActionAssurance{binding: binding}
}
func (binding *sdkBinding) Tokens() identitysdk.TokenVerifier { return sdkTokenVerifier{binding} }
func (binding *sdkBinding) Authorization() identitysdk.Authorization {
	return sdkAuthorization{binding}
}
func (binding *sdkBinding) Principals() identitysdk.PrincipalResolver {
	return sdkPrincipalResolver{binding: binding}
}
func (binding *sdkBinding) WorkflowWorkloads() identitysdk.WorkflowWorkloadIdentity {
	return sdkWorkflowWorkloads{binding: binding}
}
func (binding *sdkBinding) Projection() identitysdk.Projection {
	return sdkProjection{binding: binding}
}
func (binding *sdkBinding) Applications() identitysdk.ApplicationRegistry {
	return sdkApplications{binding: binding}
}
func (binding *sdkBinding) Permissions() identitysdk.PermissionRegistry {
	return sdkPermissions{binding: binding}
}
func (binding *sdkBinding) Credentials() identitysdk.CredentialManager {
	return sdkCredentials{binding}
}

func (binding *sdkBinding) ApplicationServiceVerifier() identitysdk.ApplicationServiceTokenVerifier {
	return sdkApplicationServiceVerifier{binding: binding}
}

func (binding *sdkBinding) Close(context.Context) error { return nil }

var _ identitysdk.WorkflowWorkloadIdentityBinding = (*sdkBinding)(nil)

type sdkAuthentication struct{ binding *sdkBinding }

type sdkActionAssurance struct{ binding *sdkBinding }

func (adapter sdkActionAssurance) BeginActionAssurance(ctx context.Context, request identitysdk.BeginActionAssuranceRequest) (identitysdk.ProviderChallenge, error) {
	claims, err := adapter.userClaims(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return identitysdk.ProviderChallenge{}, err
	}
	result, err := adapter.binding.flows.BeginActionAssurance(requestcontext.WithWorkspaceID(ctx, claims.WorkspaceID), claims.WorkspaceID, claims.Subject)
	if err != nil {
		return identitysdk.ProviderChallenge{}, sdkBoundaryError(err)
	}
	return sdkProviderChallenge(result), nil
}

func (adapter sdkActionAssurance) VerifyActionAssurance(ctx context.Context, request identitysdk.VerifyActionAssuranceRequest) (identitysdk.ActionAssuranceReceipt, error) {
	claims, err := adapter.userClaims(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return identitysdk.ActionAssuranceReceipt{}, err
	}
	receipt, err := adapter.binding.flows.VerifyActionAssurance(requestcontext.WithWorkspaceID(ctx, claims.WorkspaceID), claims.WorkspaceID, claims.Subject, request.Provider, request.State, request.Code)
	if err != nil {
		return identitysdk.ActionAssuranceReceipt{}, sdkBoundaryError(err)
	}
	return sdkActionAssuranceReceipt(receipt), nil
}

func (adapter sdkActionAssurance) ValidateActionAssuranceReceipt(ctx context.Context, request identitysdk.ValidateActionAssuranceReceiptRequest) (identitysdk.ActionAssuranceReceipt, error) {
	claims, err := adapter.userClaims(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return identitysdk.ActionAssuranceReceipt{}, err
	}
	if claims.Subject != string(request.SubjectID) {
		return identitysdk.ActionAssuranceReceipt{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "auth.action_assurance_receipt_invalid"}
	}
	receipt, err := adapter.binding.auth.ValidateActionAssuranceReceipt(ctx, request.Token, string(request.WorkspaceID), string(request.SubjectID))
	if err != nil {
		return identitysdk.ActionAssuranceReceipt{}, sdkBoundaryError(err)
	}
	return sdkActionAssuranceReceipt(receipt), nil
}

func (adapter sdkActionAssurance) userClaims(ctx context.Context, workspaceID identitysdk.WorkspaceID, accessToken string) (authmodel.AuthClaims, error) {
	if !workspaceID.Valid() || strings.TrimSpace(accessToken) == "" {
		return authmodel.AuthClaims{}, &identitysdk.Error{StatusCode: http.StatusUnauthorized, Code: "auth.token_required"}
	}
	claims, err := adapter.binding.auth.VerifyAccessToken(requestcontext.WithWorkspaceID(ctx, string(workspaceID)), accessToken)
	if err != nil {
		return authmodel.AuthClaims{}, sdkBoundaryError(err)
	}
	if claims.WorkspaceID != string(workspaceID) {
		return authmodel.AuthClaims{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "auth.workspace_mismatch"}
	}
	return claims, nil
}

func sdkActionAssuranceReceipt(receipt authmodel.AuthActionAssuranceReceipt) identitysdk.ActionAssuranceReceipt {
	return identitysdk.ActionAssuranceReceipt{Token: receipt.Token, WorkspaceID: identitysdk.WorkspaceID(receipt.WorkspaceID), SubjectID: identitysdk.SubjectID(receipt.UserID), Methods: append([]string(nil), receipt.Methods...), ExpiresAt: receipt.ExpiresAt}
}

var _ identitysdk.ActionAssurance = sdkActionAssurance{}

func (adapter sdkAuthentication) Providers(ctx context.Context, query identitysdk.ProviderQuery) ([]identitysdk.Provider, error) {
	if !query.WorkspaceID.Valid() {
		return nil, &identitysdk.Error{Code: "backend.workspace_scope_required"}
	}
	values := adapter.binding.providers.ListSafe(requestcontext.WithWorkspaceID(ctx, string(query.WorkspaceID)))
	providers := make([]identitysdk.Provider, 0, len(values))
	for _, value := range values {
		provider := identitysdk.Provider{Key: sdkMapString(value, "key"), Label: sdkMapString(value, "label"), Type: sdkMapString(value, "type"), Enabled: sdkMapBool(value, "enabled"), Priority: sdkMapString(value, "priority"), Market: sdkMapString(value, "market"), Issuer: sdkMapString(value, "issuer"), AuthURL: sdkMapString(value, "auth_url"), RedirectURL: sdkMapString(value, "redirect_url"), Scope: sdkMapString(value, "scope")}
		provider.Markets, provider.Channels = sdkMapStrings(value, "markets"), sdkMapStrings(value, "channels")
		providers = append(providers, provider)
	}
	return providers, nil
}

func (adapter sdkAuthentication) LoginWithPassword(ctx context.Context, request identitysdk.PasswordLoginRequest) (identitysdk.AuthSession, error) {
	outcome, err := adapter.LoginWithPasswordOutcome(ctx, request)
	return sdkAuthenticatedSession(outcome, err)
}

func (adapter sdkAuthentication) LoginWithPasswordOutcome(ctx context.Context, request identitysdk.PasswordLoginRequest) (identitysdk.AuthenticationOutcome, error) {
	if !request.WorkspaceID.Valid() {
		return identitysdk.AuthenticationOutcome{}, &identitysdk.Error{Code: "backend.workspace_scope_required"}
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return identitysdk.AuthenticationOutcome{}, err
	}
	application := identitysdk.ApplicationRef{WorkspaceID: request.WorkspaceID, ApplicationKey: request.ApplicationKey}
	if found, err := adapter.binding.applicationRegistered(ctx, application); err != nil {
		return identitysdk.AuthenticationOutcome{}, sdkBoundaryError(err)
	} else if !found {
		return identitysdk.AuthenticationOutcome{}, &identitysdk.Error{Code: "identity.application_not_registered"}
	}
	outcome, err := adapter.binding.flows.LoginWithPasswordOutcome(requestcontext.WithWorkspaceID(ctx, string(request.WorkspaceID)), string(request.WorkspaceID), request.Login, request.Password, string(request.ApplicationKey))
	return sdkAuthenticationOutcome(outcome), sdkBoundaryError(err)
}

func (adapter sdkAuthentication) BeginFederatedLogin(ctx context.Context, request identitysdk.BeginFederatedLoginRequest) (identitysdk.ProviderChallenge, error) {
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return identitysdk.ProviderChallenge{}, err
	}
	if err := adapter.binding.validateApplicationRedirect(ctx, identitysdk.ApplicationRef{WorkspaceID: request.WorkspaceID, ApplicationKey: request.ApplicationKey}, request.ReturnURL); err != nil {
		return identitysdk.ProviderChallenge{}, sdkBoundaryError(err)
	}
	result, err := adapter.binding.flows.StartForApplication(requestcontext.WithWorkspaceID(ctx, string(request.WorkspaceID)), string(request.WorkspaceID), request.Provider, "POST", request.Phone, string(request.ApplicationKey), request.ReturnURL)
	if err != nil {
		return identitysdk.ProviderChallenge{}, sdkBoundaryError(err)
	}
	return sdkProviderChallenge(result), nil
}

func (adapter sdkAuthentication) ExchangeAuthorizationCode(ctx context.Context, request identitysdk.ExchangeAuthorizationCodeRequest) (identitysdk.AuthSession, error) {
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return identitysdk.AuthSession{}, err
	}
	if err := adapter.binding.validateApplicationRedirect(ctx, identitysdk.ApplicationRef{WorkspaceID: request.WorkspaceID, ApplicationKey: request.ApplicationKey}, request.ReturnURL); err != nil {
		return identitysdk.AuthSession{}, sdkBoundaryError(err)
	}
	session, err := adapter.binding.auth.ExchangeAuthorizationCode(ctx, string(request.WorkspaceID), request.Code, string(request.ApplicationKey), request.ReturnURL)
	return sdkAuthSession(session), sdkBoundaryError(err)
}

func (adapter sdkAuthentication) CompleteFederatedLogin(ctx context.Context, request identitysdk.CompleteFederatedLoginRequest) (identitysdk.FederatedLoginCompletion, error) {
	if adapter.binding.providerCallback == nil {
		return identitysdk.FederatedLoginCompletion{}, &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "auth.provider_callback_unavailable"}
	}
	state := strings.TrimSpace(request.Values["state"])
	if state == "" {
		state = strings.TrimSpace(request.Values["RelayState"])
	}
	workspaceID, err := adapter.binding.federatedLoginWorkspace(ctx, request.Provider, state)
	if err != nil {
		return identitysdk.FederatedLoginCompletion{}, err
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, workspaceID); err != nil {
		return identitysdk.FederatedLoginCompletion{}, err
	}
	session, challenge, err := adapter.binding.flows.ExchangeAndCompleteCallbackWithChallenge(ctx, string(workspaceID), request.Provider, state, authmodel.AuthProviderCallbackInput{Values: request.Values}, adapter.binding.providerCallback)
	if err != nil {
		return identitysdk.FederatedLoginCompletion{}, sdkBoundaryError(err)
	}
	if strings.TrimSpace(challenge.ApplicationKey) == "" || strings.TrimSpace(challenge.ReturnURL) == "" {
		return identitysdk.FederatedLoginCompletion{}, &identitysdk.Error{Code: "auth.authorization_code_request_invalid"}
	}
	code, err := adapter.binding.auth.IssueAuthorizationCode(ctx, challenge.ApplicationKey, challenge.ReturnURL, session)
	if err != nil {
		return identitysdk.FederatedLoginCompletion{}, sdkBoundaryError(err)
	}
	return identitysdk.FederatedLoginCompletion{AuthorizationCode: code, ReturnURL: challenge.ReturnURL, State: challenge.State}, nil
}

func (adapter sdkAuthentication) VerifyOTP(ctx context.Context, request identitysdk.VerifyOTPRequest) (identitysdk.AuthSession, error) {
	outcome, err := adapter.VerifyOTPOutcome(ctx, request)
	return sdkAuthenticatedSession(outcome, err)
}

func (adapter sdkAuthentication) VerifyOTPOutcome(ctx context.Context, request identitysdk.VerifyOTPRequest) (identitysdk.AuthenticationOutcome, error) {
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return identitysdk.AuthenticationOutcome{}, err
	}
	outcome, err := adapter.binding.flows.VerifyOTPOutcome(requestcontext.WithWorkspaceID(ctx, string(request.WorkspaceID)), string(request.WorkspaceID), request.Provider, request.State, request.Code)
	return sdkAuthenticationOutcome(outcome), sdkBoundaryError(err)
}

func (adapter sdkAuthentication) RefreshSession(ctx context.Context, request identitysdk.RefreshRequest) (identitysdk.AuthSession, error) {
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return identitysdk.AuthSession{}, err
	}
	if found, err := adapter.binding.applicationRegistered(ctx, identitysdk.ApplicationRef{WorkspaceID: request.WorkspaceID, ApplicationKey: request.ApplicationKey}); err != nil {
		return identitysdk.AuthSession{}, sdkBoundaryError(err)
	} else if !found {
		return identitysdk.AuthSession{}, &identitysdk.Error{Code: "identity.application_not_registered"}
	}
	session, err := adapter.binding.auth.RefreshForApplication(requestcontext.WithWorkspaceID(ctx, string(request.WorkspaceID)), string(request.WorkspaceID), request.RefreshToken, string(request.ApplicationKey))
	return sdkAuthSession(session), sdkBoundaryError(err)
}

func (adapter sdkAuthentication) LogoutSession(ctx context.Context, request identitysdk.LogoutRequest) error {
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return err
	}
	return sdkBoundaryError(adapter.binding.auth.LogoutForApplication(requestcontext.WithWorkspaceID(ctx, string(request.WorkspaceID)), string(request.WorkspaceID), request.RefreshToken, string(request.ApplicationKey)))
}

func (adapter sdkAuthentication) CurrentSession(ctx context.Context, request identitysdk.CurrentSessionRequest) (identitysdk.SessionView, error) {
	claims, err := adapter.binding.auth.VerifyAccessToken(ctx, request.AccessToken)
	if err != nil {
		return identitysdk.SessionView{}, sdkBoundaryError(err)
	}
	me, err := adapter.binding.auth.Me(requestcontext.WithWorkspaceID(ctx, claims.WorkspaceID), request.AccessToken)
	if err != nil {
		return identitysdk.SessionView{}, sdkBoundaryError(err)
	}
	roles := make([]identitysdk.Role, 0, len(me.Roles))
	for _, role := range me.Roles {
		roles = append(roles, identitysdk.Role{ID: role.ID, Key: role.Key, Label: role.Label})
	}
	return identitysdk.SessionView{SessionID: identitysdk.SessionID(claims.SessionID), TenantID: identitysdk.TenantID(claims.TenantID), WorkspaceID: identitysdk.WorkspaceID(claims.WorkspaceID), SubjectID: identitysdk.SubjectID(claims.Subject), AuthorizationRevision: identitysdk.AuthorizationRevision(claims.AuthorizationRevision), User: identitysdk.User{ID: me.User.ID, Name: me.User.Name, Email: me.User.Email, Locale: me.User.Locale, Version: me.User.Version, Status: string(me.User.Status)}, Roles: roles, DefaultRole: me.DefaultRole, Permissions: append([]string(nil), me.Permissions...), MustChangePassword: me.MustChangePassword}, nil
}

type sdkTokenVerifier struct{ binding *sdkBinding }

func (adapter sdkTokenVerifier) Verify(ctx context.Context, request identitysdk.VerifyTokenRequest) (identitysdk.VerifiedToken, error) {
	claims, err := adapter.binding.auth.VerifySignedAccessToken(ctx, request.AccessToken)
	if err != nil {
		return identitysdk.VerifiedToken{}, sdkBoundaryError(err)
	}
	expectedIssuer := strings.TrimSpace(request.Issuer)
	if expectedIssuer == "" {
		expectedIssuer = strings.TrimSpace(adapter.binding.descriptor.Issuer)
	}
	expectedAudience := strings.TrimSpace(string(request.Audience))
	if expectedAudience == "" {
		expectedAudience = strings.TrimSpace(adapter.binding.descriptor.Audience)
	}
	if expectedIssuer == "" || expectedAudience == "" || expectedIssuer != claims.Issuer || expectedAudience != claims.Audience {
		return identitysdk.VerifiedToken{}, &identitysdk.Error{Code: "identity.token_invalid"}
	}
	if adapter.binding.workspaceResolver != nil {
		registered, err := adapter.binding.applicationRegistered(ctx, identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(claims.WorkspaceID), ApplicationKey: identitysdk.ApplicationKey(claims.Audience)})
		if err != nil {
			return identitysdk.VerifiedToken{}, err
		}
		if !registered {
			return identitysdk.VerifiedToken{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.application_not_registered"}
		}
	}
	return identitysdk.VerifiedToken{Issuer: claims.Issuer, Audience: identitysdk.ApplicationKey(claims.Audience), SubjectID: identitysdk.SubjectID(claims.Subject), TenantID: identitysdk.TenantID(claims.TenantID), WorkspaceID: identitysdk.WorkspaceID(claims.WorkspaceID), SessionID: identitysdk.SessionID(claims.SessionID), AuthorizationRevision: identitysdk.AuthorizationRevision(claims.AuthorizationRevision), AuthenticationTime: claims.AuthenticationTime, AuthenticationMethods: append([]string(nil), claims.AuthenticationMethods...), AssuranceLevel: claims.AssuranceLevel, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt, TokenID: claims.JTI}, nil
}

type sdkAuthorization struct{ binding *sdkBinding }

func (adapter sdkAuthorization) ResolveAccess(ctx context.Context, request identitysdk.AccessBundleRequest) (identitysdk.AccessBundle, error) {
	principal, err := adapter.binding.auth.PrincipalFromBearer(ctx, "Bearer "+request.Identity.AccessToken, "")
	if err != nil {
		return identitysdk.AccessBundle{}, sdkBoundaryError(err)
	}
	snapshot, err := adapter.binding.access.Snapshot(requestcontext.WithWorkspaceID(ctx, principal.WorkspaceID), principal.UserID, principal)
	if err != nil {
		return identitysdk.AccessBundle{}, sdkBoundaryError(err)
	}
	now := adapter.binding.clock.Now().UTC()
	bundle := sdkAccessBundle(snapshot, principal, now)
	return bundle, sdkBoundaryError(bundle.Validate(now))
}

func (adapter sdkAuthorization) Reauthorize(ctx context.Context, request identitysdk.DecisionRequest) (identitysdk.AccessDecision, error) {
	principal, err := adapter.binding.auth.PrincipalFromBearer(ctx, "Bearer "+request.Identity.AccessToken, "")
	if err != nil {
		return identitysdk.AccessDecision{}, sdkBoundaryError(err)
	}
	request.Identity.Principal = identitysdk.Principal{
		ContractVersion:       identitysdk.PrincipalContextContractVersion,
		Known:                 true,
		WorkspaceID:           principal.WorkspaceID,
		UserID:                principal.UserID,
		AuthorizationRevision: principal.AuthorizationRevision,
		OrgID:                 principal.OrgID, OrgScopeIDs: append([]string(nil), principal.OrgScopeIDs...),
		SupportOrgID: principal.SupportOrgID, SupportOrgScopeIDs: append([]string(nil), principal.SupportOrgScopeIDs...),
		ReportingScopeUserIDs: append([]string(nil), principal.ReportingScopeUserIDs...),
	}
	bundle, err := adapter.ResolveAccess(ctx, identitysdk.AccessBundleRequest{
		Identity:     request.Identity,
		ResourceType: identitysdk.ResourceType(request.Access.ObjectKey),
		Action:       identitysdk.Action(request.Access.Action),
	})
	if err != nil {
		return identitysdk.AccessDecision{}, sdkBoundaryError(err)
	}
	if len(request.Facts) == 0 {
		return identitysdk.AccessDecision{
			UserID: principal.UserID, ObjectKey: request.Access.ObjectKey, Action: request.Access.Action,
			FieldKey: request.Access.FieldKey, RecordID: request.Access.RecordID, Allowed: false,
			AuthorizationRevision: string(bundle.AuthorizationRevision),
			Reason:                identitysdk.AccessReason{Code: "resource_facts_required", Effect: "deny", Layer: "effective_policy"},
		}, nil
	}
	decision, err := identityevaluator.Evaluate(bundle, request.Access, request.Facts, adapter.binding.clock.Now().UTC())
	if err != nil {
		return identitysdk.AccessDecision{}, sdkBoundaryError(err)
	}
	return identitysdk.AccessDecision{
		UserID:                principal.UserID,
		ObjectKey:             request.Access.ObjectKey,
		Action:                request.Access.Action,
		FieldKey:              request.Access.FieldKey,
		RecordID:              request.Access.RecordID,
		Allowed:               decision.Allowed,
		AuthorizationRevision: string(bundle.AuthorizationRevision),
		Reason: identitysdk.AccessReason{
			Code:   decision.Code,
			Effect: sdkDecisionEffect(decision.Allowed),
			Layer:  "effective_policy",
		},
	}, nil
}

func sdkDecisionEffect(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func (binding *sdkBinding) validateApplicationRedirect(ctx context.Context, application identitysdk.ApplicationRef, returnURL string) error {
	if strings.TrimSpace(returnURL) == "" {
		return nil
	}
	if !application.WorkspaceID.Valid() || !application.ApplicationKey.Valid() {
		return &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	applications, err := binding.scopedApplications(ctx, application)
	if err != nil {
		return err
	}
	ok, err := applications.RedirectAllowed(ctx, string(application.ApplicationKey), returnURL)
	if err != nil {
		return err
	}
	if !ok {
		return &identitysdk.Error{Code: "identity.redirect_url_not_registered"}
	}
	return nil
}

func (binding *sdkBinding) scopedApplications(ctx context.Context, application identitysdk.ApplicationRef) (*authapplication.AuthApplicationRegistrationService, error) {
	if binding == nil || binding.applications == nil || !application.WorkspaceID.Valid() || !application.ApplicationKey.Valid() {
		return nil, &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	if binding.workspaceResolver == nil {
		if string(application.WorkspaceID) != binding.applications.WorkspaceID() {
			return nil, &identitysdk.Error{Code: "identity.application_scope_mismatch"}
		}
		return binding.applications, nil
	}
	if string(application.ApplicationKey) != binding.descriptor.Audience {
		return nil, &identitysdk.Error{Code: "identity.application_scope_mismatch"}
	}
	resolved, err := binding.workspaceResolver.ResolveWorkspace(ctx, application.WorkspaceID)
	if err != nil || resolved != application.WorkspaceID {
		return nil, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "auth.invalid_credentials"}
	}
	return binding.applications.ForWorkspace(string(resolved))
}

func (binding *sdkBinding) applicationRegistered(ctx context.Context, application identitysdk.ApplicationRef) (bool, error) {
	applications, err := binding.scopedApplications(ctx, application)
	if err != nil {
		return false, err
	}
	return applications.Registered(ctx, string(application.ApplicationKey))
}

type sdkCredentials struct{ binding *sdkBinding }

func (adapter sdkCredentials) ChangePassword(ctx context.Context, request identitysdk.ChangePasswordRequest) (identitysdk.AuthSession, error) {
	claims, err := adapter.binding.auth.VerifyAccessToken(ctx, request.AccessToken)
	if err != nil {
		return identitysdk.AuthSession{}, sdkBoundaryError(err)
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, identitysdk.WorkspaceID(claims.WorkspaceID)); err != nil {
		return identitysdk.AuthSession{}, err
	}
	principal, err := adapter.binding.auth.PrincipalFromBearer(ctx, "Bearer "+request.AccessToken, "")
	if err != nil {
		return identitysdk.AuthSession{}, sdkBoundaryError(err)
	}
	key := strings.TrimSpace(request.IdempotencyKey)
	session, _, err := adapter.binding.auth.ChangePasswordAndReissueSessionForAudience(ctx, principal, key, request.CurrentPassword, request.NewPassword, claims.Audience)
	return sdkAuthSession(session), sdkBoundaryError(err)
}
func (adapter sdkCredentials) ResetPassword(ctx context.Context, request identitysdk.ResetPasswordRequest) error {
	principal, err := adapter.binding.auth.PrincipalFromBearer(ctx, "Bearer "+request.AccessToken, "")
	if err != nil {
		return sdkBoundaryError(err)
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, identitysdk.WorkspaceID(principal.WorkspaceID)); err != nil {
		return err
	}
	key := strings.TrimSpace(request.IdempotencyKey)
	_, err = adapter.binding.auth.ResetPasswordIdempotent(ctx, principal, key, string(request.SubjectID), request.NewPassword, request.MustChangePassword)
	return sdkBoundaryError(err)
}
func (adapter sdkCredentials) RevokeSessions(ctx context.Context, request identitysdk.RevokeSessionsRequest) error {
	principal, err := adapter.binding.auth.PrincipalFromBearer(ctx, "Bearer "+request.AccessToken, "")
	if err != nil {
		return sdkBoundaryError(err)
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, identitysdk.WorkspaceID(principal.WorkspaceID)); err != nil {
		return err
	}
	targetSubject := strings.TrimSpace(string(request.SubjectID))
	if targetSubject == "" || targetSubject == principal.UserID {
		_, _, err = adapter.binding.auth.RevokeOtherSessionsIdempotent(ctx, principal, request.AccessToken, strings.TrimSpace(request.IdempotencyKey))
		return sdkBoundaryError(err)
	}
	_, _, err = adapter.binding.auth.ForceLogoutUserIdempotent(ctx, principal, strings.TrimSpace(request.IdempotencyKey), targetSubject)
	return sdkBoundaryError(err)
}

func sdkBoundaryError(err error) error {
	if err == nil {
		return nil
	}
	var existing *identitysdk.Error
	if errors.As(err, &existing) {
		if existing.StatusCode != 0 {
			return err
		}
		clone := *existing
		clone.StatusCode = http.StatusBadRequest
		return &clone
	}
	status := http.StatusInternalServerError
	switch apperror.KindOf(err) {
	case apperror.KindBadRequest:
		status = http.StatusBadRequest
	case apperror.KindForbidden:
		status = http.StatusForbidden
	case apperror.KindNotFound:
		status = http.StatusNotFound
	case apperror.KindConflict:
		status = http.StatusConflict
	case apperror.KindRateLimited:
		status = http.StatusTooManyRequests
	case apperror.KindUnavailable:
		status = http.StatusServiceUnavailable
	}
	return &identitysdk.Error{
		StatusCode: status,
		Code:       apperror.CodeOf(err),
		Params:     apperror.ParamsOf(err),
		Cause:      err,
	}
}

func sdkAuthSession(session authmodel.AuthSession) identitysdk.AuthSession {
	roles := make([]identitysdk.Role, 0, len(session.Roles))
	for _, role := range session.Roles {
		roles = append(roles, identitysdk.Role{ID: role.ID, Key: role.Key, Label: role.Label})
	}
	return identitysdk.AuthSession{SessionID: identitysdk.SessionID(session.SessionID), TenantID: identitysdk.TenantID(session.TenantID), WorkspaceID: session.WorkspaceID, AccessToken: session.AccessToken, RefreshToken: session.RefreshToken, TokenType: session.TokenType, ExpiresAt: session.ExpiresAt, User: identitysdk.User{ID: session.User.ID, Name: session.User.Name, Email: session.User.Email, Locale: session.User.Locale, Version: session.User.Version, Status: string(session.User.Status)}, Roles: roles, DefaultRole: session.DefaultRole, Permissions: append([]string(nil), session.Permissions...), MustChangePassword: session.MustChangePassword, AuthenticationTime: session.AuthenticationTime, AuthenticationMethods: append([]string(nil), session.AuthenticationMethods...), AssuranceLevel: session.AssuranceLevel}
}

func sdkAuthenticationOutcome(outcome authmodel.AuthenticationOutcome) identitysdk.AuthenticationOutcome {
	result := identitysdk.AuthenticationOutcome{Status: identitysdk.AuthenticationStatus(outcome.Status)}
	if outcome.Session != nil {
		session := sdkAuthSession(*outcome.Session)
		result.Session = &session
	}
	if outcome.Challenge != nil {
		challenge := identitysdk.ProviderChallenge{Provider: outcome.Challenge.Provider, State: outcome.Challenge.State, Type: outcome.Challenge.Type, Purpose: outcome.Challenge.Purpose, Status: identitysdk.ChallengeStatus(outcome.Challenge.Status), Nonce: outcome.Challenge.Nonce, Code: outcome.Challenge.Code, MaskedDestination: outcome.Challenge.MaskedDestination, RetryAt: outcome.Challenge.RetryAt, ExpiresAt: outcome.Challenge.ExpiresAt}
		result.Challenge = &challenge
	}
	return result
}

func sdkProviderChallenge(result authprojection.AuthProviderStartResponse) identitysdk.ProviderChallenge {
	return identitysdk.ProviderChallenge{Provider: result.Provider, State: result.State, Type: result.Type, Purpose: result.Purpose, Status: identitysdk.ChallengeStatus(result.Status), Nonce: result.Nonce, Code: result.Code, AuthURL: result.AuthURL, MaskedDestination: result.MaskedDestination, RetryAt: result.RetryAt, ExpiresAt: result.ExpiresAt}
}

func sdkAuthenticatedSession(outcome identitysdk.AuthenticationOutcome, err error) (identitysdk.AuthSession, error) {
	if err != nil {
		return identitysdk.AuthSession{}, err
	}
	if outcome.Status == identitysdk.AuthenticationStatusAuthenticated && outcome.Session != nil {
		return *outcome.Session, nil
	}
	if outcome.Status == identitysdk.AuthenticationStatusChallengeRequired && outcome.Challenge != nil {
		return identitysdk.AuthSession{}, &identitysdk.Error{StatusCode: http.StatusConflict, Code: "auth.challenge_required", Params: map[string]string{"provider": outcome.Challenge.Provider, "state": outcome.Challenge.State}}
	}
	return identitysdk.AuthSession{}, &identitysdk.Error{StatusCode: http.StatusBadGateway, Code: "identity.authentication_response_invalid"}
}

func sdkAccessBundle(snapshot identitymodel.IdentityEffectiveAccessSnapshot, principal identitymodel.Principal, now time.Time) identitysdk.AccessBundle {
	bundle := identitysdk.AccessBundle{ContractVersion: identitysdk.CurrentPolicyBundleVersion, AuthorizationRevision: identitysdk.AuthorizationRevision(snapshot.AuthorizationRevision), ExpiresAt: now.UTC().Add(5 * time.Minute), Subject: identitysdk.Subject{TenantID: identitysdk.TenantID(principal.TenantID), WorkspaceID: identitysdk.WorkspaceID(principal.WorkspaceID), SubjectID: identitysdk.SubjectID(principal.UserID), OrgID: principal.OrgID, OrgScopeIDs: append([]string(nil), principal.OrgScopeIDs...), SupportOrgID: principal.SupportOrgID, SupportOrgScopeIDs: append([]string(nil), principal.SupportOrgScopeIDs...)}}
	for _, id := range principal.ReportingScopeUserIDs {
		bundle.Subject.ReportingScopeUserIDs = append(bundle.Subject.ReportingScopeUserIDs, identitysdk.SubjectID(id))
	}
	for _, permission := range snapshot.Permissions {
		if permission.ObjectKey != "" && permission.Action != "" {
			bundle.FunctionGrants = append(bundle.FunctionGrants, identitysdk.FunctionGrant{Resource: identitysdk.ResourceType(permission.ObjectKey), Action: identitysdk.Action(permission.Action), Effect: identitysdk.EffectAllow})
		}
	}
	dataPolicyIndex := 0
	for _, policy := range snapshot.DataAccess {
		if policy.Resource == "" {
			continue
		}
		predicate := sdkEffectiveDataPredicate(policy)
		effect := identitysdk.EffectAllow
		if !policy.Allowed {
			effect = identitysdk.EffectDeny
		}
		dataScopes := make([]identitysdk.DataScope, 0, len(policy.Scopes))
		for _, scope := range policy.Scopes {
			dataScopes = append(dataScopes, identitysdk.DataScope(scope))
		}
		bundle.DataPolicies = append(bundle.DataPolicies, identitysdk.DataPolicy{Key: "data-" + policy.PermissionKey + "-" + strconv.Itoa(dataPolicyIndex), Resource: identitysdk.ResourceType(policy.Resource), Action: identitysdk.Action(policy.Action), Effect: effect, DataScopes: dataScopes, Predicate: predicate, AuditDenial: policy.AuditDenial})
		dataPolicyIndex++
	}
	for _, field := range snapshot.FieldAccess {
		bundle.FieldPolicies = append(bundle.FieldPolicies, identitysdk.FieldPolicy{Resource: identitysdk.ResourceType(field.ObjectKey), Field: field.FieldKey, Read: field.Read, Write: field.Write, Export: field.Export, Masked: field.Masked, Reason: field.Reason, Rules: sdkFieldRules(field.Policies, principal)})
	}
	for _, reference := range snapshot.ReferencePermissions {
		bundle.ReferencePolicies = append(bundle.ReferencePolicies, identitysdk.ReferencePolicy{SourceResource: identitysdk.ResourceType(reference.SourceObjectKey), Reference: reference.RelationFieldKey, TargetResource: identitysdk.ResourceType(reference.TargetObjectKey), DisplayFields: append([]string(nil), reference.DisplayFields...), Allowed: reference.Mode != "deny", Reason: reference.Reason})
	}
	for _, rule := range snapshot.ExportRules {
		// `all_fields` is the manifest representation of unrestricted export.
		// The SDK contract represents the same state by omitting an export
		// restriction; forwarding `all_fields` as an SDK ExportMode makes the
		// complete access bundle invalid and can break unrelated authenticated
		// requests such as a mandatory password change.
		mode := strings.TrimSpace(rule.Mode)
		if mode == "all_fields" {
			continue
		}
		if mode == "selected_fields" {
			mode = string(identitysdk.ExportModeAllowList)
		}
		bundle.ExportPolicies = append(bundle.ExportPolicies, identitysdk.ExportPolicy{Resource: identitysdk.ResourceType(rule.ObjectKey), Mode: identitysdk.ExportMode(mode), Fields: append([]string(nil), rule.Fields...)})
	}
	guardrailKeys := map[string]bool{}
	for _, key := range snapshot.GuardrailKeys {
		guardrailKeys[key] = true
	}
	for _, guardrail := range adapterGuardrails(principal, guardrailKeys) {
		bundle.Guardrails = append(bundle.Guardrails, guardrail)
	}
	return bundle
}

func sdkEffectiveDataPredicate(policy identitymodel.IdentityEffectiveDataAccess) identitysdk.Predicate {
	predicates := make([]identitysdk.Predicate, 0, len(policy.Scopes))
	for _, scope := range policy.Scopes {
		if scope == identitymodel.IdentityDataScopeAll {
			// Canonical `all` is carried by DataScopes and intentionally has no
			// executable predicate. SDK consumers therefore cannot turn it into
			// a fake always-true WHERE condition.
			return identitysdk.Predicate{}
		}
		predicates = append(predicates, sdkScopePredicate(scope))
	}
	if len(predicates) == 1 {
		return predicates[0]
	}
	if len(predicates) > 1 {
		return identitysdk.Predicate{Any: predicates}
	}
	return identitysdk.Predicate{Fact: "__identity_scope_unsupported__", Operator: identitysdk.OperatorEqual, Value: true}
}

func adapterGuardrails(principal identitymodel.Principal, enabled map[string]bool) []identitysdk.Guardrail {
	result := []identitysdk.Guardrail{}
	for _, guardrail := range principal.Role.Guardrails {
		if !enabled[guardrail.Key] {
			continue
		}
		for _, permission := range guardrail.DeniedPermissionKeys {
			resource, action := sdkPermissionSubject(permission)
			if resource != "" && action != "" {
				result = append(result, identitysdk.Guardrail{Key: guardrail.Key + ":permission:" + permission, Resource: identitysdk.ResourceType(resource), Action: identitysdk.Action(action), Effect: identitysdk.EffectDeny})
			}
		}
		for _, restriction := range guardrail.DataRestrictions {
			for _, action := range restriction.Actions {
				result = append(result, identitysdk.Guardrail{Key: guardrail.Key + ":data:" + restriction.ObjectKey + ":" + action, Resource: identitysdk.ResourceType(restriction.ObjectKey), Action: identitysdk.Action(action), Effect: identitysdk.EffectDeny, Reason: restriction.Reason})
			}
		}
		for _, restriction := range guardrail.FieldRestrictions {
			for _, action := range restriction.Actions {
				result = append(result, identitysdk.Guardrail{Key: guardrail.Key + ":field:" + restriction.ObjectKey + ":" + restriction.FieldKey + ":" + action, Resource: identitysdk.ResourceType(restriction.ObjectKey), Action: identitysdk.Action(action), Field: restriction.FieldKey, Effect: identitysdk.EffectDeny, Reason: restriction.Reason})
			}
		}
	}
	return result
}

func sdkPermissionSubject(permission string) (string, string) {
	parts := strings.Split(strings.TrimSpace(permission), ".")
	if len(parts) < 2 {
		return "", ""
	}
	return strings.Join(parts[:len(parts)-1], "."), parts[len(parts)-1]
}

func sdkPolicyPredicate(value identitymodel.IdentityPolicyExpression, principal identitymodel.Principal) identitysdk.Predicate {
	switch strings.ToLower(strings.TrimSpace(value.Operator)) {
	case "and":
		result := identitysdk.Predicate{All: make([]identitysdk.Predicate, 0, len(value.Children))}
		for _, child := range value.Children {
			result.All = append(result.All, sdkPolicyPredicate(child, principal))
		}
		return result
	case "or":
		result := identitysdk.Predicate{Any: make([]identitysdk.Predicate, 0, len(value.Children))}
		for _, child := range value.Children {
			result.Any = append(result.Any, sdkPolicyPredicate(child, principal))
		}
		return result
	case "not":
		if len(value.Children) == 1 {
			child := sdkPolicyPredicate(value.Children[0], principal)
			return identitysdk.Predicate{Not: &child}
		}
	}
	fact := strings.TrimSpace(value.FieldKey)
	if fact == "" {
		return identitysdk.Predicate{Fact: "__identity_policy_unsupported__", Operator: identitysdk.OperatorEqual, Value: true}
	}
	operator := identitysdk.OperatorEqual
	if strings.EqualFold(value.Operator, "in") {
		operator = identitysdk.OperatorIn
	}
	var policyValue any = append([]string(nil), value.Values...)
	if operator == identitysdk.OperatorEqual && len(value.Values) == 1 {
		policyValue = value.Values[0]
	}
	if strings.EqualFold(value.ValueSource, "actor_claim") {
		policyValue = sdkActorClaim(value.ClaimKey, principal)
	}
	path := make([]identitysdk.RelationSegment, 0, len(value.Path))
	for _, segment := range value.Path {
		path = append(path, identitysdk.RelationSegment{Direction: identitysdk.RelationDirection(strings.TrimSpace(segment.Direction)), Reference: strings.TrimSpace(segment.RelationFieldKey), TargetResource: identitysdk.ResourceType(strings.TrimSpace(segment.TargetObjectKey))})
	}
	return identitysdk.Predicate{Fact: fact, Path: path, Operator: operator, Value: policyValue}
}

func sdkActorClaim(key string, principal identitymodel.Principal) any {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "user_id", "subject_id", "id":
		return "$subject.id"
	case "org_id":
		return "$subject.org_id"
	case "org_scope_ids":
		return "$subject.org_scope_ids"
	case "reporting_scope_user_ids":
		return "$subject.reporting_scope_user_ids"
	case "support_org_scope_ids":
		// support_org_scope_ids is an Identity-owned authorization fact, not a
		// caller-supplied business claim. Freeze it into the subject-specific
		// bundle so an empty or invalid assignment remains fail-closed.
		return append([]string(nil), principal.SupportOrgScopeIDs...)
	case "business_profile_id":
		return "$context.business_profile_id"
	default:
		return "$context.claims." + strings.TrimSpace(key)
	}
}

func sdkFieldRules(values []identitymodel.ContextualFieldPolicyRule, principal identitymodel.Principal) []identitysdk.FieldRule {
	result := make([]identitysdk.FieldRule, 0, len(values))
	for _, value := range values {
		actions := make([]identitysdk.Action, 0, len(value.Actions))
		for _, action := range value.Actions {
			actions = append(actions, identitysdk.Action(strings.TrimSpace(action)))
		}
		var predicate *identitysdk.Predicate
		if value.Predicate != nil {
			converted := sdkPolicyPredicate(*value.Predicate, principal)
			predicate = &converted
		}
		var strategy *identitysdk.MaskStrategy
		if value.MaskStrategy != nil {
			strategy = &identitysdk.MaskStrategy{Type: identitysdk.MaskType(strings.TrimSpace(value.MaskStrategy.Type)), LastN: value.MaskStrategy.LastN}
		}
		result = append(result, identitysdk.FieldRule{Key: strings.TrimSpace(value.Key), Priority: value.Priority, Actions: actions, Effect: identitysdk.FieldEffect(strings.TrimSpace(value.Effect)), Predicate: predicate, MaskStrategy: strategy, AuditDenial: value.AuditDenial})
	}
	return result
}

func sdkScopePredicate(scope identitymodel.IdentityDataScope) identitysdk.Predicate {
	switch scope {
	case identitymodel.IdentityDataScopeAll:
		return identitysdk.Predicate{}
	case identitymodel.IdentityDataScopeOwner:
		return identitysdk.Predicate{Fact: "owner_user_id", Operator: identitysdk.OperatorEqual, Value: "$subject.id"}
	case identitymodel.IdentityDataScopeOrg:
		return identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorEqual, Value: "$subject.org_id"}
	case identitymodel.IdentityDataScopeOrgChild:
		return identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorIn, Value: "$subject.org_scope_ids"}
	case identitymodel.IdentityDataScopeTargetOrg:
		return identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorIn, Value: "$subject.support_org_scope_ids"}
	default:
		return identitysdk.Predicate{Fact: "__identity_scope_unsupported__", Operator: identitysdk.OperatorEqual, Value: true}
	}
}

func sdkAccessReason(value identitymodel.IdentityAccessReason) identitysdk.AccessReason {
	result := identitysdk.AccessReason{Code: value.Code, Effect: value.Effect, Layer: value.Layer, Subject: value.Subject, Details: value.Details}
	for _, child := range value.Children {
		result.Children = append(result.Children, sdkAccessReason(child))
	}
	for _, source := range value.Sources {
		result.Sources = append(result.Sources, identitysdk.GrantSource{Type: source.Type, Key: source.Key, RoleID: source.RoleID, RoleKey: source.RoleKey, PermissionSetKey: source.PermissionSetKey, PermissionSetGroup: source.PermissionSetGroup, AssignmentSource: source.AssignmentSource, BindingKey: source.BindingKey, ProfileID: source.ProfileID, ValidFrom: source.ValidFrom, ValidUntil: source.ValidUntil, ExpiresAt: source.ExpiresAt})
	}
	return result
}

func sdkMapString(value map[string]any, key string) string {
	text, _ := value[key].(string)
	return strings.TrimSpace(text)
}
func sdkMapBool(value map[string]any, key string) bool { result, _ := value[key].(bool); return result }
func sdkMapStrings(value map[string]any, key string) []string {
	if result, ok := value[key].([]string); ok {
		return append([]string(nil), result...)
	}
	return []string{}
}

var _ identitysdk.Binding = (*sdkBinding)(nil)
var _ identitysdk.Authentication = sdkAuthentication{}
var _ identitysdk.TokenVerifier = sdkTokenVerifier{}
var _ identitysdk.Authorization = sdkAuthorization{}
var _ identitysdk.PrincipalResolver = sdkPrincipalResolver{}
var _ identitysdk.Projection = sdkProjection{}
var _ identitysdk.ApplicationRegistry = sdkApplications{}
var _ identitysdk.PermissionRegistry = sdkPermissions{}
var _ identitysdk.CredentialManager = sdkCredentials{}

type sdkSystemClock struct{}

func (sdkSystemClock) Now() time.Time { return time.Now().UTC() }

func defaultString(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}
