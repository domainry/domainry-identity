package identitysdkadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
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
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type MetadataSource interface {
	Schema() metadatamodel.MetadataSchemaSnapshot
}

type BindingDependencies struct {
	Config                config.Config
	Authentication        *authapplication.AuthApplicationService
	ProviderConfiguration *authapplication.AuthProviderApplicationService
	ProviderFlows         *authapplication.AuthProviderFlowApplicationService
	ProviderCallback      authcontract.AuthProviderCallbackAdapter
	EffectiveAccess       *identityapplication.IdentityEffectiveAccessApplicationService
	Identity              *identityapplication.IdentityApplicationService
	Metadata              MetadataSource
	Clock                 identitysdk.Clock
	Catalog               CatalogPersistence
	MutationFence         IdentityMutationFence
	LoginTransactions     FederatedLoginTransactionReader
	CatalogPublished      func([]identitysdk.AuthorizationCatalog)
}

type sdkCatalogScope struct {
	workspaceID    identitysdk.WorkspaceID
	applicationKey identitysdk.ApplicationKey
}

type sdkCatalogRevisionScope struct {
	catalog  sdkCatalogScope
	revision identitysdk.CatalogRevision
}

func catalogScope(application identitysdk.ApplicationRef) sdkCatalogScope {
	return sdkCatalogScope{
		workspaceID:    identitysdk.WorkspaceID(strings.TrimSpace(string(application.WorkspaceID))),
		applicationKey: identitysdk.ApplicationKey(strings.TrimSpace(string(application.ApplicationKey))),
	}
}

type sdkBinding struct {
	descriptor         identitysdk.Descriptor
	auth               *authapplication.AuthApplicationService
	providers          *authapplication.AuthProviderApplicationService
	flows              *authapplication.AuthProviderFlowApplicationService
	providerCallback   authcontract.AuthProviderCallbackAdapter
	access             *identityapplication.IdentityEffectiveAccessApplicationService
	identity           *identityapplication.IdentityApplicationService
	metadata           MetadataSource
	catalogMu          sync.RWMutex
	catalogs           map[sdkCatalogScope]identitysdk.CatalogReceipt
	catalogDefinitions map[sdkCatalogScope]identitysdk.AuthorizationCatalog
	catalogHistory     map[sdkCatalogRevisionScope]identitysdk.AuthorizationCatalog
	catalogReceipts    map[sdkCatalogRevisionScope]identitysdk.CatalogReceipt
	catalogStore       CatalogPersistence
	clock              identitysdk.Clock
	mutationFence      IdentityMutationFence
	loginTransactions  FederatedLoginTransactionReader
	catalogPublished   func([]identitysdk.AuthorizationCatalog)
	capabilities       *modulecapability.StaticBinding
}

func NewBinding(dependencies BindingDependencies) (identitysdk.Binding, error) {
	if dependencies.Authentication == nil || dependencies.ProviderConfiguration == nil || dependencies.ProviderFlows == nil ||
		dependencies.ProviderCallback == nil || dependencies.EffectiveAccess == nil || dependencies.Identity == nil ||
		dependencies.Metadata == nil || dependencies.Catalog == nil || dependencies.MutationFence == nil || dependencies.LoginTransactions == nil {
		return nil, errors.New("complete Identity SDK Binding dependencies are required")
	}
	if dependencies.Clock == nil {
		dependencies.Clock = sdkSystemClock{}
	}
	binding := &sdkBinding{descriptor: identitysdk.Descriptor{
		ProtocolVersion: identitysdk.CurrentProtocolVersion, BundleVersion: identitysdk.CurrentPolicyBundleVersion, CatalogVersion: identitysdk.CatalogVersionV1,
		Mode: identitysdk.DeploymentModeModule, Issuer: defaultString(dependencies.Config.AuthIssuer, "http://localhost:8081"), Audience: defaultString(dependencies.Config.AuthAudience, "domainry-runtime"),
		Capabilities: []string{"authentication", "token_verification", "authorization", "principal_resolution", "directory_projection", "catalog", "credentials", "oidc", "saml"},
	}, auth: dependencies.Authentication, providers: dependencies.ProviderConfiguration, flows: dependencies.ProviderFlows,
		providerCallback: dependencies.ProviderCallback, access: dependencies.EffectiveAccess, identity: dependencies.Identity,
		metadata: dependencies.Metadata, catalogs: map[sdkCatalogScope]identitysdk.CatalogReceipt{},
		catalogDefinitions: map[sdkCatalogScope]identitysdk.AuthorizationCatalog{}, catalogHistory: map[sdkCatalogRevisionScope]identitysdk.AuthorizationCatalog{},
		catalogReceipts: map[sdkCatalogRevisionScope]identitysdk.CatalogReceipt{}, catalogStore: dependencies.Catalog, clock: dependencies.Clock,
		mutationFence: dependencies.MutationFence, loginTransactions: dependencies.LoginTransactions,
		catalogPublished: dependencies.CatalogPublished}
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
func (binding *sdkBinding) Tokens() identitysdk.TokenVerifier { return sdkTokenVerifier{binding} }
func (binding *sdkBinding) Authorization() identitysdk.Authorization {
	return sdkAuthorization{binding}
}
func (binding *sdkBinding) Principals() identitysdk.PrincipalResolver {
	return sdkPrincipalResolver{binding: binding}
}
func (binding *sdkBinding) Directory() identitysdk.Directory {
	return sdkDirectory{binding: binding}
}
func (binding *sdkBinding) Catalog() identitysdk.CatalogClient { return sdkCatalog{binding} }
func (binding *sdkBinding) Credentials() identitysdk.CredentialManager {
	return sdkCredentials{binding}
}
func (binding *sdkBinding) Close(context.Context) error { return nil }

type sdkAuthentication struct{ binding *sdkBinding }

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
	if !request.WorkspaceID.Valid() {
		return identitysdk.AuthSession{}, &identitysdk.Error{Code: "backend.workspace_scope_required"}
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return identitysdk.AuthSession{}, err
	}
	application := identitysdk.ApplicationRef{WorkspaceID: request.WorkspaceID, ApplicationKey: request.ApplicationKey}
	if _, _, found, err := adapter.binding.loadCatalog(ctx, application); err != nil {
		return identitysdk.AuthSession{}, sdkBoundaryError(err)
	} else if !found {
		return identitysdk.AuthSession{}, &identitysdk.Error{Code: "identity.application_not_registered"}
	}
	session, err := adapter.binding.auth.LoginForApplication(requestcontext.WithWorkspaceID(ctx, string(request.WorkspaceID)), string(request.WorkspaceID), request.Login, request.Password, string(request.ApplicationKey))
	return sdkAuthSession(session), sdkBoundaryError(err)
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
	return identitysdk.ProviderChallenge{Provider: result.Provider, State: result.State, Nonce: result.Nonce, Code: result.Code, AuthURL: result.AuthURL, ExpiresAt: result.ExpiresAt}, nil
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
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return identitysdk.AuthSession{}, err
	}
	session, err := adapter.binding.flows.VerifyOTP(requestcontext.WithWorkspaceID(ctx, string(request.WorkspaceID)), string(request.WorkspaceID), request.Provider, request.State, request.Code)
	return sdkAuthSession(session), sdkBoundaryError(err)
}

func (adapter sdkAuthentication) RefreshSession(ctx context.Context, request identitysdk.RefreshRequest) (identitysdk.AuthSession, error) {
	if err := adapter.binding.requireMutableWorkspace(ctx, request.WorkspaceID); err != nil {
		return identitysdk.AuthSession{}, err
	}
	if _, _, found, err := adapter.binding.loadCatalog(ctx, identitysdk.ApplicationRef{WorkspaceID: request.WorkspaceID, ApplicationKey: request.ApplicationKey}); err != nil {
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
	return identitysdk.VerifiedToken{Issuer: claims.Issuer, Audience: identitysdk.ApplicationKey(claims.Audience), SubjectID: identitysdk.SubjectID(claims.Subject), TenantID: identitysdk.TenantID(claims.TenantID), WorkspaceID: identitysdk.WorkspaceID(claims.WorkspaceID), SessionID: identitysdk.SessionID(claims.SessionID), AuthorizationRevision: identitysdk.AuthorizationRevision(claims.AuthorizationRevision), AuthenticationTime: claims.AuthenticationTime, AuthenticationMethods: append([]string(nil), claims.AuthenticationMethods...), AssuranceLevel: claims.AssuranceLevel, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt, TokenID: claims.JTI}, nil
}

type sdkAuthorization struct{ binding *sdkBinding }

func (adapter sdkAuthorization) ResolveAccess(ctx context.Context, request identitysdk.AccessBundleRequest) (identitysdk.AccessBundle, error) {
	claims, err := adapter.binding.auth.VerifyAccessToken(ctx, request.Identity.AccessToken)
	if err != nil {
		return identitysdk.AccessBundle{}, sdkBoundaryError(err)
	}
	principal, err := adapter.binding.auth.PrincipalFromBearer(ctx, "Bearer "+request.Identity.AccessToken, "")
	if err != nil {
		return identitysdk.AccessBundle{}, sdkBoundaryError(err)
	}
	snapshot, err := adapter.binding.access.Snapshot(requestcontext.WithWorkspaceID(ctx, principal.WorkspaceID), principal.UserID, principal)
	if err != nil {
		return identitysdk.AccessBundle{}, sdkBoundaryError(err)
	}
	catalog, receipt, found, err := adapter.binding.loadCatalog(ctx, identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(claims.WorkspaceID), ApplicationKey: identitysdk.ApplicationKey(claims.Audience)})
	if err != nil {
		return identitysdk.AccessBundle{}, sdkBoundaryError(err)
	}
	if !found {
		return identitysdk.AccessBundle{}, &identitysdk.Error{Code: "identity.catalog_not_published"}
	}
	now := adapter.binding.clock.Now().UTC()
	bundle := sdkAccessBundle(snapshot, principal, string(receipt.Revision), now)
	bundle = resolveCatalogRoleAccess(bundle, catalog, principal.Role)
	bundle, err = accessBundleForCatalog(bundle, catalog)
	if err != nil {
		return identitysdk.AccessBundle{}, sdkBoundaryError(err)
	}
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
	}
	bundle, err := adapter.ResolveAccess(ctx, identitysdk.AccessBundleRequest{
		Identity:     request.Identity,
		ResourceType: identitysdk.ResourceType(request.Access.ObjectKey),
		Action:       identitysdk.Action(request.Access.Action),
	})
	if err != nil {
		return identitysdk.AccessDecision{}, sdkBoundaryError(err)
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

type sdkCatalog struct{ binding *sdkBinding }

func (adapter sdkCatalog) Validate(_ context.Context, catalog identitysdk.AuthorizationCatalog) error {
	return sdkBoundaryError(catalog.ValidateContract())
}
func (adapter sdkCatalog) Publish(ctx context.Context, catalog identitysdk.AuthorizationCatalog) (identitysdk.CatalogReceipt, error) {
	if err := catalog.ValidateContract(); err != nil {
		return identitysdk.CatalogReceipt{}, sdkBoundaryError(err)
	}
	if err := adapter.binding.requireMutableWorkspace(ctx, catalog.Application.WorkspaceID); err != nil {
		return identitysdk.CatalogReceipt{}, err
	}
	payload, err := catalog.CanonicalJSON()
	if err != nil {
		return identitysdk.CatalogReceipt{}, sdkBoundaryError(err)
	}
	digest := sha256.Sum256(payload)
	revision := identitysdk.CatalogRevision(hex.EncodeToString(digest[:]))
	scope := catalogScope(catalog.Application)
	revisionScope := sdkCatalogRevisionScope{catalog: scope, revision: revision}
	adapter.binding.catalogMu.Lock()
	defer adapter.binding.catalogMu.Unlock()
	receipt, found := adapter.binding.catalogReceipts[revisionScope]
	if !found && adapter.binding.catalogStore != nil {
		persistedCatalog, persistedReceipt, persisted, err := adapter.binding.catalogStore.LoadRevision(ctx, catalog.Application, revision)
		if err != nil {
			return identitysdk.CatalogReceipt{}, sdkBoundaryError(err)
		}
		if persisted {
			persistedPayload, canonicalErr := persistedCatalog.CanonicalJSON()
			if canonicalErr != nil || !bytes.Equal(persistedPayload, payload) || persistedReceipt.SHA256 != string(revision) {
				return identitysdk.CatalogReceipt{}, &identitysdk.Error{Code: "identity.catalog_revision_immutable_conflict", Cause: canonicalErr}
			}
			receipt, found = persistedReceipt, true
		}
	}
	if !found {
		receipt = identitysdk.CatalogReceipt{Revision: revision, SHA256: string(revision), PublishedAt: adapter.binding.clock.Now().UTC().Format(time.RFC3339Nano)}
	}
	if adapter.binding.catalogStore != nil {
		if err := adapter.binding.catalogStore.Save(ctx, catalog, receipt); err != nil {
			// Another SaaS instance may have inserted the same immutable revision
			// after our lookup. Reuse its receipt and retry only the mutable current
			// pointer instead of creating duplicate history.
			_, concurrentReceipt, concurrent, loadErr := adapter.binding.catalogStore.LoadRevision(ctx, catalog.Application, revision)
			if loadErr != nil || !concurrent {
				return identitysdk.CatalogReceipt{}, sdkBoundaryError(err)
			}
			receipt = concurrentReceipt
			if retryErr := adapter.binding.catalogStore.Save(ctx, catalog, receipt); retryErr != nil {
				return identitysdk.CatalogReceipt{}, sdkBoundaryError(retryErr)
			}
		}
	}
	adapter.binding.catalogs[scope] = receipt
	adapter.binding.catalogDefinitions[scope] = catalog
	adapter.binding.catalogReceipts[revisionScope] = receipt
	adapter.binding.catalogHistory[revisionScope] = catalog
	if adapter.binding.catalogPublished != nil {
		catalogs := make([]identitysdk.AuthorizationCatalog, 0, len(adapter.binding.catalogDefinitions))
		for _, current := range adapter.binding.catalogDefinitions {
			catalogs = append(catalogs, current)
		}
		adapter.binding.catalogPublished(catalogs)
	}
	return receipt, nil
}

func (binding *sdkBinding) validateApplicationRedirect(ctx context.Context, application identitysdk.ApplicationRef, returnURL string) error {
	if strings.TrimSpace(returnURL) == "" {
		return nil
	}
	scope := catalogScope(application)
	if !scope.workspaceID.Valid() || !scope.applicationKey.Valid() {
		return &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	catalog, _, ok, err := binding.loadCatalog(ctx, application)
	if err != nil {
		return err
	}
	if !ok {
		return &identitysdk.Error{Code: "identity.application_not_registered"}
	}
	for _, candidate := range catalog.Application.RedirectURLs {
		if strings.TrimSpace(candidate) == strings.TrimSpace(returnURL) {
			return nil
		}
	}
	return &identitysdk.Error{Code: "identity.redirect_url_not_registered"}
}
func (adapter sdkCatalog) CurrentRevision(ctx context.Context, application identitysdk.ApplicationRef) (identitysdk.CatalogReceipt, error) {
	scope := catalogScope(application)
	if !scope.workspaceID.Valid() || !scope.applicationKey.Valid() {
		return identitysdk.CatalogReceipt{}, &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	_, receipt, found, err := adapter.binding.loadCatalog(ctx, application)
	if err != nil {
		return identitysdk.CatalogReceipt{}, sdkBoundaryError(err)
	}
	if !found {
		return identitysdk.CatalogReceipt{}, &identitysdk.Error{Code: "identity.catalog_not_published"}
	}
	return receipt, nil
}

func (binding *sdkBinding) loadCatalog(ctx context.Context, application identitysdk.ApplicationRef) (identitysdk.AuthorizationCatalog, identitysdk.CatalogReceipt, bool, error) {
	scope := catalogScope(application)
	if !scope.workspaceID.Valid() || !scope.applicationKey.Valid() {
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, &identitysdk.Error{Code: "identity.application_scope_invalid"}
	}
	binding.catalogMu.RLock()
	catalog, catalogFound := binding.catalogDefinitions[scope]
	receipt, receiptFound := binding.catalogs[scope]
	binding.catalogMu.RUnlock()
	if catalogFound && receiptFound {
		return catalog, receipt, true, nil
	}
	if binding.catalogStore == nil {
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, nil
	}
	persistedCatalog, persistedReceipt, found, err := binding.catalogStore.Load(ctx, application)
	if err != nil || !found {
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, err
	}
	if err := persistedCatalog.ValidateContract(); err != nil {
		return identitysdk.AuthorizationCatalog{}, identitysdk.CatalogReceipt{}, false, err
	}
	binding.catalogMu.Lock()
	binding.catalogDefinitions[scope] = persistedCatalog
	binding.catalogs[scope] = persistedReceipt
	revisionScope := sdkCatalogRevisionScope{catalog: scope, revision: persistedReceipt.Revision}
	binding.catalogHistory[revisionScope] = persistedCatalog
	binding.catalogReceipts[revisionScope] = persistedReceipt
	binding.catalogMu.Unlock()
	return persistedCatalog, persistedReceipt, true, nil
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
	return identitysdk.AuthSession{SessionID: identitysdk.SessionID(session.SessionID), TenantID: identitysdk.TenantID(session.TenantID), WorkspaceID: session.WorkspaceID, AccessToken: session.AccessToken, RefreshToken: session.RefreshToken, TokenType: session.TokenType, ExpiresAt: session.ExpiresAt, User: identitysdk.User{ID: session.User.ID, Name: session.User.Name, Email: session.User.Email, Locale: session.User.Locale, Version: session.User.Version, Status: string(session.User.Status)}, Roles: roles, DefaultRole: session.DefaultRole, Permissions: append([]string(nil), session.Permissions...), MustChangePassword: session.MustChangePassword}
}

func sdkAccessBundle(snapshot identitymodel.IdentityEffectiveAccessSnapshot, principal identitymodel.Principal, catalogRevision string, now time.Time) identitysdk.AccessBundle {
	bundle := identitysdk.AccessBundle{ContractVersion: identitysdk.CurrentPolicyBundleVersion, CatalogRevision: identitysdk.CatalogRevision(catalogRevision), AuthorizationRevision: identitysdk.AuthorizationRevision(snapshot.AuthorizationRevision), ExpiresAt: now.UTC().Add(5 * time.Minute), Subject: identitysdk.Subject{WorkspaceID: identitysdk.WorkspaceID(principal.WorkspaceID), SubjectID: identitysdk.SubjectID(principal.UserID), WorkforceProfileID: principal.WorkforceProfileID, DepartmentID: principal.DepartmentID, DepartmentPath: principal.DepartmentPath, ReportingPath: principal.ReportingPath, OrganizationScopes: map[string][]string{"team_ids": append([]string(nil), principal.TeamIDs...), "store_ids": append([]string(nil), principal.StoreIDs...), "territory_ids": append([]string(nil), principal.TerritoryIDs...), "warehouse_ids": append([]string(nil), principal.WarehouseIDs...)}}}
	for _, id := range principal.ReportingUserIDs {
		bundle.Subject.ReportingSubjectIDs = append(bundle.Subject.ReportingSubjectIDs, identitysdk.SubjectID(id))
	}
	for _, permission := range snapshot.Permissions {
		if permission.ObjectKey != "" && permission.Action != "" {
			bundle.FunctionGrants = append(bundle.FunctionGrants, identitysdk.FunctionGrant{Resource: identitysdk.ResourceType(permission.ObjectKey), Action: identitysdk.Action(permission.Action), Effect: identitysdk.EffectAllow})
		}
	}
	for index, policy := range snapshot.DataAccess {
		if policy.ObjectKey == "" || policy.Action == "" {
			continue
		}
		predicate := sdkScopePredicate(policy.Scope)
		if policy.Predicate != nil {
			predicate = sdkPolicyPredicate(*policy.Predicate)
		}
		effect := identitysdk.EffectAllow
		if !policy.Allowed {
			effect = identitysdk.EffectDeny
		}
		bundle.DataPolicies = append(bundle.DataPolicies, identitysdk.DataPolicy{Key: "data-" + policy.ObjectKey + "-" + policy.Action + "-" + strconv.Itoa(index), Resource: identitysdk.ResourceType(policy.ObjectKey), Action: identitysdk.Action(policy.Action), Effect: effect, Predicate: predicate, AuditDenial: policy.AuditDenial})
	}
	for _, field := range snapshot.FieldAccess {
		bundle.FieldPolicies = append(bundle.FieldPolicies, identitysdk.FieldPolicy{Resource: identitysdk.ResourceType(field.ObjectKey), Field: field.FieldKey, Read: field.Read, Write: field.Write, Export: field.Export, Masked: field.Masked, Reason: field.Reason, Rules: sdkFieldRules(field.Policies)})
	}
	for _, reference := range snapshot.ReferencePermissions {
		bundle.ReferencePolicies = append(bundle.ReferencePolicies, identitysdk.ReferencePolicy{SourceResource: identitysdk.ResourceType(reference.SourceObjectKey), Reference: reference.RelationFieldKey, TargetResource: identitysdk.ResourceType(reference.TargetObjectKey), DisplayFields: append([]string(nil), reference.DisplayFields...), Allowed: reference.Mode != "deny", Reason: reference.Reason})
	}
	for _, rule := range snapshot.ExportRules {
		bundle.ExportPolicies = append(bundle.ExportPolicies, identitysdk.ExportPolicy{Resource: identitysdk.ResourceType(rule.ObjectKey), Mode: identitysdk.ExportMode(rule.Mode), Fields: append([]string(nil), rule.Fields...)})
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

func sdkPolicyPredicate(value identitymodel.IdentityPolicyExpression) identitysdk.Predicate {
	switch strings.ToLower(strings.TrimSpace(value.Operator)) {
	case "and":
		result := identitysdk.Predicate{All: make([]identitysdk.Predicate, 0, len(value.Children))}
		for _, child := range value.Children {
			result.All = append(result.All, sdkPolicyPredicate(child))
		}
		return result
	case "or":
		result := identitysdk.Predicate{Any: make([]identitysdk.Predicate, 0, len(value.Children))}
		for _, child := range value.Children {
			result.Any = append(result.Any, sdkPolicyPredicate(child))
		}
		return result
	case "not":
		if len(value.Children) == 1 {
			child := sdkPolicyPredicate(value.Children[0])
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
		policyValue = sdkActorClaim(value.ClaimKey)
	}
	path := make([]identitysdk.RelationSegment, 0, len(value.Path))
	for _, segment := range value.Path {
		path = append(path, identitysdk.RelationSegment{Direction: identitysdk.RelationDirection(strings.TrimSpace(segment.Direction)), Reference: strings.TrimSpace(segment.RelationFieldKey), TargetResource: identitysdk.ResourceType(strings.TrimSpace(segment.TargetObjectKey))})
	}
	return identitysdk.Predicate{Fact: fact, Path: path, Operator: operator, Value: policyValue}
}

func sdkActorClaim(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "user_id", "subject_id", "id":
		return "$subject.id"
	case "department_id":
		return "$subject.department_id"
	case "workforce_profile_id":
		return "$subject.workforce_profile_id"
	case "reporting_user_ids", "reporting_subject_ids":
		return "$subject.reporting_subject_ids"
	case "team_ids", "store_ids", "territory_ids", "warehouse_ids":
		return "$subject.organization_scopes." + strings.ToLower(strings.TrimSpace(key))
	case "business_profile_id":
		return "$context.business_profile_id"
	default:
		return "$context.claims." + strings.TrimSpace(key)
	}
}

func sdkFieldRules(values []identitymodel.ContextualFieldPolicyRule) []identitysdk.FieldRule {
	result := make([]identitysdk.FieldRule, 0, len(values))
	for _, value := range values {
		actions := make([]identitysdk.Action, 0, len(value.Actions))
		for _, action := range value.Actions {
			actions = append(actions, identitysdk.Action(strings.TrimSpace(action)))
		}
		var predicate *identitysdk.Predicate
		if value.Predicate != nil {
			converted := sdkPolicyPredicate(*value.Predicate)
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

func sdkScopePredicate(scope string) identitysdk.Predicate {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "all_records":
		return identitysdk.Predicate{Fact: "id", Operator: identitysdk.OperatorExists, Value: true}
	case "owned_records":
		return identitysdk.Predicate{Fact: "owner_id", Operator: identitysdk.OperatorEqual, Value: "$subject.id"}
	case "department":
		return identitysdk.Predicate{Fact: "department_id", Operator: identitysdk.OperatorEqual, Value: "$subject.department_id"}
	case "department_and_children":
		return identitysdk.Predicate{Fact: "department_path", Operator: identitysdk.OperatorPrefix, Value: "$subject.department_path"}
	case "subordinates":
		return identitysdk.Predicate{Fact: "owner_id", Operator: identitysdk.OperatorIn, Value: "$subject.reporting_subject_ids"}
	case "team":
		return identitysdk.Predicate{Fact: "team_id", Operator: identitysdk.OperatorIn, Value: "$subject.organization_scopes.team_ids"}
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
		result.Sources = append(result.Sources, identitysdk.GrantSource{Type: source.Type, Key: source.Key, RoleID: source.RoleID, RoleKey: source.RoleKey, PermissionSetKey: source.PermissionSetKey, PermissionSetGroup: source.PermissionSetGroup, AssignmentSource: source.AssignmentSource, BindingKey: source.BindingKey, ProfileID: source.ProfileID, WorkforceProfileID: source.WorkforceProfileID, ValidFrom: source.ValidFrom, ValidUntil: source.ValidUntil, ExpiresAt: source.ExpiresAt})
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
var _ identitysdk.Directory = sdkDirectory{}
var _ identitysdk.CatalogClient = sdkCatalog{}
var _ identitysdk.CredentialManager = sdkCredentials{}

type sdkSystemClock struct{}

func (sdkSystemClock) Now() time.Time { return time.Now().UTC() }

func defaultString(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}
