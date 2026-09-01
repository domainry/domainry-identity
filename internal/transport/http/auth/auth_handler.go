package auth

import authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"

import (
	"context"
	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	"net/http"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type AuthProviderFlowApplication interface {
	Start(context.Context, string, string, string, string) (authprojection.AuthProviderStartResponse, error)
	VerifyOTP(context.Context, string, string, string, string) (authmodel.AuthSession, error)
	ExchangeAndCompleteCallbackWithChallenge(context.Context, string, string, string, authmodel.AuthProviderCallbackInput, authcontract.AuthProviderCallbackAdapter) (authmodel.AuthSession, authmodel.AuthProviderChallenge, error)
}

type authProviderApplicationFlow interface {
	StartForApplication(context.Context, string, string, string, string, string, string) (authprojection.AuthProviderStartResponse, error)
}

type authProviderCodeExchangeFlow interface {
	ExchangeCode(context.Context, string, string, string, string, authcontract.AuthProviderCodeExchangeAdapter) (authmodel.AuthSession, error)
}

type authAuthorizationCodeIssuer interface {
	IssueAuthorizationCode(context.Context, string, string, authmodel.AuthSession) (string, error)
}

type AuthHandler struct {
	passwords                 *authapplication.AuthApplicationService
	externalAccounts          *authapplication.AuthApplicationService
	roleRequests              *identityapplication.IdentityApplicationService
	providerConfiguration     *authapplication.AuthProviderApplicationService
	providerFlows             AuthProviderFlowApplication
	providerCallback          authcontract.AuthProviderCallbackAdapter
	principal                 func(*http.Request) identitymodel.Principal
	writeJSON                 func(http.ResponseWriter, int, any)
	writeError                func(http.ResponseWriter, *http.Request, int, string, ...string)
	writeServiceError         func(http.ResponseWriter, *http.Request, error)
	decodeJSON                func(http.ResponseWriter, *http.Request, any) bool
	actionAuthorization       *identityapplication.IdentityActionAuthorizationService
	providerFailureAudit      func(*http.Request, string, string)
	securityAudit             func(*http.Request, string, string, map[string]any)
	securityAuditForPrincipal func(*http.Request, identitymodel.Principal, string, string, map[string]any)
	applicationRegistered     func(context.Context, string, string) (bool, error)
	writesFrozen              func(context.Context, string) (bool, error)
	federatedLoginWorkspace   func(context.Context, string, string, time.Time) (string, bool, error)
}

type AuthDependencies struct {
	Passwords                 *authapplication.AuthApplicationService
	ExternalAccounts          *authapplication.AuthApplicationService
	RoleRequests              *identityapplication.IdentityApplicationService
	ProviderConfiguration     *authapplication.AuthProviderApplicationService
	ProviderFlows             AuthProviderFlowApplication
	ProviderCallback          authcontract.AuthProviderCallbackAdapter
	Principal                 func(*http.Request) identitymodel.Principal
	WriteJSON                 func(http.ResponseWriter, int, any)
	WriteError                func(http.ResponseWriter, *http.Request, int, string, ...string)
	WriteServiceError         func(http.ResponseWriter, *http.Request, error)
	DecodeJSON                func(http.ResponseWriter, *http.Request, any) bool
	ActionAuthorization       *identityapplication.IdentityActionAuthorizationService
	ProviderFailureAudit      func(*http.Request, string, string)
	SecurityAudit             func(*http.Request, string, string, map[string]any)
	SecurityAuditForPrincipal func(*http.Request, identitymodel.Principal, string, string, map[string]any)
	ApplicationRegistered     func(context.Context, string, string) (bool, error)
	WritesFrozen              func(context.Context, string) (bool, error)
	FederatedLoginWorkspace   func(context.Context, string, string, time.Time) (string, bool, error)
}

func NewAuthHandler(deps AuthDependencies) *AuthHandler {
	actionAuthorization := deps.ActionAuthorization
	if actionAuthorization == nil {
		registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
		if err != nil {
			panic("compile Identity Action registry for Auth routes: " + err.Error())
		}
		actionAuthorization = identityapplication.NewIdentityActionAuthorizationService(registry, nil)
	}
	return &AuthHandler{
		passwords: deps.Passwords, externalAccounts: deps.ExternalAccounts, roleRequests: deps.RoleRequests,
		providerConfiguration: deps.ProviderConfiguration, providerFlows: deps.ProviderFlows,
		providerCallback: deps.ProviderCallback, principal: deps.Principal,
		writeJSON: deps.WriteJSON, writeError: deps.WriteError,
		writeServiceError: deps.WriteServiceError, decodeJSON: deps.DecodeJSON, actionAuthorization: actionAuthorization,
		providerFailureAudit: deps.ProviderFailureAudit, securityAudit: deps.SecurityAudit,
		securityAuditForPrincipal: deps.SecurityAuditForPrincipal, applicationRegistered: deps.ApplicationRegistered,
		writesFrozen: deps.WritesFrozen, federatedLoginWorkspace: deps.FederatedLoginWorkspace,
	}
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

func bearerTokenFromRequest(r *http.Request) string {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authorization) < len("Bearer ") || !strings.EqualFold(authorization[:len("Bearer ")], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(authorization[len("Bearer "):])
}

func (h *AuthHandler) requireWorkspace(w http.ResponseWriter, r *http.Request, value string) (string, bool) {
	workspace, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		h.writeError(w, r, http.StatusBadRequest, "backend.workspace_scope_required")
		return "", false
	}
	if !h.requireMutableWorkspace(w, r, workspace.String()) {
		return "", false
	}
	return workspace.String(), true
}

func (h *AuthHandler) requireMutableWorkspace(w http.ResponseWriter, r *http.Request, workspaceID string) bool {
	if h == nil || h.writesFrozen == nil {
		return true
	}
	frozen, err := h.writesFrozen(r.Context(), strings.TrimSpace(workspaceID))
	if err != nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "identity.write_fence_unavailable")
		return false
	}
	if frozen {
		h.writeError(w, r, http.StatusLocked, "identity.workspace_writes_frozen")
		return false
	}
	return true
}

func (h *AuthHandler) requireMutableFederatedLogin(w http.ResponseWriter, r *http.Request, provider, state string) (string, bool) {
	if h == nil || h.federatedLoginWorkspace == nil {
		return "", false
	}
	workspaceID, found, err := h.federatedLoginWorkspace(r.Context(), provider, state, time.Now().UTC())
	if err != nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "identity.login_transaction_unavailable")
		return "", false
	}
	if !found {
		h.writeError(w, r, http.StatusForbidden, "auth.provider_state_invalid")
		return "", false
	}
	if !h.requireMutableWorkspace(w, r, workspaceID) {
		return "", false
	}
	return workspaceID, true
}
