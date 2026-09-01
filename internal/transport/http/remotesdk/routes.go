package remotesdk

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type applicationServiceTokenAuthority interface {
	IssueApplicationServiceToken(context.Context, identitysdk.ExchangeApplicationServiceTokenRequest, string) (identitysdk.ApplicationServiceToken, error)
	VerifyApplicationServiceToken(context.Context, identitysdk.VerifyApplicationServiceTokenRequest) (identitysdk.ApplicationServicePrincipal, error)
}

type Support struct {
	DecodeJSON        func(http.ResponseWriter, *http.Request, any) bool
	WriteJSON         func(http.ResponseWriter, int, any)
	WriteError        func(http.ResponseWriter, *http.Request, int, string, ...string)
	WriteServiceError func(http.ResponseWriter, *http.Request, error)
}

type RouteRegistrar interface {
	Handle(string, http.Handler)
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}

func (s Support) decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	return s.DecodeJSON(w, r, value)
}

func (s Support) writeJSON(w http.ResponseWriter, status int, value any) {
	s.WriteJSON(w, status, value)
}

func (s Support) writeError(w http.ResponseWriter, r *http.Request, status int, code string, params ...string) {
	s.WriteError(w, r, status, code, params...)
}

func (s Support) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	s.WriteServiceError(w, r, err)
}

func RegisterRoutes(registrar RouteRegistrar, binding identitysdk.Binding, support Support, credentials *ApplicationCredentialRegistry) {
	registrar.HandleFunc("GET /identity/discovery", func(w http.ResponseWriter, _ *http.Request) {
		descriptor := binding.Descriptor()
		descriptor.Mode = identitysdk.DeploymentModeSaaS
		// SaaS serves multiple registered applications. The caller's expected
		// audience is client configuration and is verified on every token;
		// discovery describes the issuer and protocol, not one tenant app.
		descriptor.Audience = ""
		support.writeJSON(w, http.StatusOK, descriptor)
	})
	registrar.HandleFunc("POST /identity/application-service/token", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.ExchangeApplicationServiceTokenRequest
		if !support.decodeJSON(w, r, &request) {
			return
		}
		if credentials == nil {
			support.writeError(w, r, http.StatusUnauthorized, "identity.application_service_credential_invalid")
			return
		}
		decision := credentials.Authorize(r.Header.Get("Authorization"), applicationScope(request.Application))
		writeApplicationCredentialRateLimit(w, decision)
		if !decision.Authenticated {
			support.writeError(w, r, http.StatusUnauthorized, "identity.application_service_credential_invalid")
			return
		}
		if decision.RateLimited {
			support.writeError(w, r, http.StatusTooManyRequests, "identity.application_rate_limited")
			return
		}
		authority, ok := binding.(applicationServiceTokenAuthority)
		if !ok {
			support.writeError(w, r, http.StatusNotImplemented, "identity.application_service_authentication_unavailable")
			return
		}
		token, err := authority.IssueApplicationServiceToken(r.Context(), request, decision.CredentialID)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, token)
	})
	registrar.HandleFunc("POST /identity/application-service/verify", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.VerifyApplicationServiceTokenRequest
		if !support.decodeJSON(w, r, &request) {
			return
		}
		// The verifier is itself an Identity-bound resource application. Its
		// static credential authenticates that exact audience; the caller's
		// short-lived token remains in the JSON body and is never confused with
		// the verifier credential.
		scope := identitysdk.ApplicationScope{WorkspaceID: identitysdk.WorkspaceID(strings.TrimSpace(r.Header.Get("X-Domainry-Workspace-ID"))), ApplicationKey: request.Audience}
		scope.TenantID = identitysdk.TenantID(strings.TrimSpace(r.Header.Get("X-Domainry-Tenant-ID")))
		if scope.WorkspaceID == "" {
			scope.WorkspaceID = identitysdk.WorkspaceID(strings.TrimSpace(r.Header.Get("X-Domainry-Identity-Workspace-ID")))
		}
		if credentials == nil {
			support.writeError(w, r, http.StatusUnauthorized, "identity.application_service_verifier_invalid")
			return
		}
		decision := credentials.Authorize(r.Header.Get("Authorization"), scope)
		writeApplicationCredentialRateLimit(w, decision)
		if !decision.Authenticated {
			support.writeError(w, r, http.StatusUnauthorized, "identity.application_service_verifier_invalid")
			return
		}
		if decision.RateLimited {
			support.writeError(w, r, http.StatusTooManyRequests, "identity.application_rate_limited")
			return
		}
		authority, ok := binding.(applicationServiceTokenAuthority)
		if !ok {
			support.writeError(w, r, http.StatusNotImplemented, "identity.application_service_authentication_unavailable")
			return
		}
		principal, err := authority.VerifyApplicationServiceToken(r.Context(), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		if !credentials.Active(identitysdk.ApplicationScope{TenantID: principal.Application.TenantID, WorkspaceID: principal.Application.WorkspaceID, ApplicationKey: principal.Application.ApplicationKey}, principal.CredentialID) {
			support.writeError(w, r, http.StatusUnauthorized, "identity.application_service_credential_rotated")
			return
		}
		support.writeJSON(w, http.StatusOK, principal)
	})
	registrar.HandleFunc("GET /auth/session", func(w http.ResponseWriter, r *http.Request) {
		token := sdkBearerToken(r.Header.Get("Authorization"))
		if token == "" {
			support.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		session, err := binding.Authentication().CurrentSession(r.Context(), identitysdk.CurrentSessionRequest{AccessToken: token})
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, session)
	})
	registrar.HandleFunc("POST /auth/code/exchange", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.ExchangeAuthorizationCodeRequest
		if !support.decodeJSON(w, r, &request) {
			return
		}
		session, err := binding.Authentication().ExchangeAuthorizationCode(r.Context(), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, session)
	})
	registrar.HandleFunc("POST /identity/access-bundle", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ResourceType identitysdk.ResourceType `json:"resource_type"`
			Action       identitysdk.Action       `json:"action"`
		}
		if !support.decodeJSON(w, r, &request) {
			return
		}
		token := sdkBearerToken(r.Header.Get("Authorization"))
		if token == "" {
			support.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		bundle, err := binding.Authorization().ResolveAccess(r.Context(), identitysdk.AccessBundleRequest{Identity: identitysdk.RequestIdentity{Principal: identitysdk.Principal{Known: true}, AccessToken: token}, ResourceType: request.ResourceType, Action: request.Action})
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, bundle)
	})
	registrar.HandleFunc("POST /identity/reauthorize", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Access identitysdk.AccessRequest `json:"access"`
			Facts  identitysdk.ResourceFacts `json:"facts,omitempty"`
		}
		if !support.decodeJSON(w, r, &request) {
			return
		}
		token := sdkBearerToken(r.Header.Get("Authorization"))
		if token == "" {
			support.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		decision, err := binding.Authorization().Reauthorize(r.Context(), identitysdk.DecisionRequest{
			Identity: identitysdk.RequestIdentity{
				Principal:   identitysdk.Principal{Known: true},
				AccessToken: token,
			},
			Access: request.Access,
			Facts:  request.Facts,
		})
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, decision)
	})
	registrar.HandleFunc("PUT /identity/applications/current", func(w http.ResponseWriter, r *http.Request) {
		var registration identitysdk.ApplicationRegistration
		if !support.decodeJSON(w, r, &registration) {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, applicationScope(registration.Application)) {
			return
		}
		receipt, err := binding.Applications().Register(r.Context(), registration)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, receipt)
	})
	registrar.HandleFunc("PUT /identity/permissions/reconcile", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.PermissionReconcileRequest
		if !support.decodeJSON(w, r, &request) {
			return
		}
		if !authorizeApplicationCredentialSourceOwner(w, r, support, credentials, applicationScope(request.Application), request.SourceOwner) {
			return
		}
		receipt, err := binding.Permissions().Reconcile(r.Context(), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, receipt)
	})
	registrar.HandleFunc("POST /identity/permissions/source-snapshot", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.PermissionSourceSnapshotRequest
		if !support.decodeJSON(w, r, &request) {
			return
		}
		if !authorizeApplicationCredentialSourceOwner(w, r, support, credentials, applicationScope(request.Application), request.SourceOwner) {
			return
		}
		reader, ok := binding.Permissions().(identitysdk.PermissionSnapshotReader)
		if !ok {
			support.writeError(w, r, http.StatusNotImplemented, "identity.permission_snapshot_reader_unavailable")
			return
		}
		snapshot, err := reader.CurrentSourceSnapshot(r.Context(), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		if err := snapshot.ValidateFor(request); err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, snapshot)
	})
	registerRuntimeProjectionRoutes(registrar, binding, support, credentials)
}

func authorizeApplicationCredentialSourceOwner(w http.ResponseWriter, r *http.Request, support Support, credentials *ApplicationCredentialRegistry, scope identitysdk.ApplicationScope, sourceOwner string) bool {
	if credentials == nil {
		support.writeError(w, r, http.StatusUnauthorized, "identity.service_credential_required")
		return false
	}
	decision := credentials.AuthorizeSourceOwner(r.Header.Get("Authorization"), scope, sourceOwner)
	if !decision.Authenticated {
		support.writeError(w, r, http.StatusUnauthorized, "identity.service_credential_required")
		return false
	}
	if !decision.SourceOwnerAllowed {
		support.writeError(w, r, http.StatusForbidden, "identity.permission_source_owner_forbidden")
		return false
	}
	writeApplicationCredentialRateLimit(w, decision)
	if decision.RateLimited {
		support.writeError(w, r, http.StatusTooManyRequests, "identity.application_rate_limited")
		return false
	}
	return true
}

func authorizeApplicationCredential(w http.ResponseWriter, r *http.Request, support Support, credentials *ApplicationCredentialRegistry, scope identitysdk.ApplicationScope) bool {
	if credentials == nil {
		support.writeError(w, r, http.StatusUnauthorized, "identity.service_credential_required")
		return false
	}
	decision := credentials.Authorize(r.Header.Get("Authorization"), scope)
	if !decision.Authenticated {
		support.writeError(w, r, http.StatusUnauthorized, "identity.service_credential_required")
		return false
	}
	writeApplicationCredentialRateLimit(w, decision)
	if decision.RateLimited {
		support.writeError(w, r, http.StatusTooManyRequests, "identity.application_rate_limited")
		return false
	}
	return true
}

func writeApplicationCredentialRateLimit(w http.ResponseWriter, decision ApplicationCredentialDecision) {
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	if !decision.ResetAt.IsZero() {
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))
	}
	if decision.RateLimited {
		retryAfter := int(time.Until(decision.ResetAt).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
}

func sdkBearerToken(value string) string {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
