package remotesdk

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type Support struct {
	DecodeJSON        func(http.ResponseWriter, *http.Request, any) bool
	WriteJSON         func(http.ResponseWriter, int, any)
	WriteError        func(http.ResponseWriter, *http.Request, int, string, ...string)
	WriteServiceError func(http.ResponseWriter, *http.Request, error)
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

func RegisterRoutes(mux *http.ServeMux, binding identitysdk.Binding, support Support, credentials *ApplicationCredentialRegistry) {
	mux.HandleFunc("GET /identity/discovery", func(w http.ResponseWriter, _ *http.Request) {
		descriptor := binding.Descriptor()
		descriptor.Mode = identitysdk.DeploymentModeSaaS
		// SaaS serves multiple registered applications. The caller's expected
		// audience is client configuration and is verified on every token;
		// discovery describes the issuer and protocol, not one tenant app.
		descriptor.Audience = ""
		support.writeJSON(w, http.StatusOK, descriptor)
	})
	mux.HandleFunc("GET /auth/session", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /auth/code/exchange", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /identity/access-bundle", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /identity/reauthorize", func(w http.ResponseWriter, r *http.Request) {
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
	publishCatalog := func(w http.ResponseWriter, r *http.Request) {
		var catalog identitysdk.AuthorizationCatalog
		if !support.decodeJSON(w, r, &catalog) {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, applicationScope(catalog.Application)) {
			return
		}
		receipt, err := binding.Catalog().Publish(r.Context(), catalog)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, receipt)
	}
	mux.HandleFunc("PUT /identity/catalog", publishCatalog)
	mux.HandleFunc("POST /identity/catalog/revision", func(w http.ResponseWriter, r *http.Request) {
		var application identitysdk.ApplicationRef
		if !support.decodeJSON(w, r, &application) {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, applicationScope(application)) {
			return
		}
		receipt, err := binding.Catalog().CurrentRevision(r.Context(), application)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, receipt)
	})
	registerRuntimeProjectionRoutes(mux, binding, support, credentials)
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
		support.writeError(w, r, http.StatusTooManyRequests, "identity.application_rate_limited")
		return false
	}
	return true
}

func sdkBearerToken(value string) string {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
