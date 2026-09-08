package auth

import (
	"net/http"

	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type routeRegistrar interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}

func (h *AuthHandler) RegisterRoutes(mux routeRegistrar) {
	h.registerAuthAction(mux, "auth.totp.manage", h.authTOTP)
	h.registerAuthAction(mux, "auth.discovery.jwks", h.authJSONWebKeySet)
	h.registerAuthAction(mux, "auth.discovery.openid_configuration", h.authOpenIDConfiguration)
	h.registerAuthAction(mux, "auth.login", h.authLogin)
	h.registerAuthAction(mux, "auth.guest", h.authGuest)
	h.registerAuthAction(mux, "auth.refresh", h.authRefresh)
	h.registerAuthAction(mux, "auth.logout", h.authLogout)
	h.registerAuthAction(mux, "auth.sessions.revoke_others", h.authRevokeOtherSessions)
	h.registerAuthAction(mux, "auth.change_password", h.authChangePassword)
	h.registerAuthAction(mux, identitycontract.IdentityActionAuthResetPassword, h.authResetPassword)
	h.registerAuthAction(mux, "auth.providers.list", h.authProviders)
	h.registerAuthAction(mux, "auth.providers.setup_check", h.authProviderSetupCheck)
	h.registerAuthAction(mux, identitycontract.IdentityActionAuthProvidersSetup, h.authProviderSetupSave)
	h.registerAuthAction(mux, "auth.providers.start_get", h.authProviderStart)
	h.registerAuthAction(mux, "auth.providers.start_post", h.authProviderStart)
	h.registerAuthAction(mux, "auth.providers.callback_get", h.authProviderCallback)
	h.registerAuthAction(mux, "auth.providers.callback_post", h.authProviderCallback)
	h.registerAuthAction(mux, "auth.providers.verify", h.authProviderVerify)
	h.registerAuthAction(mux, "auth.providers.exchange", h.authProviderExchange)
	h.registerAuthAction(mux, "auth.external_accounts.list", h.authExternalAccounts)
	h.registerAuthAction(mux, "auth.external_accounts.bind", h.authBindExternalAccount)
	h.registerAuthAction(mux, "auth.external_accounts.unbind", h.authUnbindExternalAccount)
	h.registerAuthAction(mux, "auth.me.get", h.authMe)
	h.registerAuthAction(mux, "auth.me.update", h.authUpdateCurrentUserLocale)
	h.registerAuthAction(mux, "auth.role_options.list", h.authRoleOptions)
	h.registerAuthAction(mux, "auth.role_requests.list", h.authRoleRequests)
	h.registerAuthAction(mux, "auth.role_requests.create", h.authCreateRoleRequest)
}

func (h *AuthHandler) registerAuthAction(mux routeRegistrar, actionKey string, next http.HandlerFunc) {
	action, found := h.actionAuthorization.Definition(actionKey)
	if !found || action.HTTP == nil {
		panic("Auth route references unregistered action " + actionKey)
	}
	mux.HandleFunc(action.HTTP.Method+" "+action.HTTP.RouteTemplate, func(w http.ResponseWriter, r *http.Request) {
		principal := identitymodel.Principal{}
		if h.principal != nil {
			principal = h.principal(r)
		}
		if !h.actionAuthorization.Allows(action, principal, identityapplication.IdentityActionAuthorizationContext{}) {
			if h.securityAudit != nil {
				h.securityAudit(r, "auth_api_denied", "Auth API action denied", map[string]any{
					"action_key": action.Key, "path": r.URL.Path, "method": r.Method, "strategy": action.Authorization.Strategy,
				})
			}
			if h.writeError != nil {
				if !principal.Known {
					h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
					return
				}
				h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
				return
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
