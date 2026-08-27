package auth

import "net/http"

func (h *AuthHandler) RegisterRoutes(mux *http.ServeMux) {
	authenticated := h.authenticated
	if authenticated == nil {
		authenticated = h.admin
	}
	mux.HandleFunc("GET /.well-known/jwks.json", h.authJSONWebKeySet)
	mux.HandleFunc("GET /.well-known/openid-configuration", h.authOpenIDConfiguration)
	mux.HandleFunc("POST /auth/login", h.authLogin)
	mux.HandleFunc("POST /auth/guest", h.authGuest)
	mux.HandleFunc("POST /auth/refresh", h.authRefresh)
	mux.HandleFunc("POST /auth/logout", h.authLogout)
	mux.HandleFunc("POST /auth/sessions/revoke-others", authenticated(h.authRevokeOtherSessions))
	mux.HandleFunc("POST /auth/change-password", h.authChangePassword)
	mux.HandleFunc("POST /auth/reset-password", h.authResetPassword)
	mux.HandleFunc("GET /auth/providers", h.authProviders)
	mux.HandleFunc("GET /auth/providers/{provider}/setup-check", h.authProviderSetupCheck)
	mux.HandleFunc("PUT /auth/providers/{provider}/setup", authenticated(h.authProviderSetupSave))
	mux.HandleFunc("GET /auth/providers/{provider}/start", h.authProviderStart)
	mux.HandleFunc("POST /auth/providers/{provider}/start", h.authProviderStart)
	mux.HandleFunc("GET /auth/providers/{provider}/callback", h.authProviderCallback)
	mux.HandleFunc("POST /auth/providers/{provider}/callback", h.authProviderCallback)
	mux.HandleFunc("POST /auth/providers/{provider}/verify", h.authProviderVerify)
	mux.HandleFunc("GET /auth/external-accounts", h.authExternalAccounts)
	mux.HandleFunc("POST /auth/external-accounts/{provider}/bind", h.authBindExternalAccount)
	mux.HandleFunc("DELETE /auth/external-accounts/{provider}/{accountID}", h.authUnbindExternalAccount)
	mux.HandleFunc("GET /auth/me", h.authMe)
	mux.HandleFunc("PATCH /auth/me", h.authUpdateCurrentUserLocale)
	mux.HandleFunc("GET /auth/role-options", h.authRoleOptions)
	mux.HandleFunc("GET /auth/role-requests", h.authRoleRequests)
	mux.HandleFunc("POST /auth/role-requests", h.authCreateRoleRequest)
}
