package auth

import (
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/requestcontext"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func (h *AuthHandler) authLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WorkspaceID    string `json:"workspace_id"`
		ApplicationKey string `json:"application_key"`
		Login          string `json:"login"`
		UserID         string `json:"user_id"`
		Email          string `json:"email"`
		Password       string `json:"password"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	workspaceID, ok := h.requireWorkspace(w, r, req.WorkspaceID)
	if !ok {
		return
	}
	login := valueOrDefault(req.Login, valueOrDefault(req.UserID, req.Email))
	applicationKey := strings.TrimSpace(req.ApplicationKey)
	if h.applicationRegistered != nil {
		if applicationKey == "" {
			h.writeError(w, r, http.StatusBadRequest, "identity.application_scope_invalid")
			return
		}
		registered, err := h.applicationRegistered(r.Context(), workspaceID, applicationKey)
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		if !registered {
			h.writeError(w, r, http.StatusBadRequest, "identity.application_not_registered")
			return
		}
	}
	flowContext := requestcontext.WithWorkspaceID(r.Context(), workspaceID)
	if challengeAware, ok := h.providerFlows.(authChallengeAwareProviderFlow); ok {
		outcome, err := challengeAware.LoginWithPasswordOutcome(flowContext, workspaceID, login, req.Password, applicationKey)
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		h.writeJSON(w, http.StatusOK, outcome)
		return
	}
	result, err := h.passwords.LoginForApplication(flowContext, workspaceID, login, req.Password, applicationKey)
	if err != nil {
		if h.securityAudit != nil {
			h.securityAudit(r, "auth_login_failed", "Password login failed", map[string]any{"reason": "invalid_credentials", "error_code": "auth.invalid_credentials", "result": "failed", "authentication_method": "password"})
		}
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) authGuest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WorkspaceID string `json:"workspace_id"`
		Role        string `json:"role"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	workspaceID, ok := h.requireWorkspace(w, r, req.WorkspaceID)
	if !ok {
		return
	}
	// req.Role is retained for wire compatibility only. The domain service owns
	// the sole guest role policy and ignores anonymous role selection.
	result, err := h.passwords.GuestSession(requestcontext.WithWorkspaceID(r.Context(), workspaceID), workspaceID, req.Role)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) authRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WorkspaceID    string `json:"workspace_id"`
		ApplicationKey string `json:"application_key"`
		RefreshToken   string `json:"refresh_token"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	workspaceID, ok := h.requireWorkspace(w, r, req.WorkspaceID)
	if !ok {
		return
	}
	applicationKey := strings.TrimSpace(req.ApplicationKey)
	if h.applicationRegistered != nil {
		if applicationKey == "" {
			h.writeError(w, r, http.StatusBadRequest, "identity.application_scope_invalid")
			return
		}
		registered, registerErr := h.applicationRegistered(r.Context(), workspaceID, applicationKey)
		if registerErr != nil {
			h.writeServiceError(w, r, registerErr)
			return
		}
		if !registered {
			h.writeError(w, r, http.StatusBadRequest, "identity.application_not_registered")
			return
		}
	}
	result, err := h.passwords.RefreshForApplication(requestcontext.WithWorkspaceID(r.Context(), workspaceID), workspaceID, req.RefreshToken, applicationKey)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) authLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WorkspaceID    string `json:"workspace_id"`
		ApplicationKey string `json:"application_key"`
		RefreshToken   string `json:"refresh_token"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	workspaceID, ok := h.requireWorkspace(w, r, req.WorkspaceID)
	if !ok {
		return
	}
	applicationKey := strings.TrimSpace(req.ApplicationKey)
	if h.applicationRegistered != nil && applicationKey == "" {
		h.writeError(w, r, http.StatusBadRequest, "identity.application_scope_invalid")
		return
	}
	if err := h.passwords.LogoutForApplication(requestcontext.WithWorkspaceID(r.Context(), workspaceID), workspaceID, req.RefreshToken, applicationKey); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *AuthHandler) revokeSession(r *http.Request, session authmodel.AuthSession) {
	if h.passwords != nil {
		h.passwords.Logout(r.Context(), session.WorkspaceID, session.RefreshToken)
		return
	}
	if h.externalAccounts != nil {
		h.externalAccounts.Logout(r.Context(), session.WorkspaceID, session.RefreshToken)
	}
}

func (h *AuthHandler) authChangePassword(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	operationKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if operationKey == "" {
		h.writeError(w, r, http.StatusBadRequest, idempotency.ErrorCodeMissingKey)
		return
	}
	audience := ""
	if accessToken := bearerTokenFromRequest(r); accessToken != "" {
		claims, err := h.passwords.VerifyAccessToken(r.Context(), accessToken)
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		audience = claims.Audience
	}
	session, replayed, err := h.passwords.ChangePasswordAndReissueSessionForAudience(r.Context(), principal, operationKey, req.CurrentPassword, req.NewPassword, audience)
	if replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, session)
}

func (h *AuthHandler) authResetPassword(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
		return
	}
	var req struct {
		UserID             string `json:"user_id"`
		NewPassword        string `json:"new_password"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	operationKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if operationKey == "" {
		h.writeError(w, r, http.StatusBadRequest, idempotency.ErrorCodeMissingKey)
		return
	}
	replayed, err := h.passwords.ResetPasswordIdempotent(r.Context(), principal, operationKey, req.UserID, req.NewPassword, req.MustChangePassword)
	if replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
