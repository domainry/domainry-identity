package auth

import (
	"net/http"

	"github.com/domainry/domainry-foundation/requestcontext"
	authservice "github.com/domainry/domainry-identity/internal/domain/auth/service"
)

func (h *AuthHandler) authEmailCredentials(w http.ResponseWriter, r *http.Request) {
	var input struct {
		WorkspaceID string `json:"workspace_id"`
		Email       string `json:"email"`
		Token       string `json:"token"`
		State       string `json:"state"`
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
	}
	if !h.decodeJSON(w, r, &input) {
		return
	}
	workspace, ok := h.requireWorkspace(w, r, valueOrDefault(input.WorkspaceID, requestcontext.WorkspaceID(r.Context())))
	if !ok {
		return
	}
	ctx := requestcontext.WithWorkspaceID(r.Context(), workspace)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch r.URL.Path {
	case "/auth/password/recovery/start":
		challenge, err := h.passwords.StartPasswordRecovery(ctx, workspace, input.Email)
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		h.writeJSON(w, http.StatusOK, challenge)
	default:
		purpose, token := authservice.PasswordSetupPurpose, input.Token
		if r.URL.Path == "/auth/password/recovery/complete" {
			purpose, token = authservice.PasswordRecoveryPurpose, input.State
		}
		if err := h.passwords.CompleteEmailPassword(ctx, workspace, token, purpose, input.Code, input.NewPassword); err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		if h.securityAudit != nil {
			h.securityAudit(r, "auth_email_credential_completed", "Completed one-time email credential handoff and revoked prior sessions", map[string]any{"purpose": purpose})
		}
		h.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
