package auth

import (
	"net/http"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func (h *AuthHandler) authTOTP(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
		return
	}
	if !h.requireMutableWorkspace(w, r, principal.WorkspaceID) {
		return
	}
	var request authmodel.TOTPRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result, err := h.passwords.ManageTOTPForPrincipal(r.Context(), principal, request)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
