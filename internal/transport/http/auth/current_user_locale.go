package auth

import (
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/idempotency"
)

func (h *AuthHandler) authUpdateCurrentUserLocale(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
		return
	}
	var req struct {
		Locale          string `json:"locale"`
		ExpectedVersion int64  `json:"expected_version"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		h.writeError(w, r, http.StatusBadRequest, idempotency.ErrorCodeMissingKey)
		return
	}
	result, replayed, err := h.externalAccounts.UpdateCurrentUserLocaleIdempotent(r.Context(), principal, bearerTokenFromRequest(r), key, req.Locale, req.ExpectedVersion)
	if replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
