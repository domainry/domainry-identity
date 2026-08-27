package auth

import "net/http"

func (h *AuthHandler) authRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	result, replayed, err := h.passwords.RevokeOtherSessionsIdempotent(r.Context(), principal, bearerTokenFromRequest(r), r.Header.Get("Idempotency-Key"))
	if replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if h.securityAuditForPrincipal != nil {
		h.securityAuditForPrincipal(r, principal, "auth_other_sessions_revoked", "Revoked other authentication sessions", map[string]any{
			"revoked_sessions":     result.RevokedSessions,
			"current_session_id":   result.CurrentSessionID,
			"idempotency_replayed": replayed,
		})
	}
	h.writeJSON(w, http.StatusOK, result)
}
