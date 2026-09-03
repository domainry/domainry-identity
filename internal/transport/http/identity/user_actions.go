package identity

import "net/http"

func (h *IdentityHandler) identityUserSecurity(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	profile, err := h.userSecurity.UserSecurityProfileGoverned(r.Context(), principal, r.PathValue("userID"))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, profile)
}

func (h *IdentityHandler) unlockIdentityUser(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	userID := r.PathValue("userID")
	if err := h.userSecurity.UnlockUserGoverned(r.Context(), principal, userID); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_unlocked", "identity_user", userID, "Unlocked identity user", nil)
	h.writeJSON(w, http.StatusOK, map[string]any{"status": "unlocked"})
}

func (h *IdentityHandler) forceLogoutIdentityUser(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	userID := r.PathValue("userID")
	result, replayed, err := h.userSecurity.ForceLogoutUserIdempotent(r.Context(), principal, r.Header.Get("Idempotency-Key"), userID)
	if replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_force_logged_out", "identity_user", userID, "Force logged out identity user", map[string]any{"revoked_sessions": result.RevokedSessions, "idempotency_replayed": replayed})
	h.writeJSON(w, http.StatusOK, result)
}

func (h *IdentityHandler) revokeIdentityUserMFAFactor(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	userID, factorID := r.PathValue("userID"), r.PathValue("factorID")
	if err := h.userSecurity.RevokeMFAFactorGoverned(r.Context(), principal, userID, factorID); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_mfa_factor_revoked", "identity_user", userID, "Revoked identity user MFA factor", map[string]any{"factor_id": factorID})
	h.writeJSON(w, http.StatusOK, map[string]any{"status": "disabled", "factor_id": factorID})
}
