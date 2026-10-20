package identity

import (
	"context"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-identity/internal/domain/auth/contract/credentialemail"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityEmailInvitationSecurity interface {
	CheckCredentialEmail(context.Context, string) error
	SendPasswordInvitation(context.Context, string, string) (credentialemail.Receipt, error)
}

type identityEmailInvitationResponse struct {
	identitymodel.IdentityUser
	Invitation    credentialemail.Receipt `json:"invitation"`
	DeliveryError string                  `json:"delivery_error,omitempty"`
}

// This is the product invitation use case, distinct from API provisioning.
// It never issues, stores, or returns an initial/default login password.
func (h *IdentityHandler) inviteIdentityUser(w http.ResponseWriter, r *http.Request) {
	var user identitymodel.IdentityUser
	if !h.decodeJSON(w, r, &user) {
		return
	}
	if user.AccountType != "" && user.AccountType != identitymodel.IdentityAccountHuman {
		h.writeError(w, r, http.StatusBadRequest, "auth.invitation_human_required")
		return
	}
	security, ok := h.userSecurity.(identityEmailInvitationSecurity)
	if !ok {
		h.writeError(w, r, http.StatusServiceUnavailable, "auth.credential_email_unavailable")
		return
	}
	principal := h.principal(r)
	if err := security.CheckCredentialEmail(r.Context(), principal.WorkspaceID); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	user.ID = strings.TrimSpace(user.ID)
	if err := h.users.CreateUserWithinDataScope(r.Context(), user, principal, "identity.users.invite"); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	persisted, found, err := h.users.UserByIDWithinDataScope(r.Context(), user.ID, principal, "identity.users.invite")
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if !found {
		h.writeError(w, r, http.StatusInternalServerError, "backend.identity.user_not_found")
		return
	}
	receipt, err := security.SendPasswordInvitation(r.Context(), principal.WorkspaceID, user.ID)
	response := identityEmailInvitationResponse{IdentityUser: persisted, Invitation: receipt}
	if err != nil {
		// Keep the created account visible and explicitly retryable. Pretending
		// the invite succeeded or deleting a possibly-delivered identity is unsafe.
		response.Invitation.Status = "failed"
		response.DeliveryError = apperror.CodeOf(err)
	}
	h.appendIdentityMutationAudit(r, "identity_user_invited", "identity_user", user.ID, "Created user with email password-setup invitation", map[string]any{"delivery_status": response.Invitation.Status})
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusCreated, response)
}

func (h *IdentityHandler) resendIdentityInvitation(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	user, found, err := h.users.UserByIDWithinDataScope(r.Context(), strings.TrimSpace(r.PathValue("userID")), principal, "identity.users.invitation_resend")
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if !found {
		h.writeError(w, r, http.StatusNotFound, "backend.identity.user_not_found")
		return
	}
	security, ok := h.userSecurity.(identityEmailInvitationSecurity)
	if !ok {
		h.writeError(w, r, http.StatusServiceUnavailable, "auth.credential_email_unavailable")
		return
	}
	receipt, err := security.SendPasswordInvitation(r.Context(), principal.WorkspaceID, user.ID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_invitation_resent", "identity_user", user.ID, "Sent replacement one-time password-setup link", nil)
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, receipt)
}
