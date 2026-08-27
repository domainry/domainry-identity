package identity

import (
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
)

func (h *IdentityHandler) getIdentityProfileBinding(w http.ResponseWriter, r *http.Request) {
	if h.profileBindings == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.profile_binding_unavailable")
		return
	}
	binding, found, err := h.profileBindings.Get(r.Context(), r.PathValue("objectKey"), r.PathValue("profileID"), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if !found {
		h.writeError(w, r, http.StatusNotFound, "backend.identity.profile_binding_not_found")
		return
	}
	h.writeJSON(w, http.StatusOK, binding)
}

func (h *IdentityHandler) executeIdentityProfileBindingCommand(w http.ResponseWriter, r *http.Request) {
	if h.profileBindings == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.profile_binding_unavailable")
		return
	}
	var request identityapplication.IdentityProfileBindingCommandRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	request.ObjectKey = strings.TrimSpace(r.PathValue("objectKey"))
	request.ProfileID = strings.TrimSpace(r.PathValue("profileID"))
	receipt, err := h.profileBindings.Execute(r.Context(), request, h.principal(r))
	if err != nil {
		principal := h.principal(r)
		h.securityPrincipal(r, principal, "identity_profile_binding_command_denied", "Denied identity profile binding command", map[string]any{
			"object_key": request.ObjectKey, "profile_id": request.ProfileID, "operation": request.Operation, "error_code": apperror.CodeOf(err),
		})
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_profile_binding_"+string(receipt.Operation), request.ObjectKey, request.ProfileID, "Executed identity profile binding command", map[string]any{
		"binding_key": receipt.BindingKey, "operation": receipt.Operation, "binding_version": receipt.Binding.Version, "replayed": receipt.Replayed,
	})
	h.writeJSON(w, http.StatusOK, receipt)
}
