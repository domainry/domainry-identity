package identity

import (
	"net/http"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
)

func (h *IdentityHandler) validateIdentityGovernance(w http.ResponseWriter, r *http.Request) {
	var request identitycontract.IdentityGovernanceValidationRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	result, err := h.governance.Validate(r.Context(), request, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
