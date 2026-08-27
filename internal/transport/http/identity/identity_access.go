package identity

import (
	"context"
	"net/http"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityprojection "github.com/domainry/domainry-identity/internal/domain/identity/projection"
)

type IdentityEffectiveAccess interface {
	Snapshot(context.Context, string, identitymodel.Principal) (identitymodel.IdentityEffectiveAccessSnapshot, error)
	Explain(context.Context, identitymodel.IdentityAccessExplainRequest, identitymodel.Principal) (identitymodel.IdentityAccessExplainResult, error)
	ReverseIndex(context.Context, identitymodel.Principal) (identitymodel.IdentityAccessReverseIndex, error)
	GovernanceReports(context.Context, identitymodel.Principal) (identitymodel.IdentityGovernanceReports, error)
	PreviewRoleChange(context.Context, identitymodel.IdentityRoleChangeImpactRequest, identitymodel.Principal) (identitymodel.IdentityRoleChangeImpact, error)
}

func (h *IdentityHandler) getIdentityPrincipalContext(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
		return
	}
	h.writeJSON(w, http.StatusOK, identityprojection.IdentityBuildPrincipalContext(principal))
}

type IdentityAccessReviews interface {
	CreateReview(context.Context, identitymodel.IdentityAccessReviewCreateRequest, identitymodel.Principal) (identitymodel.IdentityAccessReview, error)
	ListReviews(context.Context, string, identitymodel.Principal) ([]identitymodel.IdentityAccessReview, error)
	Decide(context.Context, string, identitymodel.IdentityAccessReviewDecisionRequest, identitymodel.Principal) (identitymodel.IdentityAccessReviewDecisionReceipt, error)
}

func (h *IdentityHandler) getIdentityEffectiveAccess(w http.ResponseWriter, r *http.Request) {
	if h.effectiveAccess == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.effective_access_unavailable")
		return
	}
	snapshot, err := h.effectiveAccess.Snapshot(r.Context(), strings.TrimSpace(r.PathValue("userID")), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, snapshot)
}

func (h *IdentityHandler) explainIdentityEffectiveAccess(w http.ResponseWriter, r *http.Request) {
	if h.effectiveAccess == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.effective_access_unavailable")
		return
	}
	var request identitymodel.IdentityAccessExplainRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	result, err := h.effectiveAccess.Explain(r.Context(), request, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *IdentityHandler) getIdentityAccessReverseIndex(w http.ResponseWriter, r *http.Request) {
	if h.effectiveAccess == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.effective_access_unavailable")
		return
	}
	result, err := h.effectiveAccess.ReverseIndex(r.Context(), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *IdentityHandler) getIdentityAccessGovernanceReports(w http.ResponseWriter, r *http.Request) {
	if h.effectiveAccess == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.effective_access_unavailable")
		return
	}
	result, err := h.effectiveAccess.GovernanceReports(r.Context(), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *IdentityHandler) previewIdentityRoleChangeImpact(w http.ResponseWriter, r *http.Request) {
	if h.effectiveAccess == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.effective_access_unavailable")
		return
	}
	var request identitymodel.IdentityRoleChangeImpactRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	request.RoleKey = strings.TrimSpace(r.PathValue("roleID"))
	result, err := h.effectiveAccess.PreviewRoleChange(r.Context(), request, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *IdentityHandler) createIdentityAccessReview(w http.ResponseWriter, r *http.Request) {
	if h.accessReviews == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.access_review_unavailable")
		return
	}
	var request identitymodel.IdentityAccessReviewCreateRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	result, err := h.accessReviews.CreateReview(r.Context(), request, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, result)
}

func (h *IdentityHandler) listIdentityAccessReviews(w http.ResponseWriter, r *http.Request) {
	if h.accessReviews == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.access_review_unavailable")
		return
	}
	result, err := h.accessReviews.ListReviews(r.Context(), r.URL.Query().Get("status"), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"items": result, "total": len(result)})
}

func (h *IdentityHandler) decideIdentityAccessReviewItem(w http.ResponseWriter, r *http.Request) {
	if h.accessReviews == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.access_review_unavailable")
		return
	}
	var request identitymodel.IdentityAccessReviewDecisionRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	result, err := h.accessReviews.Decide(r.Context(), strings.TrimSpace(r.PathValue("itemID")), request, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
