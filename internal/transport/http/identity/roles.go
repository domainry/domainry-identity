package identity

import (
	"context"
	"github.com/domainry/domainry-foundation/apperror"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"

	"net/http"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (h *IdentityHandler) listIdentityRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roles.ListRoles(r.Context())
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, roles)
}

func (h *IdentityHandler) searchIdentityRoles(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	searchFields := []string{}
	for _, field := range strings.Split(values.Get("search_fields"), ",") {
		if field = strings.TrimSpace(field); field != "" {
			searchFields = append(searchFields, field)
		}
	}
	page, err := h.roles.SearchRoles(r.Context(), identitymodel.IdentityListQuery{
		Page:         intQuery(values.Get("page")),
		PageSize:     intQuery(values.Get("page_size")),
		Search:       values.Get("search"),
		SearchFields: searchFields,
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, page)
}

func (h *IdentityHandler) getIdentityRoleGovernanceDetail(w http.ResponseWriter, r *http.Request) {
	detail, err := h.roles.RoleGovernanceDetail(r.Context(), strings.TrimSpace(r.PathValue("roleID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, detail)
}

func (h *IdentityHandler) listIdentityUserRoleAssignments(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userID"))
	assignments, err := h.roles.ListUserRoleAssignments(r.Context(), userID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	// IdentityUserRoleAssignment contains only JSON-safe scalar fields, so this
	// typed projection cannot trigger the generic fingerprint marshal error.
	resourceHash, _ := identityAuthoringResourceHash("identity.user_role_assignment", userID, assignments, len(assignments) > 0)
	w.Header().Set(identityResourceHashHeader, resourceHash)
	h.writeJSON(w, http.StatusOK, assignments)
}

func (h *IdentityHandler) searchIdentityUserRoleAssignments(w http.ResponseWriter, r *http.Request) {
	page, err := h.roles.SearchUserRoleAssignments(r.Context(), strings.TrimSpace(r.PathValue("userID")), identityListQuery(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, page)
}

func (h *IdentityHandler) listIdentityAssignableRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roles.ListAssignableRoles(r.Context(), strings.TrimSpace(r.PathValue("userID")), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, roles)
}

func (h *IdentityHandler) listIdentityAssignableWorkforceRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roles.ListAssignableWorkforceRoles(r.Context(), strings.TrimSpace(r.PathValue("profileID")), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, roles)
}

func (h *IdentityHandler) upsertIdentityUserWithRoles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User        identitymodel.IdentityUser                 `json:"user"`
		Assignments []identitymodel.IdentityUserRoleAssignment `json:"assignments"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	req.User.ID = strings.TrimSpace(r.PathValue("userID"))
	for index := range req.Assignments {
		req.Assignments[index].UserID = req.User.ID
	}
	principal := h.principal(r)
	if err := h.roles.UpsertUserWithRoles(r.Context(), req.User, req.Assignments, principal); err != nil {
		h.securityPrincipal(r, principal, "identity_user_role_reconcile_denied", "Denied atomic identity user and role reconcile", map[string]any{
			"target_user_id": req.User.ID, "role_count": len(req.Assignments), "error_code": apperror.CodeOf(err),
		})
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_roles_reconciled", "identity_user", req.User.ID, "Reconciled identity user and roles atomically", map[string]any{"role_count": len(req.Assignments)})
	h.writeJSON(w, http.StatusOK, req.User)
}

func (h *IdentityHandler) assignIdentityUserRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID             string  `json:"role_id"`
		WorkforceProfileID string  `json:"workforce_profile_id,omitempty"`
		BindingKey         string  `json:"binding_key,omitempty"`
		ProfileID          string  `json:"profile_id,omitempty"`
		ValidFrom          string  `json:"valid_from,omitempty"`
		ValidUntil         string  `json:"valid_until,omitempty"`
		GrantReason        string  `json:"grant_reason,omitempty"`
		ExpiresAt          *string `json:"expires_at,omitempty"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	assignment := identitymodel.IdentityUserRoleAssignment{
		UserID:             strings.TrimSpace(r.PathValue("userID")),
		RoleID:             strings.TrimSpace(req.RoleID),
		ExpiresAt:          req.ExpiresAt,
		WorkforceProfileID: strings.TrimSpace(req.WorkforceProfileID),
		BindingKey:         strings.TrimSpace(req.BindingKey), ProfileID: strings.TrimSpace(req.ProfileID),
		ValidFrom: strings.TrimSpace(req.ValidFrom), ValidUntil: strings.TrimSpace(req.ValidUntil), GrantReason: strings.TrimSpace(req.GrantReason),
	}
	principal := h.principal(r)
	result, err := h.executeIdentityAuthoringUpsert(r.Context(), "identity.user_role_assignment", assignment.UserID, "identity.roles.write", r.Header.Get("Builder-Task-ID"), r.Header.Get("Idempotency-Key"), r.Header.Get("Expected-Schema-Hash"), assignment, principal,
		func(ctx context.Context) (any, bool, error) {
			items, loadErr := h.roles.ListUserRoleAssignments(ctx, assignment.UserID)
			return items, len(items) > 0, loadErr
		},
		func(ctx context.Context) (any, error) {
			if executeErr := h.roles.AssignUserRoleGoverned(ctx, assignment, principal); executeErr != nil {
				return nil, executeErr
			}
			h.appendIdentityMutationAudit(r, "identity_user_role_assigned", "identity_user", assignment.UserID, "Assigned identity role to user", map[string]any{"role_id": assignment.RoleID})
			return assignment, nil
		})
	h.writeIdentityAuthoringResult(w, r, http.StatusCreated, result, err)
}

func (h *IdentityHandler) removeIdentityUserRole(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("userID"))
	roleID := strings.TrimSpace(r.PathValue("roleID"))
	principal := h.principal(r)
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if err := h.roles.RemoveUserRoleGoverned(r.Context(), userID, roleID, reason, principal); err != nil {
		h.securityPrincipal(r, principal, "identity_entitlement_revocation_denied", "Denied identity entitlement revocation", map[string]any{
			"target_user_id": userID, "role_id": roleID, "error_code": apperror.CodeOf(err),
		})
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_user_role_removed", "identity_user", userID, "Removed identity role from user", map[string]any{"role_id": roleID, "reason": valueOrDefault(reason, "manual_removal")})
	w.WriteHeader(http.StatusNoContent)
}

func (h *IdentityHandler) applyIdentityEntitlementBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Items []identitymodel.IdentityEntitlementBatchItem `json:"items"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	principal := h.principal(r)
	receipt, err := h.roles.ApplyEntitlementBatch(r.Context(), identityapplication.IdentityEntitlementBatchRequest{
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")),
		Items:          req.Items,
	}, principal)
	if err != nil {
		h.securityPrincipal(r, principal, "identity_entitlement_batch_denied", "Denied atomic identity entitlement batch", map[string]any{
			"item_count": len(req.Items), "error_code": apperror.CodeOf(err),
		})
		h.writeServiceError(w, r, err)
		return
	}
	h.securityPrincipal(r, principal, "identity_entitlement_batch_applied", "Applied atomic identity entitlement batch", map[string]any{
		"receipt_id": receipt.ID, "item_count": len(receipt.Items), "replayed": receipt.Replayed,
	})
	h.writeJSON(w, http.StatusOK, receipt)
}

func (h *IdentityHandler) listIdentityRoleRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := h.roles.ListRoleRequests(r.Context(), strings.TrimSpace(r.URL.Query().Get("status")), strings.TrimSpace(r.URL.Query().Get("user_id")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, requests)
}

func (h *IdentityHandler) approveIdentityRoleRequest(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength > 0 && !h.decodeJSON(w, r, &req) {
		return
	}
	request, err := h.roles.ApproveRoleRequest(r.Context(), strings.TrimSpace(r.PathValue("requestID")), principal.UserID, req.Note, principal)
	if err != nil {
		h.securityPrincipal(r, principal, "identity_role_request_approval_denied", "Denied identity role request approval", map[string]any{
			"request_id": strings.TrimSpace(r.PathValue("requestID")), "error_code": apperror.CodeOf(err),
		})
		h.writeServiceError(w, r, err)
		return
	}
	h.securityPrincipal(r, principal, "identity_role_request_approved", "Approved role request", map[string]any{"request_id": request.ID, "target_user_id": request.UserID, "role_count": len(request.RoleIDs)})
	h.writeJSON(w, http.StatusOK, request)
}

func (h *IdentityHandler) rejectIdentityRoleRequest(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength > 0 && !h.decodeJSON(w, r, &req) {
		return
	}
	request, err := h.roles.RejectRoleRequest(r.Context(), strings.TrimSpace(r.PathValue("requestID")), principal.UserID, req.Note)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.securityPrincipal(r, principal, "identity_role_request_rejected", "Rejected role request", map[string]any{"request_id": request.ID, "target_user_id": request.UserID, "role_count": len(request.RoleIDs)})
	h.writeJSON(w, http.StatusOK, request)
}
