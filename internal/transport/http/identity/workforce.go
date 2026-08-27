package identity

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (h *IdentityHandler) requireWorkforceIdempotencyKey(w http.ResponseWriter, r *http.Request, useCase string) bool {
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) != "" {
		return true
	}
	h.writeServiceError(w, r, apperror.New(apperror.KindBadRequest, idempotency.ErrorCodeMissingKey, nil, map[string]string{"use_case": useCase}))
	return false
}

func (h *IdentityHandler) executeWorkforceOwnerOperation(
	w http.ResponseWriter,
	r *http.Request,
	kind, resourceID string,
	payload any,
	execute func(context.Context) (any, error),
) (identityAuthoringResult, error) {
	if h.authoring == nil {
		return identityAuthoringResult{}, apperror.New(apperror.KindUnavailable, idempotency.ErrorCodeReceiptUnavailable, nil, nil)
	}
	principal := h.principal(r)
	result, err := h.authoring.ExecuteCommand(r.Context(), identityauthoring.CommandRequest{
		UseCase: kind, ResourceType: "identity_workforce_profile", ResourceID: resourceID,
		IdempotencyKey: r.Header.Get("Idempotency-Key"), Payload: payload,
	}, principal, func() error { return identityAuthoringAllowed(principal, "identity.workforce.write") }, func() (any, error) { return execute(r.Context()) })
	if err == nil {
		writeIdentityOperationHeaders(w, result)
	}
	return result, err
}

func (h *IdentityHandler) applyIdentityWorkforceLifecycle(w http.ResponseWriter, r *http.Request) {
	var request identityapplication.IdentityWorkforceLifecycleRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if !h.requireWorkforceIdempotencyKey(w, r, "identity.workforce.lifecycle") {
		return
	}
	profileID := strings.TrimSpace(r.PathValue("profileID"))
	if request.Profile.ID != "" && request.Profile.ID != profileID {
		h.writeError(w, r, http.StatusBadRequest, "backend.identity.workforce_profile_id_mismatch")
		return
	}
	request.Profile.ID = profileID
	request.ActorID = h.principal(r).UserID
	operation, err := h.executeWorkforceOwnerOperation(w, r, "identity.workforce.lifecycle", profileID, request, func(ctx context.Context) (any, error) {
		result, executeErr := h.users.ApplyWorkforceLifecycle(ctx, request)
		if executeErr != nil {
			return nil, executeErr
		}
		h.appendIdentityMutationAudit(r, "identity_workforce_lifecycle_applied", "identity_workforce_profile", profileID, "Applied workforce lifecycle operation", map[string]any{
			"operation": request.Operation, "reason": strings.TrimSpace(request.Reason),
			"ended_assignments": result.EndedAssignmentCount, "revoked_entitlements": result.RevokedEntitlementCount,
		})
		return result, nil
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, operation.Value)
}

func (h *IdentityHandler) onboardIdentityWorkforce(w http.ResponseWriter, r *http.Request) {
	var request identityapplication.IdentityWorkforceOnboardingRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if !h.requireWorkforceIdempotencyKey(w, r, "identity.workforce.onboard") {
		return
	}
	operation, err := h.executeWorkforceOwnerOperation(w, r, "identity.workforce.onboard", request.Profile.ID, request, func(ctx context.Context) (any, error) {
		result, executeErr := h.users.OnboardWorkforce(ctx, request, h.principal(r))
		if executeErr != nil {
			return nil, executeErr
		}
		h.appendIdentityMutationAudit(r, "identity_workforce_onboarded", "identity_workforce_profile", result.Profile.ID, "Created account, Workforce profile, primary assignment, and initial role assignments atomically", map[string]any{
			"identity_user_id": result.User.ID, "assignment_id": result.Assignment.ID,
			"role_count": len(result.RoleAssignments), "reason": strings.TrimSpace(request.Reason),
		})
		return result, nil
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, operation.Value)
}

func (h *IdentityHandler) applyIdentityWorkforceTransferBatch(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Items []identitymodel.IdentityWorkforceTransferBatchItem `json:"items"`
	}
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if !h.requireWorkforceIdempotencyKey(w, r, "identity.workforce.transfer_batch") {
		return
	}
	receipt, err := h.users.ApplyWorkforceTransferBatch(r.Context(), identityapplication.IdentityWorkforceTransferBatchRequest{
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")),
		Items:          request.Items,
	}, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_workforce_transfer_batch_applied", "identity_workforce_profile", receipt.ID, "Applied atomic Workforce transfer batch", map[string]any{
		"receipt_id": receipt.ID, "item_count": len(receipt.Items), "replayed": receipt.Replayed,
	})
	h.writeJSON(w, http.StatusOK, receipt)
}

func (h *IdentityHandler) rehireIdentityWorkforce(w http.ResponseWriter, r *http.Request) {
	var request struct {
		EffectiveAt string                                    `json:"effective_at"`
		Assignment  identitymodel.IdentityWorkforceAssignment `json:"assignment"`
		Reason      string                                    `json:"reason"`
	}
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if !h.requireWorkforceIdempotencyKey(w, r, "identity.workforce.rehire") {
		return
	}
	profileID := strings.TrimSpace(r.PathValue("profileID"))
	operation, err := h.executeWorkforceOwnerOperation(w, r, "identity.workforce.rehire", profileID, request, func(ctx context.Context) (any, error) {
		result, executeErr := h.users.RehireWorkforce(ctx, profileID, request.EffectiveAt, request.Assignment, h.principal(r), request.Reason)
		if executeErr != nil {
			return nil, executeErr
		}
		h.appendIdentityMutationAudit(r, "identity_workforce_rehired", "identity_workforce_profile", profileID, "Rehired Workforce with a fresh primary assignment without restoring old entitlements", map[string]any{"assignment_id": request.Assignment.ID})
		return result, nil
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, operation.Value)
}

func (h *IdentityHandler) listIdentityWorkforceProfiles(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.URL.Query().Get("projection")) == "application" {
		page, err := h.users.ListWorkforceApplicationProjection(r.Context(), h.principal(r), identityWorkforceProjectionQuery(r))
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		h.writeJSON(w, http.StatusOK, page)
		return
	}
	profiles, err := h.users.ListWorkforceProfilesForPrincipal(r.Context(), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"items": profiles, "total": len(profiles)})
}

func (h *IdentityHandler) searchIdentityWorkforceProfiles(w http.ResponseWriter, r *http.Request) {
	page, err := h.users.SearchWorkforceProfilesForPrincipal(r.Context(), identityListQuery(r), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, page)
}

func (h *IdentityHandler) getIdentityWorkforceProfile(w http.ResponseWriter, r *http.Request) {
	profile, found, err := h.users.GetWorkforceProfileForPrincipal(r.Context(), strings.TrimSpace(r.PathValue("profileID")), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if !found {
		h.writeError(w, r, http.StatusNotFound, "backend.identity.workforce_profile_not_found")
		return
	}
	h.writeIdentityAuthoringResource(w, r, "identity.workforce_profile", profile.ID, profile)
}

func (h *IdentityHandler) getIdentityWorkforceDetail(w http.ResponseWriter, r *http.Request) {
	detail, found, err := h.users.GetWorkforceDetailForPrincipal(r.Context(), strings.TrimSpace(r.PathValue("profileID")), h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if !found {
		h.writeError(w, r, http.StatusNotFound, "backend.identity.workforce_profile_not_found")
		return
	}
	h.writeJSON(w, http.StatusOK, detail)
}

func (h *IdentityHandler) upsertIdentityWorkforceProfile(w http.ResponseWriter, r *http.Request) {
	var profile identitymodel.IdentityWorkforceProfile
	if !h.decodeJSON(w, r, &profile) {
		return
	}
	if pathID := strings.TrimSpace(r.PathValue("profileID")); pathID != "" {
		if profile.ID != "" && profile.ID != pathID {
			h.writeError(w, r, http.StatusBadRequest, "backend.identity.workforce_profile_id_mismatch")
			return
		}
		profile.ID = pathID
	}
	principal := h.principal(r)
	result, err := h.executeIdentityAuthoringUpsert(r.Context(), "identity.workforce_profile", profile.ID, "identity.workforce.write", r.Header.Get("Builder-Task-ID"), r.Header.Get("Idempotency-Key"), r.Header.Get("Expected-Schema-Hash"), profile, principal,
		func(ctx context.Context) (any, bool, error) { return h.users.GetWorkforceProfile(ctx, profile.ID) },
		func(ctx context.Context) (any, error) {
			if executeErr := h.users.UpsertWorkforceProfile(ctx, profile); executeErr != nil {
				return nil, executeErr
			}
			h.appendIdentityMutationAudit(r, "identity_workforce_profile_upserted", "identity_workforce_profile", profile.ID, "Upserted workforce profile", map[string]any{"identity_user_id": profile.IdentityUserID, "work_status": profile.WorkStatus})
			return profile, nil
		})
	h.writeIdentityAuthoringResult(w, r, http.StatusOK, result, err)
}

func (h *IdentityHandler) validateIdentityWorkforceProfile(w http.ResponseWriter, r *http.Request) {
	var profile identitymodel.IdentityWorkforceProfile
	if !h.decodeJSON(w, r, &profile) {
		return
	}
	profile.ID = valueOrDefault(strings.TrimSpace(r.PathValue("profileID")), profile.ID)
	if err := h.users.ValidateWorkforceProfile(r.Context(), profile); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (h *IdentityHandler) terminateIdentityWorkforceProfile(w http.ResponseWriter, r *http.Request) {
	var request struct {
		EffectiveAt string `json:"effective_at"`
		Reason      string `json:"reason"`
	}
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if !h.requireWorkforceIdempotencyKey(w, r, "identity.workforce.terminate") {
		return
	}
	profileID := strings.TrimSpace(r.PathValue("profileID"))
	operation, err := h.executeWorkforceOwnerOperation(w, r, "identity.workforce.terminate", profileID, request, func(ctx context.Context) (any, error) {
		profile, executeErr := h.users.TerminateWorkforceProfile(ctx, profileID, request.EffectiveAt, identitymodel.IdentityWorkforceTerminationOptions{
			ActorID: h.principal(r).UserID, Reason: request.Reason,
		})
		if executeErr != nil {
			return nil, executeErr
		}
		h.appendIdentityMutationAudit(r, "identity_workforce_terminated", "identity_workforce_profile", profileID, "Terminated workforce profile", map[string]any{
			"effective_at": strings.TrimSpace(request.EffectiveAt), "reason": strings.TrimSpace(request.Reason),
			"profile_bindings_preserved": true,
		})
		return profile, nil
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, operation.Value)
}

func (h *IdentityHandler) listIdentityWorkforceAssignments(w http.ResponseWriter, r *http.Request) {
	profileID := strings.TrimSpace(r.PathValue("profileID"))
	if _, found, err := h.users.GetWorkforceProfileForPrincipal(r.Context(), profileID, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	} else if !found {
		h.writeError(w, r, http.StatusNotFound, "backend.identity.workforce_profile_not_found")
		return
	}
	assignments, err := h.users.ListWorkforceAssignments(r.Context(), profileID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	// IdentityWorkforceAssignment contains only JSON-safe scalar fields.
	resourceHash, _ := identityAuthoringResourceHash("identity.workforce_assignment", profileID, assignments, len(assignments) > 0)
	w.Header().Set(identityResourceHashHeader, resourceHash)
	h.writeJSON(w, http.StatusOK, map[string]any{"items": assignments, "total": len(assignments)})
}

func identityWorkforceProjectionQuery(r *http.Request) identitymodel.IdentityWorkforceProjectionQuery {
	query := identitymodel.IdentityWorkforceProjectionQuery{
		Search:       strings.TrimSpace(r.URL.Query().Get("search")),
		DepartmentID: strings.TrimSpace(r.URL.Query().Get("department_id")),
		WorkStatus:   identitymodel.IdentityWorkStatus(strings.TrimSpace(r.URL.Query().Get("work_status"))),
	}
	query.Page, _ = strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page")))
	query.PageSize, _ = strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page_size")))
	if query.PageSize > 200 {
		query.PageSize = 200
	}
	return query
}

func (h *IdentityHandler) upsertIdentityWorkforceAssignment(w http.ResponseWriter, r *http.Request) {
	var assignment identitymodel.IdentityWorkforceAssignment
	if !h.decodeJSON(w, r, &assignment) {
		return
	}
	profileID := strings.TrimSpace(r.PathValue("profileID"))
	if assignment.WorkforceProfileID != "" && assignment.WorkforceProfileID != profileID {
		h.writeError(w, r, http.StatusBadRequest, "backend.identity.workforce_assignment_profile_mismatch")
		return
	}
	assignment.WorkforceProfileID = profileID
	principal := h.principal(r)
	result, err := h.executeIdentityAuthoringUpsert(r.Context(), "identity.workforce_assignment", profileID, "identity.workforce.write", r.Header.Get("Builder-Task-ID"), r.Header.Get("Idempotency-Key"), r.Header.Get("Expected-Schema-Hash"), assignment, principal,
		func(ctx context.Context) (any, bool, error) {
			items, loadErr := h.users.ListWorkforceAssignments(ctx, profileID)
			if loadErr != nil {
				return nil, false, loadErr
			}
			return items, len(items) > 0, nil
		},
		func(ctx context.Context) (any, error) {
			if executeErr := h.users.UpsertWorkforceAssignment(ctx, assignment); executeErr != nil {
				return nil, executeErr
			}
			h.appendIdentityMutationAudit(r, "identity_workforce_assignment_upserted", "identity_workforce_assignment", assignment.ID, "Upserted workforce assignment", map[string]any{"workforce_profile_id": assignment.WorkforceProfileID, "organization_unit_id": assignment.OrganizationUnitID, "assignment_type": assignment.AssignmentType})
			return assignment, nil
		})
	h.writeIdentityAuthoringResult(w, r, http.StatusOK, result, err)
}

func (h *IdentityHandler) validateIdentityWorkforceAssignment(w http.ResponseWriter, r *http.Request) {
	var assignment identitymodel.IdentityWorkforceAssignment
	if !h.decodeJSON(w, r, &assignment) {
		return
	}
	assignment.WorkforceProfileID = valueOrDefault(strings.TrimSpace(r.PathValue("profileID")), assignment.WorkforceProfileID)
	if err := h.users.ValidateWorkforceAssignment(r.Context(), assignment); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}
