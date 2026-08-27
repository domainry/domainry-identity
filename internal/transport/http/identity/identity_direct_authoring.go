package identity

import (
	"context"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
)

type identityAuthoringCurrent func(context.Context) (any, bool, error)

type identityAuthoringResult = identityauthoring.ExecutionResult

const identityResourceHashHeader = "X-Resource-Hash"

func identityAuthoringResourceHash(capabilityKey, resourceID string, value any, found bool) (string, error) {
	if !found {
		return "empty", nil
	}
	return idempotency.Fingerprint(idempotency.FingerprintInput{
		UseCase:      capabilityKey + ".resource",
		ResourceType: capabilityKey,
		TargetID:     resourceID,
		Payload:      value,
	})
}

func (h *IdentityHandler) writeIdentityAuthoringResource(
	w http.ResponseWriter,
	r *http.Request,
	capabilityKey string,
	resourceID string,
	value any,
) {
	resourceHash, err := identityAuthoringResourceHash(capabilityKey, resourceID, value, true)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	w.Header().Set(identityResourceHashHeader, resourceHash)
	h.writeJSON(w, http.StatusOK, value)
}

func (h *IdentityHandler) executeIdentityAuthoringUpsert(
	ctx context.Context,
	capabilityKey, resourceID, permission, builderTaskID, idempotencyKey, expectedResourceHash string,
	payload any,
	principal identitymodel.Principal,
	current identityAuthoringCurrent,
	execute func(context.Context) (any, error),
) (identityAuthoringResult, error) {
	if h.authoring == nil {
		return identityAuthoringResult{}, apperror.New(apperror.KindUnavailable, idempotency.ErrorCodeReceiptUnavailable, nil, nil)
	}
	return h.authoring.ExecuteUpsert(ctx, identityauthoring.UpsertRequest{
		CapabilityKey: capabilityKey, ResourceID: resourceID, BuilderTaskID: builderTaskID,
		IdempotencyKey: idempotencyKey, ExpectedResourceHash: expectedResourceHash, Payload: payload,
	}, principal,
		func() error { return identityAuthoringAllowed(principal, permission) },
		func() (any, bool, error) { return current(ctx) },
		func() (any, error) { return execute(ctx) },
	)
}

func (h *IdentityHandler) writeIdentityAuthoringResult(w http.ResponseWriter, r *http.Request, status int, result identityAuthoringResult, err error) {
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeIdentityOperationHeaders(w, result)
	if result.ResourceHash != "" {
		w.Header().Set(identityResourceHashHeader, result.ResourceHash)
	}
	if result.OperationID != "" {
		h.writeJSON(w, status, map[string]any{"resource": result.Value, "resource_hash": result.ResourceHash})
		return
	}
	h.writeJSON(w, status, result.Value)
}

func writeIdentityOperationHeaders(w http.ResponseWriter, result identityAuthoringResult) {
	if strings.TrimSpace(result.OperationID) == "" {
		return
	}
	w.Header().Set("Operation-ID", result.OperationID)
	if result.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
}

func identityAuthoringAllowed(principal identitymodel.Principal, permission string) error {
	if !principal.Known || strings.TrimSpace(principal.WorkspaceID) == "" {
		return apperror.New(apperror.KindBadRequest, "backend.workspace_scope_required", nil, nil)
	}
	if !identitypolicy.IdentityRoleHasPermissionKey(principal.Role, permission) {
		return apperror.New(apperror.KindForbidden, "auth.permission_denied", nil, nil)
	}
	return nil
}
