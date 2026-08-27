package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

type IdentityEntitlementBatchRequest struct {
	IdempotencyKey string                                       `json:"idempotency_key"`
	Items          []identitymodel.IdentityEntitlementBatchItem `json:"items"`
}

func (s *IdentityApplicationService) ApplyEntitlementBatch(ctx context.Context, request IdentityEntitlementBatchRequest, actor identitymodel.Principal) (identitymodel.IdentityEntitlementBatchReceipt, error) {
	if err := ctx.Err(); err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	if !actor.Known || strings.TrimSpace(actor.UserID) == "" {
		return identitymodel.IdentityEntitlementBatchReceipt{}, apperror.New(apperror.KindForbidden, "backend.identity.entitlement_actor_required", nil, nil)
	}
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.IdempotencyKey == "" || len(request.Items) == 0 {
		return identitymodel.IdentityEntitlementBatchReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.entitlement_batch_invalid", nil, nil)
	}
	scoped, err := s.domainForContext(ctx)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	repository, ok := scoped.Repository().(identityrepository.IdentityEntitlementBatchRepository)
	if !ok {
		return identitymodel.IdentityEntitlementBatchReceipt{}, apperror.New(apperror.KindInternal, "backend.identity.entitlement_batch_unavailable", nil, nil)
	}
	fingerprint := identityEntitlementBatchFingerprint(actor.UserID, request.Items)
	if receipt, found, receiptErr := repository.GetIdentityEntitlementBatchReceipt(ctx, scoped.WorkspaceID(), request.IdempotencyKey); receiptErr != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, receiptErr
	} else if found {
		if receipt.RequestFingerprint != fingerprint {
			return identitymodel.IdentityEntitlementBatchReceipt{}, apperror.New(apperror.KindConflict, "backend.idempotency_key_reused", nil, nil)
		}
		receipt.Replayed = true
		return receipt, nil
	}
	items, assignments, err := scoped.PrepareIdentityEntitlementBatch(ctx, request.Items, actor)
	if err != nil {
		return identitymodel.IdentityEntitlementBatchReceipt{}, err
	}
	return repository.ApplyIdentityEntitlementBatch(ctx, identitymodel.IdentityEntitlementBatchMutation{
		WorkspaceID: scoped.WorkspaceID(), ActorID: strings.TrimSpace(actor.UserID), IdempotencyKey: request.IdempotencyKey,
		RequestFingerprint: fingerprint, Items: items, Assignments: assignments,
	})
}

func identityEntitlementBatchFingerprint(actorID string, items []identitymodel.IdentityEntitlementBatchItem) string {
	canonical := append([]identitymodel.IdentityEntitlementBatchItem(nil), items...)
	for index := range canonical {
		canonical[index].Operation = strings.TrimSpace(canonical[index].Operation)
		canonical[index].UserID = strings.TrimSpace(canonical[index].UserID)
		canonical[index].RoleID = strings.TrimSpace(canonical[index].RoleID)
		canonical[index].WorkforceProfileID = strings.TrimSpace(canonical[index].WorkforceProfileID)
		canonical[index].BindingKey = strings.TrimSpace(canonical[index].BindingKey)
		canonical[index].ProfileID = strings.TrimSpace(canonical[index].ProfileID)
		canonical[index].ValidFrom = strings.TrimSpace(canonical[index].ValidFrom)
		canonical[index].ValidUntil = strings.TrimSpace(canonical[index].ValidUntil)
		canonical[index].Reason = strings.TrimSpace(canonical[index].Reason)
	}
	sort.Slice(canonical, func(i, j int) bool {
		left, _ := json.Marshal(canonical[i])
		right, _ := json.Marshal(canonical[j])
		return string(left) < string(right)
	})
	raw, _ := json.Marshal(struct {
		ActorID string                                       `json:"actor_id"`
		Items   []identitymodel.IdentityEntitlementBatchItem `json:"items"`
	}{ActorID: strings.TrimSpace(actorID), Items: canonical})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
