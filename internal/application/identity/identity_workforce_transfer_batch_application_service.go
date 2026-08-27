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

type IdentityWorkforceTransferBatchRequest struct {
	IdempotencyKey string                                             `json:"idempotency_key"`
	Items          []identitymodel.IdentityWorkforceTransferBatchItem `json:"items"`
}

func (s *IdentityApplicationService) ApplyWorkforceTransferBatch(ctx context.Context, request IdentityWorkforceTransferBatchRequest, actor identitymodel.Principal) (identitymodel.IdentityWorkforceTransferBatchReceipt, error) {
	if err := ctx.Err(); err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
	}
	if !actor.Known || strings.TrimSpace(actor.UserID) == "" {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, apperror.New(apperror.KindForbidden, "backend.identity.entitlement_actor_required", nil, nil)
	}
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.IdempotencyKey == "" || len(request.Items) == 0 {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, apperror.New(apperror.KindBadRequest, "backend.identity.workforce_transfer_batch_invalid", nil, nil)
	}
	scoped, err := s.workforceForContext(ctx)
	if err != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
	}
	repository, ok := scoped.workforceRepository.(identityrepository.IdentityWorkforceTransferBatchRepository)
	if !ok {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, apperror.New(apperror.KindInternal, "backend.identity.workforce_transfer_batch_unavailable", nil, nil)
	}
	fingerprint := identityWorkforceTransferBatchFingerprint(actor.UserID, request.Items)
	if receipt, found, receiptErr := repository.GetIdentityWorkforceTransferBatchReceipt(ctx, scoped.WorkspaceID(), request.IdempotencyKey); receiptErr != nil {
		return identitymodel.IdentityWorkforceTransferBatchReceipt{}, receiptErr
	} else if found {
		if receipt.RequestFingerprint != fingerprint {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, apperror.New(apperror.KindConflict, "backend.idempotency_key_reused", nil, nil)
		}
		receipt.Replayed = true
		return receipt, nil
	}
	items := make([]identitymodel.IdentityWorkforceTransferBatchItem, 0, len(request.Items))
	mutations := make([]identitymodel.IdentityWorkforceLifecycleMutation, 0, len(request.Items))
	seenProfiles := map[string]struct{}{}
	for _, raw := range request.Items {
		item := normalizeIdentityWorkforceTransferBatchItem(raw)
		if _, duplicate := seenProfiles[item.ProfileID]; duplicate {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, apperror.New(apperror.KindConflict, "backend.identity.workforce_transfer_batch_duplicate_profile", nil, nil)
		}
		seenProfiles[item.ProfileID] = struct{}{}
		if err := scoped.WorkforceDomainService.ValidateLifecycleEffectiveDate(item.EffectiveAt); err != nil {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
		}
		profile, found, loadErr := scoped.workforceRepository.GetIdentityWorkforceProfile(ctx, scoped.WorkspaceID(), item.ProfileID)
		if loadErr != nil {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, loadErr
		}
		if !found {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, apperror.New(apperror.KindNotFound, "backend.identity.workforce_profile_not_found", nil, nil)
		}
		previous, previousFound, previousErr := scoped.workforceRepository.GetIdentityWorkforceAssignment(ctx, scoped.WorkspaceID(), item.PreviousAssignmentID)
		if previousErr != nil {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, previousErr
		}
		if !previousFound || previous.WorkforceProfileID != profile.ID || previous.AssignmentType != identitymodel.IdentityWorkforceAssignmentPrimary || previous.Status != identitymodel.IdentityStatusActive {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, apperror.New(apperror.KindConflict, "backend.identity.workforce_transfer_source_invalid", nil, nil)
		}
		item.Assignment.WorkforceProfileID = profile.ID
		item.Assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentPrimary
		item.Assignment.Status = identitymodel.IdentityStatusActive
		item.Assignment.EffectiveFrom = item.EffectiveAt
		if err := scoped.WorkforceDomainService.ValidateAssignmentAgainstProfile(ctx, item.Assignment, profile, previous.ID); err != nil {
			return identitymodel.IdentityWorkforceTransferBatchReceipt{}, err
		}
		profile.PrimaryAssignmentID = item.Assignment.ID
		items = append(items, item)
		mutations = append(mutations, identitymodel.IdentityWorkforceLifecycleMutation{
			WorkspaceID: scoped.WorkspaceID(), ActorID: actor.UserID, Reason: item.Reason, Profile: &profile,
			EndAssignments:    []identitymodel.IdentityWorkforceAssignmentEnd{{AssignmentID: previous.ID, EffectiveTo: item.EffectiveAt}},
			UpsertAssignments: []identitymodel.IdentityWorkforceAssignment{item.Assignment},
		})
	}
	return repository.ApplyIdentityWorkforceTransferBatch(ctx, identitymodel.IdentityWorkforceTransferBatchMutation{
		WorkspaceID: scoped.WorkspaceID(), ActorID: strings.TrimSpace(actor.UserID), IdempotencyKey: request.IdempotencyKey,
		RequestFingerprint: fingerprint, Items: items, Mutations: mutations,
	})
}

func normalizeIdentityWorkforceTransferBatchItem(item identitymodel.IdentityWorkforceTransferBatchItem) identitymodel.IdentityWorkforceTransferBatchItem {
	item.ProfileID = strings.TrimSpace(item.ProfileID)
	item.PreviousAssignmentID = strings.TrimSpace(item.PreviousAssignmentID)
	item.Assignment.ID = strings.TrimSpace(item.Assignment.ID)
	item.Assignment.OrganizationUnitID = strings.TrimSpace(item.Assignment.OrganizationUnitID)
	item.EffectiveAt = strings.TrimSpace(item.EffectiveAt)
	item.Reason = strings.TrimSpace(item.Reason)
	return item
}

func identityWorkforceTransferBatchFingerprint(actorID string, items []identitymodel.IdentityWorkforceTransferBatchItem) string {
	canonical := append([]identitymodel.IdentityWorkforceTransferBatchItem(nil), items...)
	for index := range canonical {
		canonical[index] = normalizeIdentityWorkforceTransferBatchItem(canonical[index])
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].ProfileID < canonical[j].ProfileID })
	raw, _ := json.Marshal(struct {
		ActorID string                                             `json:"actor_id"`
		Items   []identitymodel.IdentityWorkforceTransferBatchItem `json:"items"`
	}{ActorID: strings.TrimSpace(actorID), Items: canonical})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
