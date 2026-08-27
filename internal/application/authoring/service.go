package authoring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

var (
	ErrLeaseLost          = errors.New("identity authoring lease lost")
	ErrReceiptUnavailable = errors.New("identity authoring receipt unavailable")
)

const defaultLeaseTTL = 30 * time.Second

type Service struct {
	repository Repository
	now        func() time.Time
	newID      func() string
}

func NewService(repository Repository, now func() time.Time, newID func() string) *Service {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if newID == nil {
		newID = requestcontext.NewRequestID
	}
	return &Service{repository: repository, now: now, newID: newID}
}

func (s *Service) ExecuteUpsert(
	ctx context.Context,
	request UpsertRequest,
	principal identitymodel.Principal,
	authorize Authorize,
	current CurrentResource,
	execute Execute,
) (ExecutionResult, error) {
	request.CapabilityKey = strings.TrimSpace(request.CapabilityKey)
	request.ResourceID = strings.TrimSpace(request.ResourceID)
	request.BuilderTaskID = strings.TrimSpace(request.BuilderTaskID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.ExpectedResourceHash = strings.TrimSpace(request.ExpectedResourceHash)
	if authorize == nil || current == nil || execute == nil {
		return ExecutionResult{}, apperror.New(apperror.KindUnavailable, "backend.authoring.owner_contract_unavailable", nil, nil)
	}
	if err := authorize(); err != nil {
		return ExecutionResult{}, err
	}
	// Idempotency-Key is also used by Workforce command routes. A direct
	// authoring envelope is selected only by its builder/precondition headers;
	// this keeps older owner routes that merely forward an idempotency key from
	// being misclassified as builder authoring requests.
	managed := request.BuilderTaskID != "" || request.ExpectedResourceHash != ""
	if !managed {
		value, err := execute()
		return ExecutionResult{Value: value}, err
	}
	if request.CapabilityKey == "" || request.ResourceID == "" || request.BuilderTaskID == "" {
		return ExecutionResult{}, apperror.New(apperror.KindBadRequest, "backend.authoring.request_identity_required", nil, nil)
	}
	if request.IdempotencyKey == "" {
		return ExecutionResult{}, apperror.New(apperror.KindBadRequest, idempotency.ErrorCodeMissingKey, nil, nil)
	}
	if request.ExpectedResourceHash == "" {
		request.ExpectedResourceHash = "empty"
	}
	if trustedTaskID := TrustedBuilderTaskID(ctx); trustedTaskID != "" && trustedTaskID != request.BuilderTaskID {
		return ExecutionResult{}, apperror.New(apperror.KindForbidden, "backend.authoring.builder_task_mismatch", nil, nil)
	}
	fingerprint, err := idempotency.Fingerprint(idempotency.FingerprintInput{
		UseCase: request.CapabilityKey + ".upsert", ResourceType: request.CapabilityKey, TargetID: request.ResourceID,
		Payload: request.Payload, Preconditions: map[string]any{"builder_task_id": request.BuilderTaskID, "expected_resource_hash": request.ExpectedResourceHash},
	})
	if err != nil {
		return ExecutionResult{}, apperror.New(apperror.KindBadRequest, "backend.authoring.payload_invalid", err, nil)
	}
	return s.executeManaged(ctx, principal, request.IdempotencyKey, request.CapabilityKey+".upsert", request.CapabilityKey, request.ResourceID, fingerprint, func() (outcome, error) {
		value, found, loadErr := current()
		if loadErr != nil {
			return outcome{}, loadErr
		}
		actualHash, hashErr := resourceHash(request.CapabilityKey, request.ResourceID, value, found)
		if hashErr != nil {
			return outcome{}, hashErr
		}
		if request.ExpectedResourceHash != actualHash {
			return outcome{}, apperror.New(apperror.KindConflict, "backend.authoring.resource_hash_conflict", nil, map[string]string{"expected": request.ExpectedResourceHash, "actual": actualHash})
		}
		result, executeErr := execute()
		if executeErr != nil {
			return outcome{}, executeErr
		}
		persisted, persistedFound, loadErr := current()
		if loadErr != nil {
			return outcome{}, loadErr
		}
		persistedHash, hashErr := resourceHash(request.CapabilityKey, request.ResourceID, persisted, persistedFound)
		if hashErr != nil {
			return outcome{}, hashErr
		}
		if !persistedFound || persistedHash == "empty" {
			return outcome{}, apperror.New(apperror.KindUnavailable, "backend.authoring.resource_projection_unavailable", nil, nil)
		}
		return outcome{Value: result, ResourceHash: persistedHash}, nil
	})
}

func (s *Service) ExecuteCommand(ctx context.Context, request CommandRequest, principal identitymodel.Principal, authorize Authorize, execute Execute) (ExecutionResult, error) {
	request.UseCase = strings.TrimSpace(request.UseCase)
	request.ResourceType = strings.TrimSpace(request.ResourceType)
	request.ResourceID = strings.TrimSpace(request.ResourceID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	if request.UseCase == "" || request.ResourceType == "" || request.ResourceID == "" {
		return ExecutionResult{}, apperror.New(apperror.KindBadRequest, "backend.authoring.request_identity_required", nil, nil)
	}
	if request.IdempotencyKey == "" {
		return ExecutionResult{}, apperror.New(apperror.KindBadRequest, idempotency.ErrorCodeMissingKey, nil, nil)
	}
	if authorize == nil || execute == nil {
		return ExecutionResult{}, apperror.New(apperror.KindUnavailable, "backend.authoring.owner_contract_unavailable", nil, nil)
	}
	if err := authorize(); err != nil {
		return ExecutionResult{}, err
	}
	fingerprint, err := idempotency.Fingerprint(idempotency.FingerprintInput{
		UseCase: request.UseCase, ResourceType: request.ResourceType, TargetID: request.ResourceID, Payload: request.Payload,
	})
	if err != nil {
		return ExecutionResult{}, apperror.New(apperror.KindBadRequest, "backend.authoring.payload_invalid", err, nil)
	}
	return s.executeManaged(ctx, principal, request.IdempotencyKey, request.UseCase, request.ResourceType, request.ResourceID, fingerprint, func() (outcome, error) {
		value, executeErr := execute()
		return outcome{Value: value}, executeErr
	})
}

type outcome struct {
	Value        any                `json:"value,omitempty"`
	ResourceHash string             `json:"resource_hash,omitempty"`
	ErrorKind    apperror.ErrorKind `json:"error_kind,omitempty"`
	ErrorCode    string             `json:"error_code,omitempty"`
}

func (s *Service) executeManaged(ctx context.Context, principal identitymodel.Principal, key, useCase, resourceType, targetID, fingerprint string, execute func() (outcome, error)) (ExecutionResult, error) {
	if s == nil || s.repository == nil {
		return ExecutionResult{}, apperror.New(apperror.KindUnavailable, idempotency.ErrorCodeReceiptUnavailable, nil, nil)
	}
	now := s.now().UTC()
	leaseOwner := strings.TrimSpace(s.newID())
	receipt := Receipt{
		ID: authoringReceiptID(principal.WorkspaceID, key), WorkspaceID: strings.TrimSpace(principal.WorkspaceID), UseCase: useCase,
		ResourceType: resourceType, TargetID: targetID, IdempotencyKey: key, RequestFingerprint: fingerprint,
		Status: idempotency.StatusProcessing, LeaseOwner: leaseOwner, LeaseExpiresAt: now.Add(defaultLeaseTTL), FencingToken: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	claim, err := s.repository.Claim(ctx, receipt, defaultLeaseTTL)
	if err != nil {
		return ExecutionResult{}, apperror.New(apperror.KindInternal, idempotency.ErrorCodeReceiptUnavailable, err, nil)
	}
	switch claim.Decision {
	case idempotency.DecisionFingerprintConflict:
		return ExecutionResult{}, apperror.New(apperror.KindConflict, idempotency.ErrorCodeKeyReused, nil, nil)
	case idempotency.DecisionInProgress:
		return ExecutionResult{}, apperror.New(apperror.KindConflict, idempotency.ErrorCodeInProgress, nil, nil)
	case idempotency.DecisionReplay:
		return replayResult(claim.Receipt)
	case idempotency.DecisionAcquired:
		// continue below
	default:
		return ExecutionResult{}, apperror.New(apperror.KindInternal, idempotency.ErrorCodeReceiptUnavailable, nil, nil)
	}
	value, ownerErr := execute()
	if ownerErr != nil {
		value.ErrorKind = apperror.KindOf(ownerErr)
		value.ErrorCode = apperror.CodeOf(ownerErr)
	}
	encoded, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		ownerErr = apperror.New(apperror.KindInternal, "backend.authoring.result_invalid", marshalErr, nil)
		encoded, _ = json.Marshal(outcome{ErrorKind: apperror.KindInternal, ErrorCode: "backend.authoring.result_invalid"})
	}
	status := idempotency.StatusSucceeded
	if ownerErr != nil {
		status = idempotency.StatusFailedTerminal
	}
	completed, completeErr := s.repository.Complete(ctx, Completion{
		ReceiptID: claim.Receipt.ID, WorkspaceID: claim.Receipt.WorkspaceID, LeaseOwner: claim.Receipt.LeaseOwner,
		FencingToken: claim.Receipt.FencingToken, Status: status, Result: encoded, CompletedAt: s.now().UTC(),
	})
	if completeErr != nil {
		return ExecutionResult{}, apperror.New(apperror.KindConflict, idempotency.ErrorCodeLeaseLost, completeErr, nil)
	}
	return ExecutionResult{Value: value.Value, OperationID: completed.ID, ResourceHash: value.ResourceHash}, ownerErr
}

func replayResult(receipt Receipt) (ExecutionResult, error) {
	var stored struct {
		Value        json.RawMessage    `json:"value"`
		ResourceHash string             `json:"resource_hash"`
		ErrorKind    apperror.ErrorKind `json:"error_kind"`
		ErrorCode    string             `json:"error_code"`
	}
	if err := json.Unmarshal(receipt.Result, &stored); err != nil {
		return ExecutionResult{}, apperror.New(apperror.KindInternal, "backend.authoring.receipt_result_invalid", err, nil)
	}
	var value any
	if len(stored.Value) != 0 && string(stored.Value) != "null" {
		if err := json.Unmarshal(stored.Value, &value); err != nil {
			return ExecutionResult{}, apperror.New(apperror.KindInternal, "backend.authoring.receipt_result_invalid", err, nil)
		}
	}
	result := ExecutionResult{Value: value, OperationID: receipt.ID, ResourceHash: stored.ResourceHash, Replayed: true}
	if receipt.Status == idempotency.StatusFailedTerminal {
		return result, apperror.New(stored.ErrorKind, stored.ErrorCode, nil, nil)
	}
	return result, nil
}

func resourceHash(capabilityKey, resourceID string, value any, found bool) (string, error) {
	if !found {
		return "empty", nil
	}
	return idempotency.Fingerprint(idempotency.FingerprintInput{UseCase: capabilityKey + ".resource", ResourceType: capabilityKey, TargetID: resourceID, Payload: value})
}

func authoringReceiptID(workspaceID, key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(workspaceID) + "\x00" + strings.TrimSpace(key)))
	return "identity_authoring_" + hex.EncodeToString(sum[:12])
}
