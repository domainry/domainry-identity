package operationreceipt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/idempotency"
	sharedoperation "github.com/domainry/domainry-foundation/operation"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

const (
	StatusStarted   = sharedoperation.StatusStarted
	StatusSucceeded = sharedoperation.StatusSucceeded
	StatusFailed    = sharedoperation.StatusFailed
)

type Leased = sharedoperation.LeasedRecord
type Started struct {
	Leased
	Owner          string
	Kind           string
	Reason         string
	Reference      string
	MetadataJSON   json.RawMessage
	RelatedIDsJSON json.RawMessage
	EvidenceJSON   json.RawMessage
}
type Reclaim = sharedoperation.LeaseReclaim
type Completion = sharedoperation.LeaseCompletion

func InsertStarted(ctx context.Context, execer Execer, renderer ormdialect.Renderer, value Started) error {
	return sharedoperation.InsertStarted(ctx, execer, renderer, sharedoperation.StartedRecord{
		LeasedRecord:   value.Leased,
		Owner:          value.Owner,
		Kind:           value.Kind,
		Reason:         value.Reason,
		Reference:      value.Reference,
		MetadataJSON:   value.MetadataJSON,
		RelatedIDsJSON: value.RelatedIDsJSON,
		EvidenceJSON:   value.EvidenceJSON,
	})
}

func LoadLeasedByKey(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, idempotencyKey string) (Leased, bool, error) {
	return sharedoperation.LoadLeasedByKey(ctx, queryer, renderer, workspaceID, owner, kind, idempotencyKey)
}

func LoadLeasedByID(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, id string) (Leased, bool, error) {
	return sharedoperation.LoadLeasedByID(ctx, queryer, renderer, workspaceID, owner, kind, id)
}

func ReclaimStarted(ctx context.Context, execer Execer, renderer ormdialect.Renderer, value Reclaim) (bool, error) {
	return sharedoperation.ReclaimStarted(ctx, execer, renderer, value)
}

func CompleteLeased(ctx context.Context, execer Execer, renderer ormdialect.Renderer, value Completion) (bool, error) {
	return sharedoperation.CompleteLeased(ctx, execer, renderer, value)
}

func IdempotencyStatus(status string) (idempotency.Status, error) {
	switch strings.TrimSpace(status) {
	case StatusStarted:
		return idempotency.StatusProcessing, nil
	case StatusSucceeded:
		return idempotency.StatusSucceeded, nil
	case StatusFailed:
		return idempotency.StatusFailedTerminal, nil
	default:
		return "", fmt.Errorf("identity shared leased operation status %q is invalid", status)
	}
}

func OperationStatus(status idempotency.Status) (string, error) {
	switch status {
	case idempotency.StatusProcessing:
		return StatusStarted, nil
	case idempotency.StatusSucceeded:
		return StatusSucceeded, nil
	case idempotency.StatusFailedTerminal:
		return StatusFailed, nil
	default:
		return "", fmt.Errorf("identity idempotency status %q has no shared Operations state", status)
	}
}
