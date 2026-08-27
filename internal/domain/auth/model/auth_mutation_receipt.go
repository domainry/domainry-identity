package authmodel

import (
	"encoding/json"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
)

type AuthMutationReceipt struct {
	ID, WorkspaceID, UseCase, TargetID, IdempotencyKey  string
	RequestFingerprint, Status                          string
	Result                                              json.RawMessage
	LeaseOwner, LeaseExpiresAt                          string
	FencingToken                                        int64
	ErrorCode, ExpiresAt, ActorID, CreatedAt, UpdatedAt string
}

type AuthMutationClaimRequest struct {
	Receipt            AuthMutationReceipt
	RequestFingerprint string
	LeaseOwner         string
	LeaseTTL           time.Duration
	Now                time.Time
}

type AuthMutationClaimResult struct {
	Decision idempotency.Decision
	Receipt  AuthMutationReceipt
}

type AuthMutationCompletion struct {
	ReceiptID    string
	LeaseOwner   string
	FencingToken int64
	Result       any
	ErrorCode    string
	Failed       bool
	ExpiresAt    time.Time
	Now          time.Time
}
