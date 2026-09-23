package authoring

import (
	"encoding/json"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
)

// Receipt is the durable execution envelope for an Identity administration
// mutation. The business mutation stays in its owning Identity application;
// this value only records concurrency and replay facts.
type Receipt struct {
	ID                 string
	WorkspaceID        string
	UseCase            string
	ResourceType       string
	TargetID           string
	ActorID            string
	IdempotencyKey     string
	RequestFingerprint string
	Status             idempotency.Status
	Result             json.RawMessage
	LeaseOwner         string
	LeaseExpiresAt     time.Time
	FencingToken       int64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Claim struct {
	Decision idempotency.Decision
	Receipt  Receipt
}

type Completion struct {
	ReceiptID    string
	WorkspaceID  string
	LeaseOwner   string
	FencingToken int64
	Status       idempotency.Status
	Result       json.RawMessage
	CompletedAt  time.Time
}

type UpsertRequest struct {
	CapabilityKey        string
	ResourceID           string
	BuilderTaskID        string
	IdempotencyKey       string
	ExpectedResourceHash string
	Payload              any
}

type CommandRequest struct {
	UseCase        string
	ResourceType   string
	ResourceID     string
	IdempotencyKey string
	Payload        any
}

type ExecutionResult struct {
	Value        any
	OperationID  string
	ResourceHash string
	Replayed     bool
}

type CurrentResource func() (value any, found bool, err error)
type Authorize func() error
type Execute func() (any, error)
