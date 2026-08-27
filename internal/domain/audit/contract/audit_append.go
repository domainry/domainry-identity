package contract

import (
	"context"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// AuditAppendRequest describes one audit fact without exposing persistence details.
type AuditAppendRequest struct {
	// IdempotencyKey is optional. When present, the audit owner derives a stable
	// event identity and treats an exact duplicate as success while rejecting a
	// different event under the same key.
	IdempotencyKey string
	Event          string
	ObjectKey      string
	RecordID       string
	Principal      identitymodel.Principal
	Summary        string
	Before         map[string]any
	After          map[string]any
	Metadata       map[string]any
}

// AuditAppender persists mandatory audit facts and returns storage failures.
type AuditAppender interface {
	AppendAudit(context.Context, AuditAppendRequest) error
}

// AuditTelemetryAppender records explicitly best-effort operational telemetry.
// Keeping this separate from AuditAppender prevents mandatory audit failures from
// being discarded accidentally.
type AuditTelemetryAppender interface {
	AppendAuditTelemetry(context.Context, AuditAppendRequest)
}
