package contract

import (
	"context"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// AuditReader exposes stable audit read capabilities without leaking AuditRepository.
type AuditReader interface {
	ListAuditEvents(context.Context, string, auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error)
	ListAuditEventsForSystem(context.Context, identitymodel.SystemScope, auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error)
	ListAuditOptions(context.Context, string, auditmodel.AuditOptionQuery) ([]auditmodel.AuditOption, error)
}
