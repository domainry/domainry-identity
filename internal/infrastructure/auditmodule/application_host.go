package auditmodule

import (
	"context"
	"crypto/sha256"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditmodulehost "github.com/domainry/domainry-audit-sdk/modulehost"
	"github.com/domainry/domainry-foundation/apperror"
)

// ApplicationHost lets the standalone Identity process mount the Audit-owned
// governance Surface. Identity has no business-record authorization boundary,
// so record-targeted Audit product use cases fail closed here.
type ApplicationHost struct{ exportKey [sha256.Size]byte }

func NewApplicationHost(secret string) ApplicationHost {
	return ApplicationHost{exportKey: sha256.Sum256([]byte(strings.TrimSpace(secret) + "/domainry-audit-export"))}
}

func (ApplicationHost) ResolveAuditSurfacePrincipal(_ context.Context, request auditmodulehost.AuditSurfacePrincipalRequest) (auditmodulehost.AuditSurfacePrincipal, error) {
	return auditmodulehost.AuditSurfacePrincipal{
		Identity: request.Identity, BusinessProfileKey: request.BusinessProfileKey, BusinessProfileID: request.BusinessProfileID,
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, AuthorizationRevision: request.Identity.AuthorizationRevision,
	}, nil
}

func (ApplicationHost) AuthorizeAuditRecord(context.Context, auditmodulehost.AuditSurfacePrincipal, string, string) error {
	return apperror.New(apperror.KindForbidden, "backend.audit.data_scope_unavailable", nil, nil)
}

func (ApplicationHost) ProjectAuditEvents(_ context.Context, _ auditmodulehost.AuditSurfacePrincipal, events []contract.Event) ([]contract.Event, error) {
	return append([]contract.Event(nil), events...), nil
}

func (host ApplicationHost) AuditExportTokenKey() []byte {
	return append([]byte(nil), host.exportKey[:]...)
}

var _ auditmodulehost.AuditApplicationHost = ApplicationHost{}
