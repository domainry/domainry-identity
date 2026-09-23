package metadata

import (
	"context"
	"database/sql"
	"strings"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	auditmoduleimpl "github.com/domainry/domainry-audit/module"
	identityauditmodule "github.com/domainry/domainry-identity/internal/infrastructure/auditmodule"
)

func (s MetadataStore) insertMetadataChangeAudit(ctx context.Context, tx *sql.Tx, event auditmodel.AuditEvent) error {
	return auditmoduleimpl.AppendPreparedWithin(ctx, s.store.BuilderRenderer(), identityauditmodule.NewTransaction(tx), event)
}

func metadataMutationValueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}
