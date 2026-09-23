package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	identityauditmodule "github.com/domainry/domainry-identity/internal/infrastructure/auditmodule"
)

func (s MetadataStore) insertMetadataChangeAudit(ctx context.Context, tx *sql.Tx, event auditmodel.AuditEvent) error {
	binding := s.store.Audit()
	if binding == nil || binding.PreparedAppender() == nil {
		return fmt.Errorf("Audit module binding is unavailable")
	}
	return binding.PreparedAppender().AppendPreparedWithin(ctx, identityauditmodule.NewTransaction(tx), event)
}

func metadataMutationValueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}
