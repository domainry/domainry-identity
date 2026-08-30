package auditmodule

import (
	"context"
	"database/sql"
	"fmt"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	sdkcontract "github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
)

// Store adapts Identity transaction and system-scope semantics to the reusable
// Audit application store contract. Audit persistence remains module-owned.
type AuditStore struct{ binding auditsdk.Binding }

func NewAuditStore(binding auditsdk.Binding) *AuditStore { return &AuditStore{binding: binding} }

func (r *AuditStore) InsertAuditEvent(ctx context.Context, workspaceID string, event auditmodel.AuditEvent) error {
	if r == nil || r.binding == nil {
		return fmt.Errorf("audit.binding_unavailable")
	}
	if event.WorkspaceID != workspaceID {
		return fmt.Errorf("audit event workspace %q does not match repository workspace %q", event.WorkspaceID, workspaceID)
	}
	if tx := transaction.ExecutorFromContext(ctx); tx != nil {
		return r.binding.PreparedAppender().AppendPreparedWithin(ctx, transactionAdapter{tx}, event)
	}
	return r.binding.PreparedAppender().AppendPrepared(ctx, event)
}

func (r *AuditStore) ListAuditEvents(ctx context.Context, workspaceID string, query auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	if r == nil || r.binding == nil {
		return nil, fmt.Errorf("audit.binding_unavailable")
	}
	return r.binding.Reader().List(ctx, workspaceID, query)
}

func (r *AuditStore) ListAuditEventsForSystem(ctx context.Context, scope identitymodel.SystemScope, query auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	if _, err := identitymodel.NewSystemQueryScope(scope); err != nil {
		return nil, err
	}
	if r == nil || r.binding == nil {
		return nil, fmt.Errorf("audit.binding_unavailable")
	}
	return r.binding.Reader().ListSystem(ctx, query)
}

func (r *AuditStore) ListAuditOptions(ctx context.Context, workspaceID string, query auditmodel.AuditOptionQuery) ([]auditmodel.AuditOption, error) {
	if r == nil || r.binding == nil {
		return nil, fmt.Errorf("audit.binding_unavailable")
	}
	return r.binding.Reader().Options(ctx, workspaceID, query)
}

type transactionAdapter struct{ executor transaction.Executor }

func NewTransaction(executor transaction.Executor) sdkcontract.Transaction {
	return transactionAdapter{executor: executor}
}

func (a transactionAdapter) ExecContext(ctx context.Context, q string, args ...any) (sdkcontract.Result, error) {
	r, err := a.executor.ExecContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return sqlResult{r}, nil
}
func (a transactionAdapter) QueryRowContext(ctx context.Context, q string, args ...any) sdkcontract.Row {
	return a.executor.QueryRowContext(ctx, q, args...)
}

type sqlResult struct{ sql.Result }

var _ auditrepository.AuditRepository = (*AuditStore)(nil)
