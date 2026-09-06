package identity

import (
	"context"

	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
)

// WithinIdentityTransaction joins a host-owned Runtime transaction when one
// is present. Otherwise Identity owns the lifecycle and commits only after all
// user, role, profile, receipt, session, and audit effects succeed.
func (s *SQLIdentityStore) WithinIdentityTransaction(ctx context.Context, operation func(context.Context) error) error {
	if operation == nil {
		return nil
	}
	if identitytransaction.ExecutorFromContext(ctx) != nil {
		return operation(ctx)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := operation(identitytransaction.WithExecutor(ctx, tx)); err != nil {
		return err
	}
	return tx.Commit()
}

var _ identityrepository.IdentityTransactionManager = (*SQLIdentityStore)(nil)
