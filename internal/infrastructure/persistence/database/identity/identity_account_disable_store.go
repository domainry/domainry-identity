package identity

import (
	"context"
	"fmt"

	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func (s *SQLIdentityStore) DisableIdentityAccount(ctx context.Context, workspaceID, userID string) (int, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "identity_users", workspaceID).
		Set("status", "disabled").
		SetExpression("version", ormbuilder.Add(ormbuilder.Column("version"), ormbuilder.Value(1))).
		Set("updated_at", nowString()).
		Where(ormbuilder.Equal("id", userID)).
		Build()
	if err != nil {
		return 0, fmt.Errorf("build identity account disable: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return 0, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if changed != 1 {
		return 0, fmt.Errorf("identity user %q not found", userID)
	}
	now := nowString()
	statement, arguments, err = ormbuilder.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "auth_refresh_tokens", workspaceID).
		Set("revoked_at", now).
		Set("updated_at", now).
		Where(ormbuilder.And(ormbuilder.Equal("user_id", userID), ormbuilder.IsNull("revoked_at"))).
		Build()
	if err != nil {
		return 0, fmt.Errorf("build identity refresh-token revocation: %w", err)
	}
	revoked, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return 0, err
	}
	revokedCount, err := revoked.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(revokedCount), nil
}
