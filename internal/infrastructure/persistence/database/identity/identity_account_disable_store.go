package identity

import (
	"context"
	"fmt"
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
	result, err := tx.ExecContext(ctx, "UPDATE "+s.tableIdentifier("identity_users")+" SET "+s.identifier("status")+" = 'disabled', "+s.identifier("version")+" = "+s.identifier("version")+" + 1, "+s.identifier("updated_at")+" = "+s.placeholder(1)+
		" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(2)+" AND "+s.identifier("id")+" = "+s.placeholder(3), nowString(), workspaceID, userID)
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
	revoked, err := tx.ExecContext(ctx, "UPDATE "+s.tableIdentifier("auth_refresh_tokens")+" SET "+s.identifier("revoked_at")+" = "+s.placeholder(1)+", "+s.identifier("updated_at")+" = "+s.placeholder(2)+
		" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(3)+" AND "+s.identifier("user_id")+" = "+s.placeholder(4)+" AND "+s.identifier("revoked_at")+" IS NULL", now, now, workspaceID, userID)
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
