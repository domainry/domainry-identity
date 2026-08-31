package account

import (
	"context"
	"database/sql"
	"fmt"

	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) Store { return Store{backend: backend, now: now} }

func (s Store) Disable(ctx context.Context, workspaceID, userID string) (int, error) {
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).
		Set("status", "disabled").
		SetExpression("version", query.Add(query.Column("version"), query.Value(1))).
		Set("updated_at", s.now()).
		Where(query.Equal("id", userID)).
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
	now := s.now()
	statement, arguments, err = query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		Set("revoked_at", now).
		Set("updated_at", now).
		Where(query.And(query.Equal("user_id", userID), query.IsNull("revoked_at"))).
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
