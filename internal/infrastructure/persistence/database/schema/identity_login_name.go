package schema

import (
	"context"
	"database/sql"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/query"
	ormschema "github.com/domainry/domainry-orm/schema"
)

// Backfill precedes the unique index. Existing conflicting accounts are never
// silently renamed or merged: migration fails with a non-identifying error.
func ensureIdentityGlobalLoginNames(ctx context.Context, s Store) error {
	const table = "_identity_users"
	columns, err := s.TableColumns(ctx, table)
	if err != nil {
		return err
	}
	if !columns["login_name_key"] {
		statement, args, err := ormschema.NewAddColumn(s.SchemaRenderer(), table, ormschema.Column("login_name_key", ormschema.TextKey(64))).Build()
		if err != nil {
			return err
		}
		if _, err = s.SchemaDB().ExecContext(ctx, statement, args...); err != nil {
			return err
		}
	}
	statement, args, err := query.NewSelectBuilder(s.SchemaRenderer(), table).Columns("workspace_id", "id", "email", "login_name_key").Build()
	if err != nil {
		return err
	}
	rows, err := s.SchemaDB().QueryContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	type loginRow struct {
		workspace, id, email string
		key                  sql.NullString
	}
	var users []loginRow
	seen := map[string]bool{}
	for rows.Next() {
		var user loginRow
		if err := rows.Scan(&user.workspace, &user.id, &user.email, &user.key); err != nil {
			_ = rows.Close()
			return err
		}
		if key, ok := identitymodel.IdentityLoginNameKey(user.email).(string); ok {
			if seen[key] {
				_ = rows.Close()
				return fmt.Errorf("identity.login_name_conflict: existing user login names must be globally unique")
			}
			seen[key] = true
		}
		users = append(users, user)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, user := range users {
		key := identitymodel.IdentityLoginNameKey(user.email)
		if key == nil && !user.key.Valid || key != nil && user.key.Valid && user.key.String == key {
			continue
		}
		statement, args, err := query.NewWorkspaceUpdateBuilder(s.SchemaRenderer(), table, user.workspace).Set("login_name_key", key).Where(query.Equal("id", user.id)).Build()
		if err != nil {
			return err
		}
		if _, err = s.SchemaDB().ExecContext(ctx, statement, args...); err != nil {
			return err
		}
	}
	return s.CreateIndexIfMissing(ctx, table, "uniq_identity_users_login_name", true, "login_name_key")
}
