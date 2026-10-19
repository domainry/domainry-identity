package user

import (
	"context"
	"database/sql"
	"errors"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/timevalue"
	"github.com/domainry/domainry-orm/query"
)

func (s *Store) ArchiveWithinDataScope(ctx context.Context, workspaceID, userID string, expectedVersion int64, scope identitymodel.IdentityDataScopeFilter) (int, bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return 0, false, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	predicates := []query.Predicate{query.Equal("id", userID), query.NotEqual("status", "erased")}
	if !scope.Unrestricted {
		predicates = append(predicates, userDataScopePredicate(scope))
	}
	statement, args, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Columns("status", "account_type", "version").Where(query.And(predicates...)).Build()
	if err != nil {
		return 0, false, err
	}
	var status, accountType string
	var version int64
	if err := tx.QueryRowContext(ctx, statement, args...).Scan(&status, &accountType, &version); errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	} else if err != nil {
		return 0, false, err
	}
	if accountType != string(identitymodel.IdentityAccountHuman) {
		return 0, false, apperror.New(apperror.KindBadRequest, "backend.identity.user_archive_human_required", nil, nil)
	}
	if status == string(identitymodel.IdentityStatusDeleted) {
		return 0, true, nil
	}
	if expectedVersion > 0 && expectedVersion != version {
		return 0, false, apperror.New(apperror.KindConflict, "backend.identity.user_version_conflict", nil, nil)
	}
	now := timevalue.Millis(s.now())
	predicates = append(predicates, query.Equal("version", version), query.NotEqual("status", string(identitymodel.IdentityStatusDeleted)))
	statement, args, err = query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_users", workspaceID).Set("status", string(identitymodel.IdentityStatusDeleted)).Set("version", version+1).Set("updated_at", now).Where(query.And(predicates...)).Build()
	if err != nil {
		return 0, false, err
	}
	result, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return 0, false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, false, err
	}
	if count != 1 {
		return 0, false, apperror.New(apperror.KindConflict, "backend.identity.user_version_conflict", nil, nil)
	}
	// Retain assignment history and external bindings, revoke all effective access.
	statement, args, err = query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_user_role_assignments", workspaceID).Set("status", "revoked").Set("revoked_at", now).Set("revoke_reason", "account_archived").Set("updated_at", now).Where(query.And(query.Equal("user_id", userID), query.NotEqual("status", "revoked"))).Build()
	if err != nil {
		return 0, false, err
	}
	if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
		return 0, false, err
	}
	for _, table := range []string{"_identity_credentials", "_identity_mfa_factors"} {
		statement, args, err = query.NewWorkspaceDeleteBuilder(s.backend.SQLRenderer(), table, workspaceID).Where(query.Equal("user_id", userID)).Build()
		if err != nil {
			return 0, false, err
		}
		if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
			return 0, false, err
		}
	}
	statement, args, err = query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).Set("revoked_at", now).Set("updated_at", now).Where(query.And(query.Equal("user_id", userID), query.Equal("revoked_at", int64(0)))).Build()
	if err != nil {
		return 0, false, err
	}
	result, err = tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return 0, false, err
	}
	revoked, err := result.RowsAffected()
	if err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return int(revoked), true, nil
}
