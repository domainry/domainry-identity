package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	identitydatascope "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/datascope"
	"github.com/domainry/domainry-orm/query"
)

type authScopedQueryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s AuthStore) IdentityUserExistsWithinDataScope(ctx context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	return s.identityUserExistsWithinDataScope(ctx, s.db, workspaceID, strings.TrimSpace(userID), scope)
}

func (s AuthStore) identityUserExistsWithinDataScope(ctx context.Context, queryer authScopedQueryRower, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	predicates := []query.Predicate{query.Equal("id", userID)}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserPredicate(scope, query.Column("id"), query.Column("org_id")))
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).
		Columns("id").Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build scoped auth user candidate: %w", err)
	}
	var persistedUserID string
	if err := queryer.QueryRowContext(ctx, statement, arguments...).Scan(&persistedUserID); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (s AuthStore) UnlockIdentityCredentialWithinDataScope(ctx context.Context, workspaceID, userID string, scope identitymodel.IdentityDataScopeFilter) (bool, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return false, false, err
	}
	userID = strings.TrimSpace(userID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()
	visible, err := s.identityUserExistsWithinDataScope(ctx, tx, workspaceID, userID, scope)
	if err != nil || !visible {
		return visible, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_credentials", workspaceID).
		Columns("user_id").Where(query.Equal("user_id", userID)).Build()
	if err != nil {
		return true, false, fmt.Errorf("build scoped credential candidate: %w", err)
	}
	var persistedUserID string
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&persistedUserID); err == sql.ErrNoRows {
		return true, false, nil
	} else if err != nil {
		return true, false, err
	}
	predicates := []query.Predicate{query.Equal("user_id", userID)}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_credentials", "user_id"), scope))
	}
	statement, arguments, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_credentials", workspaceID).
		Set("failed_login_count", 0).Set("locked_until", nil).Set("updated_at", identitypersistence.NowString()).
		Where(query.And(predicates...)).Build()
	if err != nil {
		return true, false, fmt.Errorf("build scoped credential unlock: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return true, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return true, false, err
	}
	if changed != 1 {
		return true, false, nil
	}
	if err := tx.Commit(); err != nil {
		return true, false, err
	}
	return true, true, nil
}

func (s AuthStore) ResetIdentityCredentialWithinDataScope(ctx context.Context, workspaceID, userID, passwordHash, passwordUpdatedAt string, mustChangePassword bool, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	userID, passwordHash = strings.TrimSpace(userID), strings.TrimSpace(passwordHash)
	if userID == "" || passwordHash == "" {
		return false, fmt.Errorf("credential user id and password hash are required")
	}
	if strings.TrimSpace(passwordUpdatedAt) == "" {
		passwordUpdatedAt = identitypersistence.NowString()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	predicates := []query.Predicate{query.Equal("id", userID), query.Equal("status", string(identitymodel.IdentityStatusActive))}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserPredicate(scope, query.Column("id"), query.Column("org_id")))
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).
		Columns("id").Where(query.And(predicates...)).Build()
	if err != nil {
		return false, fmt.Errorf("build scoped password reset candidate: %w", err)
	}
	var persistedUserID string
	if err := tx.QueryRowContext(ctx, statement, arguments...).Scan(&persistedUserID); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	now := identitypersistence.NowString()
	values := []any{workspaceID, userID, passwordHash, passwordUpdatedAt, 0, nil, nil, mustChangePassword, now, now}
	projections := make([]query.Projection, len(values))
	for index := range values {
		projections[index] = query.Project(query.Value(values[index]))
	}
	source := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).
		Projections(projections...).Where(query.And(predicates...)).Limit(1)
	insert := query.NewInsertBuilder(s.store.SQLRenderer(), "_identity_credentials").
		Columns("workspace_id", "user_id", "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password", "created_at", "updated_at").
		FromSelect(source)
	s.store.ApplyUpsert(insert, []string{"workspace_id", "user_id"}, "password_hash", "password_updated_at", "failed_login_count", "locked_until", "must_change_password", "updated_at")
	statement, arguments, err = insert.Build()
	if err != nil {
		return false, fmt.Errorf("build scoped password reset: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if changed != 1 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s AuthStore) RevokeIdentityMFAFactorWithinDataScope(ctx context.Context, workspaceID, userID, factorID string, scope identitymodel.IdentityDataScopeFilter) (bool, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return false, false, err
	}
	userID, factorID = strings.TrimSpace(userID), strings.TrimSpace(factorID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()
	visible, err := s.identityUserExistsWithinDataScope(ctx, tx, workspaceID, userID, scope)
	if err != nil || !visible {
		return visible, false, err
	}
	predicates := []query.Predicate{query.Equal("user_id", userID), query.Equal("id", factorID)}
	if !scope.Unrestricted {
		predicates = append(predicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_mfa_factors", "user_id"), scope))
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", workspaceID).
		Set("status", "disabled").Set("updated_at", identitypersistence.NowString()).
		Where(query.And(predicates...)).Build()
	if err != nil {
		return true, false, fmt.Errorf("build scoped identity MFA factor revoke: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return true, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return true, false, err
	}
	if changed != 1 {
		return true, false, nil
	}
	if err := tx.Commit(); err != nil {
		return true, false, err
	}
	return true, true, nil
}

func (s AuthStore) RevokeAuthRefreshTokensForUserWithinDataScope(ctx context.Context, workspaceID, userID, revokedAt string, scope identitymodel.IdentityDataScopeFilter) (int, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return 0, false, err
	}
	userID = strings.TrimSpace(userID)
	if revokedAt == "" {
		revokedAt = identitypersistence.NowString()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	visible, err := s.identityUserExistsWithinDataScope(ctx, tx, workspaceID, userID, scope)
	if err != nil || !visible {
		return 0, visible, err
	}
	predicate := query.And(query.Equal("user_id", userID), query.IsNull("revoked_at"))
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		Columns("session_id", "expires_at").Where(predicate).Build()
	if err != nil {
		return 0, true, fmt.Errorf("build scoped active auth sessions query: %w", err)
	}
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return 0, true, err
	}
	now, parseErr := time.Parse(time.RFC3339Nano, revokedAt)
	if parseErr != nil {
		rows.Close()
		return 0, true, fmt.Errorf("parse auth session revocation time: %w", parseErr)
	}
	active := map[string]struct{}{}
	for rows.Next() {
		var sessionID, expiresAt string
		if err := rows.Scan(&sessionID, &expiresAt); err != nil {
			rows.Close()
			return 0, true, err
		}
		expires, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			rows.Close()
			return 0, true, fmt.Errorf("parse auth session expiry: %w", err)
		}
		if expires.After(now) {
			active[sessionID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, true, err
	}
	if err := rows.Close(); err != nil {
		return 0, true, err
	}
	writePredicates := []query.Predicate{query.Equal("user_id", userID), query.IsNull("revoked_at")}
	if !scope.Unrestricted {
		writePredicates = append(writePredicates, identitydatascope.UserExists(workspaceID, query.TableColumn("_identity_auth_refresh_tokens", "user_id"), scope))
	}
	statement, arguments, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		Set("revoked_at", revokedAt).Set("last_used_at", revokedAt).Set("updated_at", revokedAt).
		Where(query.And(writePredicates...)).Build()
	if err != nil {
		return 0, true, fmt.Errorf("build scoped auth sessions revoke: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return 0, true, err
	}
	if err := tx.Commit(); err != nil {
		return 0, true, err
	}
	return len(active), true, nil
}
