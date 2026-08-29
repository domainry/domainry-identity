package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"

	"github.com/domainry/domainry-foundation/idempotency"
	"github.com/domainry/domainry-foundation/secrets"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

// AuthStore is the credential/session/external-account
// view of SQLIdentityStore. Identity governance remains a separate aggregate.
type AuthStore struct {
	store        *identitypersistence.SQLIdentityStore
	db           *sql.DB
	metrics      idempotency.MetricsCollector
	secrets      secrets.Cipher
	loginSecrets secrets.Cipher
	codeSecrets  secrets.Cipher
}

var authRefreshTokenColumns = []string{"id", "user_id", "session_id", "audience", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at"}

var _ authrepository.AuthRepository = AuthStore{}
var _ authrepository.AuthMFARepository = AuthStore{}
var _ authrepository.AuthUserDirectorySecurityRepository = AuthStore{}
var _ authrepository.AuthRefreshRotationRepository = AuthStore{}
var _ authrepository.AuthLoginAttemptRepository = AuthStore{}
var _ authrepository.AuthProviderCredentialRepository = AuthStore{}
var _ authrepository.AuthLoginTransactionRepository = AuthStore{}
var _ authrepository.AuthOTPTransactionRepository = AuthStore{}
var _ authrepository.AuthAuthorizationCodeRepository = AuthStore{}
var _ authrepository.AuthApplicationRepository = AuthStore{}
var _ authrepository.AuthAssertionReplayRepository = AuthStore{}

func NewAuthStore(store *identitypersistence.SQLIdentityStore, metrics ...idempotency.MetricsCollector) AuthStore {
	result := AuthStore{store: store, db: store.DB()}
	if len(metrics) > 0 {
		result.metrics = metrics[0]
	}
	return result
}

func NewAuthStoreWithKeyProvider(store *identitypersistence.SQLIdentityStore, keys secrets.KeyProvider, metrics ...idempotency.MetricsCollector) AuthStore {
	result := NewAuthStore(store, metrics...)
	result.secrets = secrets.Cipher{Keys: keys, Purpose: "identity.auth-provider-credential"}
	result.loginSecrets = secrets.Cipher{Keys: keys, Purpose: "identity.auth-login-transaction"}
	result.codeSecrets = secrets.Cipher{Keys: keys, Purpose: "identity.auth-authorization-code"}
	return result
}

func authWorkspaceID(value string) (string, error) {
	workspace, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return workspace.String(), nil
}

func authRefreshTokenSelect(s AuthStore, workspaceID string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).Columns(authRefreshTokenColumns...)
}

func authRefreshTokenInsert(s AuthStore, workspaceID string, token identitymodel.AuthRefreshToken, updatedAt string) *ormbuilder.InsertBuilder {
	return ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).
		Columns("id", "user_id", "session_id", "audience", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at", "updated_at").
		Values(token.ID, token.UserID, token.SessionID, token.Audience, token.TokenHash, token.ExpiresAt, database.NullableText(token.RevokedAt), database.NullableText(token.ReplacedByID), database.NullableText(token.LastUsedAt), token.CreatedAt, updatedAt)
}

func (s AuthStore) ListUserDirectorySecurityFacts(ctx context.Context, workspaceID string, userIDs []string) ([]authmodel.UserDirectorySecurityFact, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil || len(userIDs) == 0 {
		return []authmodel.UserDirectorySecurityFact{}, err
	}
	userIDs = normalizedAuthUserIDs(userIDs)
	ranges, err := (ormbuilder.ParameterBatch{MaxParameters: s.store.MaxParameters(), FixedParameters: 9, ParametersPerItem: 1, MaxItems: 500}).Ranges(len(userIDs))
	if err != nil {
		return nil, fmt.Errorf("build auth directory security batches: %w", err)
	}
	facts := make([]authmodel.UserDirectorySecurityFact, 0, len(userIDs))
	for _, batch := range ranges {
		rows, err := s.queryUserDirectorySecurityFacts(ctx, workspaceID, userIDs[batch.Start:batch.End])
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var fact authmodel.UserDirectorySecurityFact
			if err := rows.Scan(&fact.UserID, &fact.LockedUntil, &fact.LastLoginAt, &fact.ActiveSessions, &fact.MFAEnabled); err != nil {
				rows.Close()
				return nil, err
			}
			facts = append(facts, fact)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return facts, nil
}

func (s AuthStore) queryUserDirectorySecurityFacts(ctx context.Context, workspaceID string, userIDs []string) (*sql.Rows, error) {
	outerUserID := ormbuilder.QualifiedColumn("u", "id")
	credentialPredicate := ormbuilder.And(ormbuilder.Equal("workspace_id", workspaceID), ormbuilder.EqualExpressions(ormbuilder.Column("user_id"), outerUserID))
	refreshPredicate := ormbuilder.And(ormbuilder.Equal("workspace_id", workspaceID), ormbuilder.EqualExpressions(ormbuilder.Column("user_id"), outerUserID), ormbuilder.IsNull("revoked_at"), ormbuilder.GreaterThan("expires_at", identitypersistence.NowString()))
	mfaPredicate := ormbuilder.And(ormbuilder.Equal("workspace_id", workspaceID), ormbuilder.EqualExpressions(ormbuilder.Column("user_id"), outerUserID), ormbuilder.Equal("status", "active"), ormbuilder.NotEqualExpressions(ormbuilder.Coalesce(ormbuilder.Column("verified_at"), ormbuilder.Value("")), ormbuilder.Value("")))
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_users", workspaceID).Alias("u").
		Projections(
			ormbuilder.Project(outerUserID),
			ormbuilder.Project(ormbuilder.Coalesce(ormbuilder.ScalarSubquery("identity_credentials", ormbuilder.Column("locked_until"), credentialPredicate), ormbuilder.Value(""))),
			ormbuilder.Project(ormbuilder.Coalesce(ormbuilder.ScalarSubquery("identity_credentials", ormbuilder.Column("last_login_at"), credentialPredicate), ormbuilder.Value(""))),
			ormbuilder.Project(ormbuilder.ScalarSubquery("auth_refresh_tokens", ormbuilder.CountAll(), refreshPredicate)),
			ormbuilder.Project(ormbuilder.CaseWhen(ormbuilder.Exists("identity_mfa_factors", mfaPredicate), 1).Else(0)),
		).
		Where(ormbuilder.In("id", authStringValues(userIDs)...)).Build()
	if err != nil {
		return nil, fmt.Errorf("build auth directory security query: %w", err)
	}
	return s.db.QueryContext(ctx, statement, arguments...)
}

func normalizedAuthUserIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func authStringValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func (s AuthStore) GetIdentityCredential(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityCredential, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityCredential{}, false, err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_credentials", workspaceID).
		Columns("user_id", "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password").
		Where(ormbuilder.Equal("user_id", userID)).Build()
	if err != nil {
		return identitymodel.IdentityCredential{}, false, fmt.Errorf("build identity credential query: %w", err)
	}
	row := s.db.QueryRowContext(ctx, statement, arguments...)
	var credential identitymodel.IdentityCredential
	var lockedUntil, lastLoginAt sql.NullString
	if err := row.Scan(&credential.UserID, &credential.PasswordHash, &credential.PasswordUpdatedAt, &credential.FailedLoginCount, &lockedUntil, &lastLoginAt, &credential.MustChangePassword); err != nil {
		if err == sql.ErrNoRows {
			return identitymodel.IdentityCredential{}, false, nil
		}
		return identitymodel.IdentityCredential{}, false, err
	}
	credential.LockedUntil, credential.LastLoginAt = identitypersistence.ValueFromNull(lockedUntil), identitypersistence.ValueFromNull(lastLoginAt)
	return credential, true, nil
}

func (s AuthStore) UpsertIdentityCredential(ctx context.Context, workspaceID string, credential identitymodel.IdentityCredential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if credential.UserID == "" || credential.PasswordHash == "" {
		return fmt.Errorf("credential user id and password hash are required")
	}
	now := identitypersistence.NowString()
	if credential.PasswordUpdatedAt == "" {
		credential.PasswordUpdatedAt = now
	}
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "identity_credentials", workspaceID).
		Columns("user_id", "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password", "created_at", "updated_at").
		Values(credential.UserID, credential.PasswordHash, credential.PasswordUpdatedAt, credential.FailedLoginCount, database.NullableText(credential.LockedUntil), database.NullableText(credential.LastLoginAt), credential.MustChangePassword, now, now)
	s.store.ApplyUpsert(insert, []string{"workspace_id", "user_id"}, "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity credential upsert: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

func (s AuthStore) RecordIdentityLoginSuccess(ctx context.Context, workspaceID, userID, at string) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if at == "" {
		at = identitypersistence.NowString()
	}
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "identity_credentials", workspaceID).
		Set("failed_login_count", 0).Set("locked_until", nil).Set("last_login_at", at).Set("updated_at", at).Where(ormbuilder.Equal("user_id", userID)).Build()
	if err != nil {
		return fmt.Errorf("build identity login success update: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

// RecordIdentityLoginFailure increments the credential counter inside the
// database so concurrent bad-password attempts cannot lose updates. The lock
// timestamp is installed by the same statement that crosses the threshold.
func (s AuthStore) RecordIdentityLoginFailure(ctx context.Context, workspaceID, userID string, maxFailures int, lockedUntil, at string) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("credential user id is required")
	}
	if at == "" {
		at = identitypersistence.NowString()
	}
	update := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "identity_credentials", workspaceID).
		SetExpression("failed_login_count", ormbuilder.Add(ormbuilder.Column("failed_login_count"), ormbuilder.Value(1)))
	if maxFailures > 0 {
		if strings.TrimSpace(lockedUntil) == "" {
			return fmt.Errorf("credential lock timestamp is required")
		}
		update.SetExpression("locked_until", ormbuilder.CaseWhen(
			ormbuilder.GreaterThanOrEqualExpressions(ormbuilder.Add(ormbuilder.Column("failed_login_count"), ormbuilder.Value(1)), ormbuilder.Value(maxFailures)),
			lockedUntil,
		).Else(ormbuilder.Column("locked_until")))
	}
	statement, arguments, err := update.Set("updated_at", at).Where(ormbuilder.Equal("user_id", userID)).Build()
	if err != nil {
		return fmt.Errorf("build identity login failure update: %w", err)
	}
	result, err := s.db.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("credential login failure update affected %d rows", changed)
	}
	return nil
}

func (s AuthStore) CreateAuthRefreshToken(ctx context.Context, workspaceID string, token identitymodel.AuthRefreshToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if token.ID == "" || token.UserID == "" || token.SessionID == "" || token.TokenHash == "" || token.ExpiresAt == "" {
		return fmt.Errorf("refresh token id, user id, session id, hash, and expiry are required")
	}
	now := identitypersistence.NowString()
	if token.CreatedAt == "" {
		token.CreatedAt = now
	}
	statement, arguments, err := authRefreshTokenInsert(s, workspaceID, token, now).Build()
	if err != nil {
		return fmt.Errorf("build auth refresh token insert: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

func (s AuthStore) GetAuthRefreshTokenByHash(ctx context.Context, workspaceID, tokenHash string) (identitymodel.AuthRefreshToken, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.AuthRefreshToken{}, false, err
	}
	statement, arguments, err := authRefreshTokenSelect(s, workspaceID).Where(ormbuilder.Equal("token_hash", tokenHash)).Build()
	if err != nil {
		return identitymodel.AuthRefreshToken{}, false, fmt.Errorf("build auth refresh token query: %w", err)
	}
	row := s.db.QueryRowContext(ctx, statement, arguments...)
	token, err := identitypersistence.ScanAuthRefreshToken(row)
	if err == sql.ErrNoRows {
		return identitymodel.AuthRefreshToken{}, false, nil
	}
	return token, err == nil, err
}

func (s AuthStore) RevokeAuthRefreshToken(ctx context.Context, workspaceID, tokenID, revokedAt, replacedByID string) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if revokedAt == "" {
		revokedAt = identitypersistence.NowString()
	}
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).
		Set("revoked_at", revokedAt).Set("replaced_by_id", database.NullableText(replacedByID)).Set("last_used_at", revokedAt).Set("updated_at", revokedAt).
		Where(ormbuilder.Equal("id", tokenID)).Build()
	if err != nil {
		return fmt.Errorf("build auth refresh token revoke: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

func (s AuthStore) RotateAuthRefreshToken(ctx context.Context, workspaceID, tokenID, revokedAt string, replacement identitymodel.AuthRefreshToken) (bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	if tokenID == "" || replacement.ID == "" || replacement.UserID == "" || replacement.SessionID == "" || replacement.TokenHash == "" || replacement.ExpiresAt == "" {
		return false, fmt.Errorf("old and replacement refresh token identities are required")
	}
	if revokedAt == "" {
		revokedAt = identitypersistence.NowString()
	}
	if replacement.CreatedAt == "" {
		replacement.CreatedAt = revokedAt
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).
		Set("revoked_at", revokedAt).Set("replaced_by_id", replacement.ID).Set("last_used_at", revokedAt).Set("updated_at", revokedAt).
		Where(ormbuilder.And(ormbuilder.Equal("id", tokenID), ormbuilder.IsNull("revoked_at"))).Build()
	if err != nil {
		return false, fmt.Errorf("build auth refresh token rotation claim: %w", err)
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
	statement, arguments, err = authRefreshTokenInsert(s, workspaceID, replacement, revokedAt).Build()
	if err != nil {
		return false, fmt.Errorf("build replacement auth refresh token insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s AuthStore) ListAuthRefreshTokensForUser(ctx context.Context, workspaceID, userID string) ([]identitymodel.AuthRefreshToken, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := authRefreshTokenSelect(s, workspaceID).Where(ormbuilder.Equal("user_id", userID)).OrderBy(ormbuilder.Descending("created_at")).Build()
	if err != nil {
		return nil, fmt.Errorf("build auth refresh tokens query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.AuthRefreshToken{}
	for rows.Next() {
		token, err := identitypersistence.ScanAuthRefreshToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, token)
	}
	return out, rows.Err()
}

func (s AuthStore) RevokeAuthRefreshTokensForUser(ctx context.Context, workspaceID, userID, revokedAt string) (int, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return 0, err
	}
	if revokedAt == "" {
		revokedAt = identitypersistence.NowString()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	predicate := ormbuilder.And(ormbuilder.Equal("user_id", userID), ormbuilder.IsNull("revoked_at"))
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).
		Columns("session_id", "expires_at").Where(predicate).Build()
	if err != nil {
		return 0, fmt.Errorf("build active auth sessions query: %w", err)
	}
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return 0, err
	}
	now, parseErr := time.Parse(time.RFC3339Nano, revokedAt)
	if parseErr != nil {
		rows.Close()
		return 0, fmt.Errorf("parse auth session revocation time: %w", parseErr)
	}
	active := map[string]struct{}{}
	for rows.Next() {
		var sessionID, expiresAt string
		if err := rows.Scan(&sessionID, &expiresAt); err != nil {
			rows.Close()
			return 0, err
		}
		expires, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("parse auth session expiry: %w", err)
		}
		if expires.After(now) {
			active[sessionID] = struct{}{}
		}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	statement, arguments, err = ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).
		Set("revoked_at", revokedAt).Set("last_used_at", revokedAt).Set("updated_at", revokedAt).Where(predicate).Build()
	if err != nil {
		return 0, fmt.Errorf("build auth sessions revoke: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(active), nil
}

func (s AuthStore) AuthSessionState(ctx context.Context, workspaceID, userID, sessionID string, now time.Time) (string, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authrepository.AuthSessionStateMissing, err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).
		Columns("expires_at", "revoked_at").Where(ormbuilder.And(ormbuilder.Equal("user_id", userID), ormbuilder.Equal("session_id", sessionID))).Build()
	if err != nil {
		return authrepository.AuthSessionStateMissing, fmt.Errorf("build auth session state query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return authrepository.AuthSessionStateMissing, err
	}
	defer rows.Close()
	found, revoked := false, false
	for rows.Next() {
		found = true
		var expiresAt string
		var revokedAt sql.NullString
		if err := rows.Scan(&expiresAt, &revokedAt); err != nil {
			return authrepository.AuthSessionStateMissing, err
		}
		if revokedAt.Valid && strings.TrimSpace(revokedAt.String) != "" {
			revoked = true
			continue
		}
		expires, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			return authrepository.AuthSessionStateExpired, fmt.Errorf("parse auth session expiry: %w", err)
		}
		if expires.After(now) {
			return authrepository.AuthSessionStateActive, nil
		}
	}
	if err := rows.Err(); err != nil {
		return authrepository.AuthSessionStateMissing, err
	}
	if revoked {
		return authrepository.AuthSessionStateRevoked, nil
	}
	if found {
		return authrepository.AuthSessionStateExpired, nil
	}
	return authrepository.AuthSessionStateMissing, nil
}

func (s AuthStore) RevokeOtherAuthSessions(ctx context.Context, workspaceID, userID, currentSessionID, revokedAt string) (int, error) {
	return s.revokeLogicalSessions(ctx, workspaceID, userID, currentSessionID, true, revokedAt)
}

func (s AuthStore) RevokeAuthSession(ctx context.Context, workspaceID, userID, sessionID, revokedAt string) (int, error) {
	return s.revokeLogicalSessions(ctx, workspaceID, userID, sessionID, false, revokedAt)
}

func (s AuthStore) revokeLogicalSessions(ctx context.Context, workspaceID, userID, sessionID string, exclude bool, revokedAt string) (int, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(sessionID) == "" {
		return 0, fmt.Errorf("auth session user and session id are required")
	}
	if revokedAt == "" {
		revokedAt = identitypersistence.NowString()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var sessionPredicate ormbuilder.Predicate = ormbuilder.Equal("session_id", sessionID)
	if exclude {
		sessionPredicate = ormbuilder.NotEqual("session_id", sessionID)
	}
	predicate := ormbuilder.And(ormbuilder.Equal("user_id", userID), sessionPredicate, ormbuilder.IsNull("revoked_at"))
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).
		Columns("session_id", "expires_at").Where(predicate).Build()
	if err != nil {
		return 0, fmt.Errorf("build logical auth sessions query: %w", err)
	}
	rows, err := tx.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return 0, err
	}
	active := map[string]struct{}{}
	now, parseErr := time.Parse(time.RFC3339Nano, revokedAt)
	if parseErr != nil {
		rows.Close()
		return 0, fmt.Errorf("parse auth session revocation time: %w", parseErr)
	}
	for rows.Next() {
		var candidate, expiresAt string
		if err := rows.Scan(&candidate, &expiresAt); err != nil {
			rows.Close()
			return 0, err
		}
		expires, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("parse auth session expiry: %w", err)
		}
		if expires.After(now) {
			active[candidate] = struct{}{}
		}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	statement, arguments, err = ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "auth_refresh_tokens", workspaceID).
		Set("revoked_at", revokedAt).Set("last_used_at", revokedAt).Set("updated_at", revokedAt).Where(predicate).Build()
	if err != nil {
		return 0, fmt.Errorf("build logical auth sessions revoke: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(active), nil
}

func (s AuthStore) ListIdentityExternalAccounts(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityExternalAccount, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_external_accounts", workspaceID).
		Columns("id", "user_id", "provider", "provider_subject", "email", "phone", "display_name", "avatar_url", "metadata", "linked_at")
	if strings.TrimSpace(userID) != "" {
		builder.Where(ormbuilder.Equal("user_id", userID))
	}
	statement, arguments, err := builder.OrderBy(ormbuilder.Ascending("provider"), ormbuilder.Ascending("provider_subject")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity external accounts query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityExternalAccount{}
	for rows.Next() {
		var account identitymodel.IdentityExternalAccount
		var email, phone, displayName, avatarURL, metadata sql.NullString
		if err := rows.Scan(&account.ID, &account.UserID, &account.Provider, &account.ProviderSubject, &email, &phone, &displayName, &avatarURL, &metadata, &account.LinkedAt); err != nil {
			return nil, err
		}
		account.Email, account.Phone = identitypersistence.ValueFromNull(email), identitypersistence.ValueFromNull(phone)
		account.DisplayName, account.AvatarURL, account.Metadata = identitypersistence.ValueFromNull(displayName), identitypersistence.ValueFromNull(avatarURL), identitypersistence.ValueFromNull(metadata)
		out = append(out, account)
	}
	return out, rows.Err()
}

func (s AuthStore) UpsertIdentityExternalAccount(ctx context.Context, workspaceID string, account identitymodel.IdentityExternalAccount) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if account.ID == "" || account.UserID == "" || account.Provider == "" || account.ProviderSubject == "" {
		return fmt.Errorf("external account id, user id, provider, and subject are required")
	}
	now := identitypersistence.NowString()
	if account.LinkedAt == "" {
		account.LinkedAt = now
	}
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "identity_external_accounts", workspaceID).
		Columns("id", "user_id", "provider", "provider_subject", "email", "phone", "display_name", "avatar_url", "metadata", "linked_at", "created_at", "updated_at").
		Values(account.ID, account.UserID, account.Provider, account.ProviderSubject, database.NullableText(account.Email), database.NullableText(account.Phone), database.NullableText(account.DisplayName), database.NullableText(account.AvatarURL), database.NullableText(account.Metadata), account.LinkedAt, now, now)
	s.store.ApplyUpsert(insert, []string{"workspace_id", "id"}, "user_id", "provider", "provider_subject", "email", "phone", "display_name", "avatar_url", "metadata", "linked_at", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity external account upsert: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

// ListIdentityMFAFactors returns only factor metadata. Cryptographic enrollment
// material is owned by the configured authentication provider and is never
// persisted in the Runtime identity database.
func (s AuthStore) ListIdentityMFAFactors(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityMFAFactor, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("MFA factor user id is required")
	}
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_mfa_factors", workspaceID).
		Columns("id", "user_id", "factor_type", "label", "provider", "provider_ref", "status", "verified_at", "last_used_at", "created_at", "updated_at").
		Where(ormbuilder.Equal("user_id", userID)).OrderBy(ormbuilder.Ascending("created_at"), ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity MFA factors query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	factors := []identitymodel.IdentityMFAFactor{}
	for rows.Next() {
		var factor identitymodel.IdentityMFAFactor
		var label, provider, providerRef, verifiedAt, lastUsedAt sql.NullString
		if err := rows.Scan(&factor.ID, &factor.UserID, &factor.Type, &label, &provider, &providerRef, &factor.Status, &verifiedAt, &lastUsedAt, &factor.CreatedAt, &factor.UpdatedAt); err != nil {
			return nil, err
		}
		factor.Label = identitypersistence.ValueFromNull(label)
		factor.Provider = identitypersistence.ValueFromNull(provider)
		factor.ProviderRef = identitypersistence.ValueFromNull(providerRef)
		factor.VerifiedAt = identitypersistence.ValueFromNull(verifiedAt)
		factor.LastUsedAt = identitypersistence.ValueFromNull(lastUsedAt)
		factors = append(factors, factor)
	}
	return factors, rows.Err()
}

func (s AuthStore) UpsertIdentityMFAFactor(ctx context.Context, workspaceID string, factor identitymodel.IdentityMFAFactor) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	factor.ID, factor.UserID = strings.TrimSpace(factor.ID), strings.TrimSpace(factor.UserID)
	factor.Type, factor.Status = strings.TrimSpace(factor.Type), strings.TrimSpace(factor.Status)
	if factor.ID == "" || factor.UserID == "" || factor.Type == "" || factor.Status == "" {
		return fmt.Errorf("MFA factor id, user id, type, and status are required")
	}
	now := identitypersistence.NowString()
	if factor.CreatedAt == "" {
		factor.CreatedAt = now
	}
	factor.UpdatedAt = now
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "identity_mfa_factors", workspaceID).
		Columns("id", "user_id", "factor_type", "label", "provider", "provider_ref", "status", "verified_at", "last_used_at", "created_at", "updated_at").
		Values(factor.ID, factor.UserID, factor.Type, database.NullableText(factor.Label), database.NullableText(factor.Provider), database.NullableText(factor.ProviderRef), factor.Status, database.NullableText(factor.VerifiedAt), database.NullableText(factor.LastUsedAt), factor.CreatedAt, factor.UpdatedAt)
	s.store.ApplyUpsert(insert, []string{"workspace_id", "id"}, "user_id", "factor_type", "label", "provider", "provider_ref", "status", "verified_at", "last_used_at", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity MFA factor upsert: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

func (s AuthStore) RevokeIdentityMFAFactor(ctx context.Context, workspaceID, userID, factorID string) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	userID, factorID = strings.TrimSpace(userID), strings.TrimSpace(factorID)
	if userID == "" || factorID == "" {
		return fmt.Errorf("MFA factor user id and factor id are required")
	}
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "identity_mfa_factors", workspaceID).
		Set("status", "disabled").Set("updated_at", identitypersistence.NowString()).
		Where(ormbuilder.And(ormbuilder.Equal("user_id", userID), ormbuilder.Equal("id", factorID))).Build()
	if err != nil {
		return fmt.Errorf("build identity MFA factor revoke: %w", err)
	}
	result, err := s.db.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("MFA factor not found")
	}
	return nil
}

func (s AuthStore) RemoveIdentityExternalAccount(ctx context.Context, workspaceID, accountID string) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	statement, arguments, err := ormbuilder.NewWorkspaceDeleteBuilder(s.store.SQLRenderer(), "identity_external_accounts", workspaceID).Where(ormbuilder.Equal("id", accountID)).Build()
	if err != nil {
		return fmt.Errorf("build identity external account delete: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}
