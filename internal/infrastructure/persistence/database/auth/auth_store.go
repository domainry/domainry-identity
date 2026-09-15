package auth

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"github.com/domainry/domainry-orm/batch"
	"github.com/domainry/domainry-orm/query"
)

type AuthStore struct {
	store        *identitypersistence.SQLIdentityStore
	db           *sql.DB
	metrics      idempotency.MetricsCollector
	secrets      secrets.Cipher
	loginSecrets secrets.Cipher
	codeSecrets  secrets.Cipher
	totpSecrets  secrets.Cipher
}

// Ready reports whether the value-backed store has its required persistence
// dependencies. AuthStore is intentionally passed by value, so its zero value
// must be distinguished explicitly instead of being compared with nil.
func (s AuthStore) Ready() bool {
	return s.store != nil && s.db != nil
}

var authRefreshTokenColumns = []string{"id", "user_id", "session_id", "audience", "authentication_time", "authentication_methods", "assurance_level", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at"}

var _ authrepository.AuthRepository = AuthStore{}
var _ authrepository.AuthMFARepository = AuthStore{}
var _ authrepository.AuthUserProjectionSecurityRepository = AuthStore{}
var _ authrepository.AuthUserDataScopeRepository = AuthStore{}
var _ authrepository.AuthCredentialDataScopeRepository = AuthStore{}
var _ authrepository.AuthPasswordResetDataScopeRepository = AuthStore{}
var _ authrepository.AuthRefreshTokenDataScopeRepository = AuthStore{}
var _ authrepository.AuthMFADataScopeRepository = AuthStore{}
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
	result.totpSecrets = secrets.Cipher{Keys: keys, Purpose: "identity.auth-totp-factor"}
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

func authRefreshTokenSelect(s AuthStore, workspaceID string) *query.SelectBuilder {
	return query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).Columns(authRefreshTokenColumns...)
}

func authRefreshTokenInsert(s AuthStore, workspaceID string, token identitymodel.AuthRefreshToken, updatedAt string) *query.InsertBuilder {
	methods, _ := json.Marshal(token.AuthenticationMethods)
	return query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		Columns("id", "user_id", "session_id", "audience", "authentication_time", "authentication_methods", "assurance_level", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at", "updated_at").
		Values(token.ID, token.UserID, token.SessionID, token.Audience, token.AuthenticationTime, string(methods), token.AssuranceLevel, token.TokenHash, token.ExpiresAt, database.NullableText(token.RevokedAt), database.NullableText(token.ReplacedByID), database.NullableText(token.LastUsedAt), token.CreatedAt, updatedAt)
}

func (s AuthStore) ListUserProjectionSecurityFacts(ctx context.Context, workspaceID string, userIDs []string) ([]authmodel.UserProjectionSecurityFact, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil || len(userIDs) == 0 {
		return []authmodel.UserProjectionSecurityFact{}, err
	}
	userIDs = normalizedAuthUserIDs(userIDs)
	ranges, err := (batch.Parameters{Max: s.store.MaxParameters(), Fixed: 9, PerItem: 1, MaxItems: 500}).Ranges(len(userIDs))
	if err != nil {
		return nil, fmt.Errorf("build auth projection security batches: %w", err)
	}
	facts := make([]authmodel.UserProjectionSecurityFact, 0, len(userIDs))
	for _, batch := range ranges {
		rows, err := s.queryUserProjectionSecurityFacts(ctx, workspaceID, userIDs[batch.Start:batch.End])
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var fact authmodel.UserProjectionSecurityFact
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

func (s AuthStore) queryUserProjectionSecurityFacts(ctx context.Context, workspaceID string, userIDs []string) (*sql.Rows, error) {
	outerUserID := query.QualifiedColumn("u", "id")
	credentialPredicate := query.And(query.Equal("workspace_id", workspaceID), query.EqualExpressions(query.Column("user_id"), outerUserID))
	refreshPredicate := query.And(query.Equal("workspace_id", workspaceID), query.EqualExpressions(query.Column("user_id"), outerUserID), query.IsNull("revoked_at"), query.GreaterThan("expires_at", identitypersistence.NowString()))
	mfaPredicate := query.And(query.Equal("workspace_id", workspaceID), query.EqualExpressions(query.Column("user_id"), outerUserID), query.Equal("status", "active"), query.NotEqualExpressions(query.Coalesce(query.Column("verified_at"), query.Value("")), query.Value("")))
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).Alias("u").
		Projections(
			query.Project(outerUserID),
			query.Project(query.Coalesce(query.ScalarSubquery("_identity_credentials", query.Column("locked_until"), credentialPredicate), query.Value(""))),
			query.Project(query.Coalesce(query.ScalarSubquery("_identity_credentials", query.Column("last_login_at"), credentialPredicate), query.Value(""))),
			query.Project(query.ScalarSubquery("_identity_auth_refresh_tokens", query.CountAll(), refreshPredicate)),
			query.Project(query.CaseWhen(query.Exists("_identity_mfa_factors", mfaPredicate), 1).Else(0)),
		).
		Where(query.In("id", authStringValues(userIDs)...)).Build()
	if err != nil {
		return nil, fmt.Errorf("build auth projection security query: %w", err)
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
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_credentials", workspaceID).
		Columns("user_id", "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password").
		Where(query.Equal("user_id", userID)).Build()
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
	return s.UpsertIdentityCredentialWithExecutor(ctx, s.db, workspaceID, credential)
}

func (s AuthStore) UpsertIdentityCredentialWithExecutor(ctx context.Context, execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, workspaceID string, credential identitymodel.IdentityCredential) error {
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
	insert := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_credentials", workspaceID).
		Columns("user_id", "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password", "created_at", "updated_at").
		Values(credential.UserID, credential.PasswordHash, credential.PasswordUpdatedAt, credential.FailedLoginCount, database.NullableText(credential.LockedUntil), database.NullableText(credential.LastLoginAt), credential.MustChangePassword, now, now)
	s.store.ApplyUpsert(insert, []string{"workspace_id", "user_id"}, "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity credential upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
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
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_credentials", workspaceID).
		Set("failed_login_count", 0).Set("locked_until", nil).Set("last_login_at", at).Set("updated_at", at).Where(query.Equal("user_id", userID)).Build()
	if err != nil {
		return fmt.Errorf("build identity login success update: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}

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
	update := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_credentials", workspaceID).
		SetExpression("failed_login_count", query.Add(query.Column("failed_login_count"), query.Value(1)))
	if maxFailures > 0 {
		if strings.TrimSpace(lockedUntil) == "" {
			return fmt.Errorf("credential lock timestamp is required")
		}
		update.SetExpression("locked_until", query.CaseWhen(
			query.GreaterThanOrEqualExpressions(query.Add(query.Column("failed_login_count"), query.Value(1)), query.Value(maxFailures)),
			lockedUntil,
		).Else(query.Column("locked_until")))
	}
	statement, arguments, err := update.Set("updated_at", at).Where(query.Equal("user_id", userID)).Build()
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
	statement, arguments, err := authRefreshTokenSelect(s, workspaceID).Where(query.Equal("token_hash", tokenHash)).Build()
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

// GlobalRefreshTokenWorkspace resolves an opaque browser refresh credential to
// its owning Workspace before a scoped authentication request is constructed.
// Token hashes are not globally unique by schema, so ambiguous matches fail
// closed instead of selecting an arbitrary Workspace.
func (s AuthStore) GlobalRefreshTokenWorkspace(ctx context.Context, tokenHash string) (string, bool, error) {
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return "", false, nil
	}
	statement, arguments, err := query.NewSelectBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens").
		Columns("workspace_id").
		Where(query.Equal("token_hash", tokenHash)).
		OrderBy(query.Ascending("workspace_id")).
		Build()
	if err != nil {
		return "", false, fmt.Errorf("build global auth refresh workspace query: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	workspaceID := ""
	for rows.Next() {
		var candidate string
		if err := rows.Scan(&candidate); err != nil {
			return "", false, err
		}
		candidate = strings.TrimSpace(candidate)
		if workspaceID != "" && workspaceID != candidate {
			return "", false, nil
		}
		workspaceID = candidate
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	if workspaceID == "" {
		return "", false, nil
	}
	if _, err := authWorkspaceID(workspaceID); err != nil {
		return "", false, err
	}
	return workspaceID, true, nil
}

func (s AuthStore) RevokeAuthRefreshToken(ctx context.Context, workspaceID, tokenID, revokedAt, replacedByID string) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if revokedAt == "" {
		revokedAt = identitypersistence.NowString()
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		Set("revoked_at", revokedAt).Set("replaced_by_id", database.NullableText(replacedByID)).Set("last_used_at", revokedAt).Set("updated_at", revokedAt).
		Where(query.Equal("id", tokenID)).Build()
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
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		Set("revoked_at", revokedAt).Set("replaced_by_id", replacement.ID).Set("last_used_at", revokedAt).Set("updated_at", revokedAt).
		Where(query.And(query.Equal("id", tokenID), query.IsNull("revoked_at"))).Build()
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
	statement, arguments, err := authRefreshTokenSelect(s, workspaceID).Where(query.Equal("user_id", userID)).OrderBy(query.Descending("created_at")).Build()
	if err != nil {
		return nil, fmt.Errorf("build auth refresh tokens query: %w", err)
	}
	rows, err := s.store.QueryIdentityContext(ctx, statement, arguments...)
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
	predicate := query.And(query.Equal("user_id", userID), query.IsNull("revoked_at"))
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
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
	statement, arguments, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
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
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		Columns("expires_at", "revoked_at").Where(query.And(query.Equal("user_id", userID), query.Equal("session_id", sessionID))).Build()
	if err != nil {
		return authrepository.AuthSessionStateMissing, fmt.Errorf("build auth session state query: %w", err)
	}
	rows, err := s.store.QueryIdentityContext(ctx, statement, arguments...)
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
	var sessionPredicate query.Predicate = query.Equal("session_id", sessionID)
	if exclude {
		sessionPredicate = query.NotEqual("session_id", sessionID)
	}
	predicate := query.And(query.Equal("user_id", userID), sessionPredicate, query.IsNull("revoked_at"))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// Acquire the write slot before reading the candidate sessions. SQLite starts
	// deferred transactions as readers; two concurrent callers that both read
	// first cannot safely upgrade the older snapshot to a writer. The no-op
	// update serializes that transition while retaining the same predicate and
	// transaction semantics on every supported database.
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
		SetExpression("updated_at", query.Column("updated_at")).Where(predicate).Build()
	if err != nil {
		return 0, fmt.Errorf("build logical auth sessions write fence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return 0, err
	}
	statement, arguments, err = query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
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
	statement, arguments, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspaceID).
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
	builder := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_external_accounts", workspaceID).
		Columns("id", "user_id", "provider", "provider_subject", "email", "phone", "display_name", "avatar_url", "metadata", "linked_at")
	if strings.TrimSpace(userID) != "" {
		builder.Where(query.Equal("user_id", userID))
	}
	statement, arguments, err := builder.OrderBy(query.Ascending("provider"), query.Ascending("provider_subject")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity external accounts query: %w", err)
	}
	rows, err := s.store.QueryIdentityContext(ctx, statement, arguments...)
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
	insert := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_external_accounts", workspaceID).
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

func (s AuthStore) ListIdentityMFAFactors(ctx context.Context, workspaceID, userID string) ([]identitymodel.IdentityMFAFactor, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("MFA factor user id is required")
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", workspaceID).
		Columns("id", "user_id", "factor_type", "label", "provider", "provider_ref", "status", "verified_at", "last_used_at", "created_at", "updated_at").
		Where(query.Equal("user_id", userID)).OrderBy(query.Ascending("created_at"), query.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity MFA factors query: %w", err)
	}
	rows, err := s.store.QueryIdentityContext(ctx, statement, arguments...)
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
	insert := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", workspaceID).
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
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", workspaceID).
		Set("status", "disabled").Set("updated_at", identitypersistence.NowString()).
		Where(query.And(query.Equal("user_id", userID), query.Equal("id", factorID))).Build()
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
	statement, arguments, err := query.NewWorkspaceDeleteBuilder(s.store.SQLRenderer(), "_identity_external_accounts", workspaceID).Where(query.Equal("id", accountID)).Build()
	if err != nil {
		return fmt.Errorf("build identity external account delete: %w", err)
	}
	_, err = s.db.ExecContext(ctx, statement, arguments...)
	return err
}
