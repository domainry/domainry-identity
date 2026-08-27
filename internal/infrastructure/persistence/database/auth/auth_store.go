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

func (s AuthStore) ListUserDirectorySecurityFacts(ctx context.Context, workspaceID string, userIDs []string) ([]authmodel.UserDirectorySecurityFact, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil || len(userIDs) == 0 {
		return []authmodel.UserDirectorySecurityFact{}, err
	}
	args := []any{}
	bind := func(value any) string {
		args = append(args, value)
		return s.store.Placeholder(len(args))
	}
	refreshWorkspace := bind(workspaceID)
	nowPlaceholder := bind(identitypersistence.NowString())
	mfaWorkspace := bind(workspaceID)
	outerWorkspace := bind(workspaceID)
	in := make([]string, len(userIDs))
	for index, userID := range userIDs {
		in[index] = bind(strings.TrimSpace(userID))
	}
	query := "SELECT u." + s.store.Identifier("id") +
		", COALESCE(c." + s.store.Identifier("locked_until") + ", '')" +
		", COALESCE(c." + s.store.Identifier("last_login_at") + ", '')" +
		", (SELECT COUNT(*) FROM " + s.store.TableIdentifier("auth_refresh_tokens") + " rt WHERE rt." + s.store.Identifier("workspace_id") + " = " + refreshWorkspace +
		" AND rt." + s.store.Identifier("user_id") + " = u." + s.store.Identifier("id") + " AND rt." + s.store.Identifier("revoked_at") + " IS NULL AND rt." + s.store.Identifier("expires_at") + " > " + nowPlaceholder + ")" +
		", CASE WHEN EXISTS (SELECT 1 FROM " + s.store.TableIdentifier("identity_mfa_factors") + " mf WHERE mf." + s.store.Identifier("workspace_id") + " = " + mfaWorkspace +
		" AND mf." + s.store.Identifier("user_id") + " = u." + s.store.Identifier("id") + " AND mf." + s.store.Identifier("status") + " = 'active' AND COALESCE(mf." + s.store.Identifier("verified_at") + ", '') <> '') THEN 1 ELSE 0 END" +
		" FROM " + s.store.TableIdentifier("identity_users") + " u LEFT JOIN " + s.store.TableIdentifier("identity_credentials") + " c ON c." + s.store.Identifier("workspace_id") + " = u." + s.store.Identifier("workspace_id") +
		" AND c." + s.store.Identifier("user_id") + " = u." + s.store.Identifier("id") +
		" WHERE u." + s.store.Identifier("workspace_id") + " = " + outerWorkspace + " AND u." + s.store.Identifier("id") + " IN (" + strings.Join(in, ", ") + ")"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	facts := make([]authmodel.UserDirectorySecurityFact, 0, len(userIDs))
	for rows.Next() {
		var fact authmodel.UserDirectorySecurityFact
		if err := rows.Scan(&fact.UserID, &fact.LockedUntil, &fact.LastLoginAt, &fact.ActiveSessions, &fact.MFAEnabled); err != nil {
			return nil, err
		}
		facts = append(facts, fact)
	}
	return facts, rows.Err()
}

func (s AuthStore) GetIdentityCredential(ctx context.Context, workspaceID, userID string) (identitymodel.IdentityCredential, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityCredential{}, false, err
	}
	row := s.db.QueryRowContext(ctx, "SELECT "+s.store.IdentityColumns("user_id", "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password")+" FROM "+s.store.TableIdentifier("identity_credentials")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(2), workspaceID, userID)
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.store.TableIdentifier("identity_credentials")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(2), workspaceID, credential.UserID); err != nil {
		return err
	}
	query := "INSERT INTO " + s.store.TableIdentifier("identity_credentials") + " (" + s.store.IdentityColumns("user_id", "workspace_id", "password_hash", "password_updated_at", "failed_login_count", "locked_until", "last_login_at", "must_change_password", "created_at", "updated_at") + ") VALUES (" + s.store.Placeholders(10) + ")"
	if _, err := tx.ExecContext(ctx, query, credential.UserID, workspaceID, credential.PasswordHash, credential.PasswordUpdatedAt, credential.FailedLoginCount, database.NullableText(credential.LockedUntil), database.NullableText(credential.LastLoginAt), credential.MustChangePassword, now, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s AuthStore) RecordIdentityLoginSuccess(ctx context.Context, workspaceID, userID, at string) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if at == "" {
		at = identitypersistence.NowString()
	}
	_, err = s.db.ExecContext(ctx, "UPDATE "+s.store.TableIdentifier("identity_credentials")+" SET "+s.store.Identifier("failed_login_count")+" = 0, "+s.store.Identifier("locked_until")+" = NULL, "+s.store.Identifier("last_login_at")+" = "+s.store.Placeholder(1)+", "+s.store.Identifier("updated_at")+" = "+s.store.Placeholder(2)+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(3)+" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(4), at, at, workspaceID, userID)
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
	query := "UPDATE " + s.store.TableIdentifier("identity_credentials") + " SET " + s.store.Identifier("failed_login_count") + " = " + s.store.Identifier("failed_login_count") + " + 1"
	args := []any{}
	if maxFailures > 0 {
		if strings.TrimSpace(lockedUntil) == "" {
			return fmt.Errorf("credential lock timestamp is required")
		}
		query += ", " + s.store.Identifier("locked_until") + " = CASE WHEN " + s.store.Identifier("failed_login_count") + " + 1 >= " + s.store.Placeholder(1) + " THEN " + s.store.Placeholder(2) + " ELSE " + s.store.Identifier("locked_until") + " END"
		args = append(args, maxFailures, lockedUntil)
	}
	updatedAtPlaceholder := s.store.Placeholder(len(args) + 1)
	workspacePlaceholder := s.store.Placeholder(len(args) + 2)
	userPlaceholder := s.store.Placeholder(len(args) + 3)
	query += ", " + s.store.Identifier("updated_at") + " = " + updatedAtPlaceholder + " WHERE " + s.store.Identifier("workspace_id") + " = " + workspacePlaceholder + " AND " + s.store.Identifier("user_id") + " = " + userPlaceholder
	args = append(args, at, workspaceID, userID)
	result, err := s.db.ExecContext(ctx, query, args...)
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
	query := "INSERT INTO " + s.store.TableIdentifier("auth_refresh_tokens") + " (" + s.store.IdentityColumns("id", "workspace_id", "user_id", "session_id", "audience", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at", "updated_at") + ") VALUES (" + s.store.Placeholders(12) + ")"
	_, err = s.db.ExecContext(ctx, query, token.ID, workspaceID, token.UserID, token.SessionID, token.Audience, token.TokenHash, token.ExpiresAt, database.NullableText(token.RevokedAt), database.NullableText(token.ReplacedByID), database.NullableText(token.LastUsedAt), token.CreatedAt, now)
	return err
}

func (s AuthStore) GetAuthRefreshTokenByHash(ctx context.Context, workspaceID, tokenHash string) (identitymodel.AuthRefreshToken, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.AuthRefreshToken{}, false, err
	}
	row := s.db.QueryRowContext(ctx, "SELECT "+s.store.IdentityColumns("id", "user_id", "session_id", "audience", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at")+" FROM "+s.store.TableIdentifier("auth_refresh_tokens")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("token_hash")+" = "+s.store.Placeholder(2), workspaceID, tokenHash)
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
	_, err = s.db.ExecContext(ctx, "UPDATE "+s.store.TableIdentifier("auth_refresh_tokens")+" SET "+s.store.Identifier("revoked_at")+" = "+s.store.Placeholder(1)+", "+s.store.Identifier("replaced_by_id")+" = "+s.store.Placeholder(2)+", "+s.store.Identifier("last_used_at")+" = "+s.store.Placeholder(3)+", "+s.store.Identifier("updated_at")+" = "+s.store.Placeholder(4)+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(5)+" AND "+s.store.Identifier("id")+" = "+s.store.Placeholder(6), revokedAt, database.NullableText(replacedByID), revokedAt, revokedAt, workspaceID, tokenID)
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
	result, err := tx.ExecContext(ctx, "UPDATE "+s.store.TableIdentifier("auth_refresh_tokens")+" SET "+s.store.Identifier("revoked_at")+" = "+s.store.Placeholder(1)+", "+s.store.Identifier("replaced_by_id")+" = "+s.store.Placeholder(2)+", "+s.store.Identifier("last_used_at")+" = "+s.store.Placeholder(3)+", "+s.store.Identifier("updated_at")+" = "+s.store.Placeholder(4)+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(5)+" AND "+s.store.Identifier("id")+" = "+s.store.Placeholder(6)+" AND "+s.store.Identifier("revoked_at")+" IS NULL", revokedAt, replacement.ID, revokedAt, revokedAt, workspaceID, tokenID)
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
	query := "INSERT INTO " + s.store.TableIdentifier("auth_refresh_tokens") + " (" + s.store.IdentityColumns("id", "workspace_id", "user_id", "session_id", "audience", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at", "updated_at") + ") VALUES (" + s.store.Placeholders(12) + ")"
	if _, err := tx.ExecContext(ctx, query, replacement.ID, workspaceID, replacement.UserID, replacement.SessionID, replacement.Audience, replacement.TokenHash, replacement.ExpiresAt, database.NullableText(replacement.RevokedAt), database.NullableText(replacement.ReplacedByID), database.NullableText(replacement.LastUsedAt), replacement.CreatedAt, revokedAt); err != nil {
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
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.store.IdentityColumns("id", "user_id", "session_id", "audience", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at")+" FROM "+s.store.TableIdentifier("auth_refresh_tokens")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(2)+" ORDER BY "+s.store.Identifier("created_at")+" DESC", workspaceID, userID)
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
	rows, err := tx.QueryContext(ctx, "SELECT "+s.store.IdentityColumns("session_id", "expires_at")+" FROM "+s.store.TableIdentifier("auth_refresh_tokens")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(2)+" AND "+s.store.Identifier("revoked_at")+" IS NULL", workspaceID, userID)
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
	if _, err := tx.ExecContext(ctx, "UPDATE "+s.store.TableIdentifier("auth_refresh_tokens")+" SET "+s.store.Identifier("revoked_at")+" = "+s.store.Placeholder(1)+", "+s.store.Identifier("last_used_at")+" = "+s.store.Placeholder(2)+", "+s.store.Identifier("updated_at")+" = "+s.store.Placeholder(3)+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(4)+" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(5)+" AND "+s.store.Identifier("revoked_at")+" IS NULL", revokedAt, revokedAt, revokedAt, workspaceID, userID); err != nil {
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
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.store.IdentityColumns("expires_at", "revoked_at")+" FROM "+s.store.TableIdentifier("auth_refresh_tokens")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(2)+" AND "+s.store.Identifier("session_id")+" = "+s.store.Placeholder(3), workspaceID, userID, sessionID)
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
	comparison := " = "
	if exclude {
		comparison = " <> "
	}
	where := s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) + " AND " + s.store.Identifier("user_id") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("session_id") + comparison + s.store.Placeholder(3) + " AND " + s.store.Identifier("revoked_at") + " IS NULL"
	updateWhere := s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(4) + " AND " + s.store.Identifier("user_id") + " = " + s.store.Placeholder(5) + " AND " + s.store.Identifier("session_id") + comparison + s.store.Placeholder(6) + " AND " + s.store.Identifier("revoked_at") + " IS NULL"
	rows, err := tx.QueryContext(ctx, "SELECT "+s.store.IdentityColumns("session_id", "expires_at")+" FROM "+s.store.TableIdentifier("auth_refresh_tokens")+" WHERE "+where, workspaceID, userID, sessionID)
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
	if _, err := tx.ExecContext(ctx, "UPDATE "+s.store.TableIdentifier("auth_refresh_tokens")+" SET "+s.store.Identifier("revoked_at")+" = "+s.store.Placeholder(1)+", "+s.store.Identifier("last_used_at")+" = "+s.store.Placeholder(2)+", "+s.store.Identifier("updated_at")+" = "+s.store.Placeholder(3)+" WHERE "+updateWhere, revokedAt, revokedAt, revokedAt, workspaceID, userID, sessionID); err != nil {
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
	query := "SELECT " + s.store.IdentityColumns("id", "user_id", "provider", "provider_subject", "email", "phone", "display_name", "avatar_url", "metadata", "linked_at") + " FROM " + s.store.TableIdentifier("identity_external_accounts")
	args := []any{workspaceID}
	query += " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1)
	if strings.TrimSpace(userID) != "" {
		args = append(args, userID)
		query += " AND " + s.store.Identifier("user_id") + " = " + s.store.Placeholder(2)
	}
	query += " ORDER BY " + s.store.Identifier("provider") + ", " + s.store.Identifier("provider_subject")
	rows, err := s.db.QueryContext(ctx, query, args...)
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.store.TableIdentifier("identity_external_accounts")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("id")+" = "+s.store.Placeholder(2), workspaceID, account.ID); err != nil {
		return err
	}
	query := "INSERT INTO " + s.store.TableIdentifier("identity_external_accounts") + " (" + s.store.IdentityColumns("id", "workspace_id", "user_id", "provider", "provider_subject", "email", "phone", "display_name", "avatar_url", "metadata", "linked_at", "created_at", "updated_at") + ") VALUES (" + s.store.Placeholders(13) + ")"
	if _, err := tx.ExecContext(ctx, query, account.ID, workspaceID, account.UserID, account.Provider, account.ProviderSubject, database.NullableText(account.Email), database.NullableText(account.Phone), database.NullableText(account.DisplayName), database.NullableText(account.AvatarURL), database.NullableText(account.Metadata), account.LinkedAt, now, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
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
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+s.store.IdentityColumns("id", "user_id", "factor_type", "label", "provider", "provider_ref", "status", "verified_at", "last_used_at", "created_at", "updated_at")+
			" FROM "+s.store.TableIdentifier("identity_mfa_factors")+
			" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+
			" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(2)+
			" ORDER BY "+s.store.Identifier("created_at")+", "+s.store.Identifier("id"),
		workspaceID, userID,
	)
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM "+s.store.TableIdentifier("identity_mfa_factors")+
			" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+
			" AND "+s.store.Identifier("id")+" = "+s.store.Placeholder(2),
		workspaceID, factor.ID,
	); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		"INSERT INTO "+s.store.TableIdentifier("identity_mfa_factors")+" ("+
			s.store.IdentityColumns("id", "workspace_id", "user_id", "factor_type", "label", "provider", "provider_ref", "status", "verified_at", "last_used_at", "created_at", "updated_at")+
			") VALUES ("+s.store.Placeholders(12)+")",
		factor.ID, workspaceID, factor.UserID, factor.Type, database.NullableText(factor.Label),
		database.NullableText(factor.Provider), database.NullableText(factor.ProviderRef), factor.Status,
		database.NullableText(factor.VerifiedAt), database.NullableText(factor.LastUsedAt), factor.CreatedAt, factor.UpdatedAt,
	)
	if err != nil {
		return err
	}
	return tx.Commit()
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
	result, err := s.db.ExecContext(ctx,
		"UPDATE "+s.store.TableIdentifier("identity_mfa_factors")+
			" SET "+s.store.Identifier("status")+" = 'disabled', "+s.store.Identifier("updated_at")+" = "+s.store.Placeholder(1)+
			" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(2)+
			" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(3)+
			" AND "+s.store.Identifier("id")+" = "+s.store.Placeholder(4),
		identitypersistence.NowString(), workspaceID, userID, factorID,
	)
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
	_, err = s.db.ExecContext(ctx, "DELETE FROM "+s.store.TableIdentifier("identity_external_accounts")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("id")+" = "+s.store.Placeholder(2), workspaceID, accountID)
	return err
}
