package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-orm/query"
)

var _ authrepository.AuthEmailCredentialRepository = AuthStore{}

// All authorization facts, one-time consumption, password storage and session
// revocation share this transaction. No caller receives a recovered password.
func (s AuthStore) CompleteEmailCredential(ctx context.Context, workspace, state, purpose, code, passwordHash string, maxAttempts int, now time.Time) (string, bool, error) {
	workspace, err := authWorkspaceID(workspace)
	if err != nil {
		return "", false, err
	}
	if purpose != "password_setup" && purpose != "password_recovery" || passwordHash == "" {
		return "", false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	stateHash, nowMillis := authLoginStateHash(state), now.UTC().UnixMilli()
	// Serialize attempts on the grant before reading its counter. Conditional
	// updates after a shared read would undercount concurrent incorrect codes.
	statement, args, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspace).
		SetExpression("updated_at", query.Column("updated_at")).
		Where(query.And(query.Equal("provider_key", "email_credential"), query.Equal("state_hash", stateHash))).Build()
	if err != nil {
		return "", false, err
	}
	if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
		return "", false, err
	}
	selectGrant := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspace).
		Columns("payload_json", "attempts").Where(query.And(query.Equal("provider_key", "email_credential"), query.Equal("state_hash", stateHash), query.Equal("challenge_purpose", purpose), query.Equal("challenge_status", authmodel.AuthChallengeStatusActive), query.Equal("consumed_at", int64(0)), query.GreaterThan("expires_at", nowMillis))).Limit(1)
	statement, args, err = selectGrant.Build()
	if err != nil {
		return "", false, err
	}
	var envelope string
	var attempts int
	if err = tx.QueryRowContext(ctx, statement, args...).Scan(&envelope, &attempts); err == sql.ErrNoRows {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	plain, err := s.loginSecrets.Decrypt(ctx, workspace, stateHash, envelope)
	if err != nil {
		return "", false, err
	}
	challenge, err := unmarshalPersistedAuthProviderChallenge(plain)
	if err != nil {
		return "", false, err
	}
	if challenge.WorkspaceID != workspace || challenge.Purpose != purpose || challenge.Provider != "email_credential" {
		return "", false, nil
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	validCode := purpose == "password_setup" || len(code) == 6 && subtle.ConstantTimeCompare([]byte(challenge.Code), []byte(code)) == 1
	if !validCode {
		update := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspace).Set("attempts", attempts+1).Set("updated_at", nowMillis)
		if attempts+1 >= maxAttempts {
			update.Set("challenge_status", authmodel.AuthChallengeStatusFailed).Set("consumed_at", nowMillis)
		}
		statement, args, err = update.Where(query.And(query.Equal("state_hash", stateHash), query.Equal("provider_key", "email_credential"), query.Equal("consumed_at", int64(0)), query.Equal("attempts", attempts))).Build()
		if err != nil {
			return "", false, err
		}
		if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
			return "", false, err
		}
		return "", false, tx.Commit()
	}
	if challenge.UserID == "" || challenge.Email == "" {
		return "", false, nil
	}
	// A portable no-op update locks the subject on SQL engines without relying
	// on SELECT FOR UPDATE (unsupported by SQLite). Do not alter user metadata.
	statement, args, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_users", workspace).
		SetExpression("updated_at", query.Column("updated_at")).Where(query.Equal("user_id", challenge.UserID)).Build()
	if err != nil {
		return "", false, err
	}
	if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
		return "", false, err
	}
	statement, args, err = query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspace).
		Columns("user_id").Where(query.And(query.Equal("user_id", challenge.UserID), query.Equal("email", challenge.Email), query.Equal("status", "active"), query.Equal("account_type", "human"))).Build()
	if err != nil {
		return "", false, err
	}
	var userID string
	if err = tx.QueryRowContext(ctx, statement, args...).Scan(&userID); err == sql.ErrNoRows {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	statement, args, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_credentials", workspace).
		SetExpression("updated_at", query.Column("updated_at")).Where(query.Equal("user_id", userID)).Build()
	if err != nil {
		return "", false, err
	}
	if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
		return "", false, err
	}
	statement, args, err = query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_credentials", workspace).
		Columns("password_hash", "last_login_at").Where(query.Equal("user_id", userID)).Build()
	if err != nil {
		return "", false, err
	}
	var existingHash string
	var lastLoginAt int64
	if err = tx.QueryRowContext(ctx, statement, args...).Scan(&existingHash, &lastLoginAt); err != nil && err != sql.ErrNoRows {
		return "", false, err
	}
	marker := ""
	if existingHash != "" {
		digest := sha256.Sum256([]byte(existingHash))
		marker = hex.EncodeToString(digest[:])
	}
	if subtle.ConstantTimeCompare([]byte(challenge.Nonce), []byte(marker)) != 1 {
		return "", false, nil
	}
	statement, args, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspace).
		Set("challenge_status", authmodel.AuthChallengeStatusConsumed).Set("consumed_at", nowMillis).Set("updated_at", nowMillis).
		Where(query.And(query.Equal("state_hash", stateHash), query.Equal("provider_key", "email_credential"), query.Equal("challenge_purpose", purpose), query.Equal("attempts", attempts), query.Equal("consumed_at", int64(0)), query.Equal("challenge_status", authmodel.AuthChallengeStatusActive), query.GreaterThan("expires_at", nowMillis))).Build()
	if err != nil {
		return "", false, err
	}
	result, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return "", false, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return "", false, err
	}
	if err = s.UpsertIdentityCredentialWithExecutor(ctx, tx, workspace, identitymodel.IdentityCredential{UserID: userID, PasswordHash: passwordHash, PasswordUpdatedAt: now.Format(time.RFC3339Nano), LastLoginAt: identitypersistence.TimeString(lastLoginAt), MustChangePassword: false}); err != nil {
		return "", false, err
	}
	statement, args, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_refresh_tokens", workspace).
		Set("revoked_at", nowMillis).Set("updated_at", nowMillis).Where(query.And(query.Equal("user_id", userID), query.Equal("revoked_at", int64(0)))).Build()
	if err != nil {
		return "", false, err
	}
	if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
		return "", false, err
	}
	if err = tx.Commit(); err != nil {
		return "", false, err
	}
	return strings.TrimSpace(userID), true, nil
}
