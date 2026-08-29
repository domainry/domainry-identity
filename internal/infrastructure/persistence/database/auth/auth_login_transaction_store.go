package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func authLoginStateHash(state string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(state)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s AuthStore) CreateAuthLoginTransaction(ctx context.Context, challenge authmodel.AuthProviderChallenge) error {
	workspaceID, provider, stateHash, envelope, now, err := s.prepareAuthLoginTransaction(ctx, challenge, time.Time{})
	if err != nil {
		return err
	}
	return s.insertAuthLoginTransaction(ctx, s.db, workspaceID, provider, stateHash, envelope, challenge, now)
}

func (s AuthStore) CreateAuthOTPTransaction(ctx context.Context, challenge authmodel.AuthProviderChallenge, subjectKeyHash string, nextAllowedAt, now time.Time) (bool, error) {
	subjectKeyHash = strings.TrimSpace(subjectKeyHash)
	if subjectKeyHash == "" {
		return false, authWorkspaceRequiredError()
	}
	workspaceID, provider, stateHash, envelope, nowText, err := s.prepareAuthLoginTransaction(ctx, challenge, now)
	if err != nil {
		return false, err
	}
	if nextAllowedAt.IsZero() || !nextAllowedAt.After(now) {
		return false, authWorkspaceRequiredError()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	claimed, err := s.claimAuthOTPDelivery(ctx, tx, workspaceID, provider, subjectKeyHash, now, nextAllowedAt)
	if err != nil || !claimed {
		return false, err
	}
	if err := s.insertAuthLoginTransaction(ctx, tx, workspaceID, provider, stateHash, envelope, challenge, nowText); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

type authLoginTransactionExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (s AuthStore) insertAuthLoginTransaction(ctx context.Context, executor authLoginTransactionExecutor, workspaceID, provider, stateHash, envelope string, challenge authmodel.AuthProviderChallenge, now string) error {
	statement, args, buildErr := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "auth_login_transactions", workspaceID).
		Columns("state_hash", "provider_key", "payload_json", "attempts", "expires_at", "consumed_at", "created_at", "updated_at").
		Values(stateHash, provider, envelope, challenge.Attempts, challenge.ExpiresAt, nil, valueOrNow(challenge.CreatedAt, now), now).Build()
	if buildErr != nil {
		return buildErr
	}
	_, err := executor.ExecContext(ctx, statement, args...)
	return err
}

func (s AuthStore) prepareAuthLoginTransaction(ctx context.Context, challenge authmodel.AuthProviderChallenge, now time.Time) (string, string, string, string, string, error) {
	workspaceID, err := authWorkspaceID(challenge.WorkspaceID)
	if err != nil {
		return "", "", "", "", "", err
	}
	provider, state := strings.ToLower(strings.TrimSpace(challenge.Provider)), strings.TrimSpace(challenge.State)
	if provider == "" || state == "" {
		return "", "", "", "", "", authWorkspaceRequiredError()
	}
	stateHash := authLoginStateHash(state)
	persisted := challenge
	persisted.State = ""
	payload, err := json.Marshal(persisted)
	if err != nil {
		return "", "", "", "", "", err
	}
	envelope, err := s.loginSecrets.Encrypt(ctx, workspaceID, stateHash, payload)
	if err != nil {
		return "", "", "", "", "", err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return workspaceID, provider, stateHash, envelope, now.UTC().Format(time.RFC3339Nano), nil
}

func (s AuthStore) claimAuthOTPDelivery(ctx context.Context, tx *sql.Tx, workspaceID, provider, subjectKeyHash string, now, nextAllowedAt time.Time) (bool, error) {
	nowText, nextText := now.UTC().Format(time.RFC3339Nano), nextAllowedAt.UTC().Format(time.RFC3339Nano)
	update, updateArgs, buildErr := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "auth_otp_delivery_limits", workspaceID).
		Set("provider_key", provider).Set("next_allowed_at", nextText).Set("updated_at", nowText).
		Where(ormbuilder.And(ormbuilder.Equal("subject_key_hash", subjectKeyHash), ormbuilder.LessThanOrEqual("next_allowed_at", nowText))).Build()
	if buildErr != nil {
		return false, buildErr
	}
	result, err := tx.ExecContext(ctx, update, updateArgs...)
	if err != nil {
		return false, err
	}
	if changed, changeErr := result.RowsAffected(); changeErr != nil {
		return false, changeErr
	} else if changed == 1 {
		return true, nil
	}
	insert, insertArgs, buildErr := ormbuilder.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "auth_otp_delivery_limits", workspaceID).
		Columns("subject_key_hash", "provider_key", "next_allowed_at", "created_at", "updated_at").
		Values(subjectKeyHash, provider, nextText, nowText, nowText).OnConflictDoNothing("workspace_id", "subject_key_hash").Build()
	if buildErr != nil {
		return false, buildErr
	}
	result, err = tx.ExecContext(ctx, insert, insertArgs...)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return changed == 1, nil
}

func (s AuthStore) ConsumeAuthLoginTransaction(ctx context.Context, workspaceID, provider, state string, now time.Time) (authmodel.AuthProviderChallenge, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	provider, state = strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(state)
	if provider == "" || state == "" {
		return authmodel.AuthProviderChallenge{}, false, nil
	}
	stateHash := authLoginStateHash(state)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowText := now.UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	updateStatement, updateArgs, buildErr := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "auth_login_transactions", workspaceID).
		Set("consumed_at", nowText).Set("updated_at", nowText).Where(ormbuilder.And(
		ormbuilder.Equal("state_hash", stateHash), ormbuilder.Equal("provider_key", provider), ormbuilder.IsNull("consumed_at"), ormbuilder.GreaterThan("expires_at", nowText),
	)).Build()
	if buildErr != nil {
		return authmodel.AuthProviderChallenge{}, false, buildErr
	}
	result, err := tx.ExecContext(ctx, updateStatement, updateArgs...)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	selectStatement, selectArgs, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "auth_login_transactions", workspaceID).
		Columns("payload_json").Where(ormbuilder.And(ormbuilder.Equal("state_hash", stateHash), ormbuilder.Equal("provider_key", provider))).Limit(1).Build()
	if buildErr != nil {
		return authmodel.AuthProviderChallenge{}, false, buildErr
	}
	var envelope string
	if err := tx.QueryRowContext(ctx, selectStatement, selectArgs...).Scan(&envelope); err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	plain, err := s.loginSecrets.Decrypt(ctx, workspaceID, stateHash, envelope)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	var challenge authmodel.AuthProviderChallenge
	if err := json.Unmarshal(plain, &challenge); err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	challenge.State = state
	if err := tx.Commit(); err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	return challenge, true, nil
}

func (s AuthStore) FederatedLoginWorkspace(ctx context.Context, provider, state string, now time.Time) (string, bool, error) {
	provider, state = strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(state)
	if provider == "" || state == "" {
		return "", false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	query, args, buildErr := ormbuilder.NewSelectBuilder(s.store.SQLRenderer(), "auth_login_transactions").Columns("workspace_id").Where(ormbuilder.And(
		ormbuilder.Equal("state_hash", authLoginStateHash(state)), ormbuilder.Equal("provider_key", provider), ormbuilder.IsNull("consumed_at"), ormbuilder.GreaterThan("expires_at", now.UTC().Format(time.RFC3339Nano)),
	)).Limit(1).Build()
	if buildErr != nil {
		return "", false, buildErr
	}
	var workspaceID string
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&workspaceID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(workspaceID), true, nil
}

func (s AuthStore) ConsumeAuthOTPTransaction(ctx context.Context, workspaceID, provider, state, code string, maxAttempts int, now time.Time) (authmodel.AuthProviderChallenge, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	provider, state = strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(state)
	if provider == "" || state == "" {
		return authmodel.AuthProviderChallenge{}, false, nil
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowText, stateHash := now.UTC().Format(time.RFC3339Nano), authLoginStateHash(state)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	selectStatement, selectArgs, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "auth_login_transactions", workspaceID).
		Columns("payload_json", "attempts").Where(ormbuilder.And(
		ormbuilder.Equal("state_hash", stateHash), ormbuilder.Equal("provider_key", provider), ormbuilder.IsNull("consumed_at"), ormbuilder.GreaterThan("expires_at", nowText),
	)).Limit(1).Build()
	if buildErr != nil {
		return authmodel.AuthProviderChallenge{}, false, buildErr
	}
	var envelope string
	var attempts int
	if err := tx.QueryRowContext(ctx, selectStatement, selectArgs...).Scan(&envelope, &attempts); err != nil {
		if err == sql.ErrNoRows {
			return authmodel.AuthProviderChallenge{}, false, nil
		}
		return authmodel.AuthProviderChallenge{}, false, err
	}
	plain, err := s.loginSecrets.Decrypt(ctx, workspaceID, stateHash, envelope)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	var challenge authmodel.AuthProviderChallenge
	if err := json.Unmarshal(plain, &challenge); err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	challenge.State, challenge.Attempts = state, attempts
	valid := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(challenge.Code)), []byte(strings.TrimSpace(code))) == 1
	updateBuilder := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "auth_login_transactions", workspaceID).
		Set("attempts", attempts).Set("updated_at", nowText)
	if valid || attempts+1 >= maxAttempts {
		updateBuilder.Set("consumed_at", nowText)
	}
	if !valid {
		attempts++
		updateBuilder.Set("attempts", attempts)
		challenge.Attempts = attempts
	}
	expectedAttempts := challenge.Attempts
	if !valid {
		expectedAttempts = attempts - 1
	}
	updateStatement, updateArgs, buildErr := updateBuilder.Where(ormbuilder.And(
		ormbuilder.Equal("state_hash", stateHash), ormbuilder.Equal("provider_key", provider), ormbuilder.Equal("attempts", expectedAttempts), ormbuilder.IsNull("consumed_at"),
	)).Build()
	if buildErr != nil {
		return authmodel.AuthProviderChallenge{}, false, buildErr
	}
	result, err := tx.ExecContext(ctx, updateStatement, updateArgs...)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	return challenge, valid, nil
}

func valueOrNow(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func authWorkspaceRequiredError() error {
	_, err := authWorkspaceID("")
	return err
}
