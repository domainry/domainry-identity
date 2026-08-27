package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
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
	_, err = s.db.ExecContext(ctx, "INSERT INTO "+s.store.TableIdentifier("auth_login_transactions")+" ("+s.store.IdentityColumns("state_hash", "workspace_id", "provider_key", "payload_json", "attempts", "expires_at", "consumed_at", "created_at", "updated_at")+") VALUES ("+s.store.Placeholders(9)+")", stateHash, workspaceID, provider, envelope, challenge.Attempts, challenge.ExpiresAt, nil, valueOrNow(challenge.CreatedAt, now), now)
	return err
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
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.store.TableIdentifier("auth_login_transactions")+" ("+s.store.IdentityColumns("state_hash", "workspace_id", "provider_key", "payload_json", "attempts", "expires_at", "consumed_at", "created_at", "updated_at")+") VALUES ("+s.store.Placeholders(9)+")", stateHash, workspaceID, provider, envelope, challenge.Attempts, challenge.ExpiresAt, nil, valueOrNow(challenge.CreatedAt, nowText), nowText); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
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
	table := s.store.TableIdentifier("auth_otp_delivery_limits")
	nowText, nextText := now.UTC().Format(time.RFC3339Nano), nextAllowedAt.UTC().Format(time.RFC3339Nano)
	update := "UPDATE " + table + " SET " + s.store.Identifier("provider_key") + " = " + s.store.Placeholder(1) + ", " + s.store.Identifier("next_allowed_at") + " = " + s.store.Placeholder(2) + ", " + s.store.Identifier("updated_at") + " = " + s.store.Placeholder(3) + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(4) + " AND " + s.store.Identifier("subject_key_hash") + " = " + s.store.Placeholder(5) + " AND " + s.store.Identifier("next_allowed_at") + " <= " + s.store.Placeholder(6)
	result, err := tx.ExecContext(ctx, update, provider, nextText, nowText, workspaceID, subjectKeyHash, nowText)
	if err != nil {
		return false, err
	}
	if changed, changeErr := result.RowsAffected(); changeErr != nil {
		return false, changeErr
	} else if changed == 1 {
		return true, nil
	}
	insert := "INSERT INTO " + table + " (" + s.store.IdentityColumns("subject_key_hash", "workspace_id", "provider_key", "next_allowed_at", "created_at", "updated_at") + ") VALUES (" + s.store.Placeholders(6) + ")"
	switch s.store.Driver() {
	case "mysql":
		insert = strings.Replace(insert, "INSERT INTO", "INSERT IGNORE INTO", 1)
	case "postgres", "sqlite":
		insert += " ON CONFLICT (" + s.store.IdentityColumns("workspace_id", "subject_key_hash") + ") DO NOTHING"
	default:
		return false, fmt.Errorf("unsupported OTP delivery-limit database driver %q", s.store.Driver())
	}
	result, err = tx.ExecContext(ctx, insert, subjectKeyHash, workspaceID, provider, nextText, nowText, nowText)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return changed == 1, nil
}

func (s AuthStore) ConsumeAuthLoginTransaction(ctx context.Context, provider, state string, now time.Time) (authmodel.AuthProviderChallenge, bool, error) {
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
	result, err := tx.ExecContext(ctx, "UPDATE "+s.store.TableIdentifier("auth_login_transactions")+" SET "+s.store.Identifier("consumed_at")+" = "+s.store.Placeholder(1)+", "+s.store.Identifier("updated_at")+" = "+s.store.Placeholder(2)+" WHERE "+s.store.Identifier("state_hash")+" = "+s.store.Placeholder(3)+" AND "+s.store.Identifier("provider_key")+" = "+s.store.Placeholder(4)+" AND "+s.store.Identifier("consumed_at")+" IS NULL AND "+s.store.Identifier("expires_at")+" > "+s.store.Placeholder(5), nowText, nowText, stateHash, provider, nowText)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	var workspaceID, envelope string
	if err := tx.QueryRowContext(ctx, "SELECT "+s.store.IdentityColumns("workspace_id", "payload_json")+" FROM "+s.store.TableIdentifier("auth_login_transactions")+" WHERE "+s.store.Identifier("state_hash")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("provider_key")+" = "+s.store.Placeholder(2), stateHash, provider).Scan(&workspaceID, &envelope); err != nil {
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
	query := "SELECT " + s.store.Identifier("workspace_id") + " FROM " + s.store.TableIdentifier("auth_login_transactions") + " WHERE " + s.store.Identifier("state_hash") + " = " + s.store.Placeholder(1) + " AND " + s.store.Identifier("provider_key") + " = " + s.store.Placeholder(2) + " AND " + s.store.Identifier("consumed_at") + " IS NULL AND " + s.store.Identifier("expires_at") + " > " + s.store.Placeholder(3)
	var workspaceID string
	err := s.db.QueryRowContext(ctx, query, authLoginStateHash(state), provider, now.UTC().Format(time.RFC3339Nano)).Scan(&workspaceID)
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
	var storedWorkspace, envelope string
	var attempts int
	if err := tx.QueryRowContext(ctx, "SELECT "+s.store.IdentityColumns("workspace_id", "payload_json", "attempts")+" FROM "+s.store.TableIdentifier("auth_login_transactions")+" WHERE "+s.store.Identifier("state_hash")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("provider_key")+" = "+s.store.Placeholder(2)+" AND "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(3)+" AND "+s.store.Identifier("consumed_at")+" IS NULL AND "+s.store.Identifier("expires_at")+" > "+s.store.Placeholder(4), stateHash, provider, workspaceID, nowText).Scan(&storedWorkspace, &envelope, &attempts); err != nil {
		if err == sql.ErrNoRows {
			return authmodel.AuthProviderChallenge{}, false, nil
		}
		return authmodel.AuthProviderChallenge{}, false, err
	}
	plain, err := s.loginSecrets.Decrypt(ctx, storedWorkspace, stateHash, envelope)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	var challenge authmodel.AuthProviderChallenge
	if err := json.Unmarshal(plain, &challenge); err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	challenge.State, challenge.Attempts = state, attempts
	valid := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(challenge.Code)), []byte(strings.TrimSpace(code))) == 1
	query := "UPDATE " + s.store.TableIdentifier("auth_login_transactions") + " SET " + s.store.Identifier("attempts") + " = " + s.store.Placeholder(1) + ", " + s.store.Identifier("updated_at") + " = " + s.store.Placeholder(2)
	args := []any{attempts, nowText}
	if valid || attempts+1 >= maxAttempts {
		query += ", " + s.store.Identifier("consumed_at") + " = " + s.store.Placeholder(3)
		args = append(args, nowText)
	}
	if !valid {
		attempts++
		args[0], challenge.Attempts = attempts, attempts
	}
	query += " WHERE " + s.store.Identifier("state_hash") + " = " + s.store.Placeholder(len(args)+1) + " AND " + s.store.Identifier("provider_key") + " = " + s.store.Placeholder(len(args)+2) + " AND " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(len(args)+3) + " AND " + s.store.Identifier("attempts") + " = " + s.store.Placeholder(len(args)+4) + " AND " + s.store.Identifier("consumed_at") + " IS NULL"
	args = append(args, stateHash, provider, workspaceID, challenge.Attempts)
	if !valid {
		args[len(args)-1] = attempts - 1
	}
	result, err := tx.ExecContext(ctx, query, args...)
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
