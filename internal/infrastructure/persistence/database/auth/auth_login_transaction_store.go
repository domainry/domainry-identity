package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-orm/query"
)

func authLoginStateHash(state string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(state)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s AuthStore) CreateAuthLoginTransaction(ctx context.Context, challenge authmodel.AuthProviderChallenge) error {
	if strings.TrimSpace(challenge.Status) == "" {
		challenge.Status = authmodel.AuthChallengeStatusActive
	}
	if strings.TrimSpace(challenge.Purpose) == "" {
		challenge.Purpose = authmodel.AuthChallengePurposeLogin
	}
	workspaceID, provider, stateHash, envelope, now, err := s.prepareAuthLoginTransaction(ctx, challenge, time.Time{})
	if err != nil {
		return err
	}
	return s.insertAuthLoginTransaction(ctx, s.db, workspaceID, provider, stateHash, "", envelope, challenge, now)
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
	supersede, supersedeArgs, buildErr := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).
		Set("challenge_status", authmodel.AuthChallengeStatusSuperseded).Set("consumed_at", nowText).Set("updated_at", nowText).
		Where(query.And(query.Equal("provider_key", provider), query.Equal("subject_key_hash", subjectKeyHash), query.Equal("consumed_at", int64(0)))).Build()
	if buildErr != nil {
		return false, buildErr
	}
	if _, err := tx.ExecContext(ctx, supersede, supersedeArgs...); err != nil {
		return false, err
	}
	if err := s.insertAuthLoginTransaction(ctx, tx, workspaceID, provider, stateHash, subjectKeyHash, envelope, challenge, nowText); err != nil {
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

func (s AuthStore) insertAuthLoginTransaction(ctx context.Context, executor authLoginTransactionExecutor, workspaceID, provider, stateHash, subjectKeyHash, envelope string, challenge authmodel.AuthProviderChallenge, now int64) error {
	status := strings.TrimSpace(challenge.Status)
	if status == "" {
		status = authmodel.AuthChallengeStatusActive
	}
	purpose := strings.TrimSpace(challenge.Purpose)
	if purpose == "" {
		purpose = authmodel.AuthChallengePurposeLogin
	}
	statement, args, buildErr := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).
		Columns("state_hash", "provider_key", "subject_key_hash", "challenge_status", "challenge_purpose", "delivery_ref", "delivery_error", "payload_json", "attempts", "expires_at", "consumed_at", "created_at", "updated_at").
		Values(stateHash, provider, nullableAuthText(subjectKeyHash), status, purpose, nullableAuthText(challenge.DeliveryRef), nullableAuthText(challenge.DeliveryError), envelope, challenge.Attempts, identitypersistence.TimeMillis(challenge.ExpiresAt), int64(0), valueOrNowMillis(challenge.CreatedAt, now), now).Build()
	if buildErr != nil {
		return buildErr
	}
	_, err := executor.ExecContext(ctx, statement, args...)
	return err
}

func (s AuthStore) UpdateAuthOTPTransactionStatus(ctx context.Context, workspaceID, provider, state, status, deliveryRef, deliveryError string, now time.Time) error {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	provider, state, status = strings.ToLower(strings.TrimSpace(provider)), strings.TrimSpace(state), strings.TrimSpace(status)
	if provider == "" || state == "" || status == "" {
		return authWorkspaceRequiredError()
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowMillis := now.UTC().UnixMilli()
	update := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).
		Set("challenge_status", status).Set("delivery_ref", nullableAuthText(deliveryRef)).Set("delivery_error", nullableAuthText(deliveryError)).Set("updated_at", nowMillis)
	if status == authmodel.AuthChallengeStatusFailed || status == authmodel.AuthChallengeStatusSuperseded {
		update.Set("consumed_at", nowMillis)
	}
	statement, args, buildErr := update.Where(query.And(query.Equal("state_hash", authLoginStateHash(state)), query.Equal("provider_key", provider), query.Equal("consumed_at", int64(0)))).Build()
	if buildErr != nil {
		return buildErr
	}
	result, err := s.db.ExecContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s AuthStore) prepareAuthLoginTransaction(ctx context.Context, challenge authmodel.AuthProviderChallenge, now time.Time) (string, string, string, string, int64, error) {
	workspaceID, err := authWorkspaceID(challenge.WorkspaceID)
	if err != nil {
		return "", "", "", "", 0, err
	}
	provider, state := strings.ToLower(strings.TrimSpace(challenge.Provider)), strings.TrimSpace(challenge.State)
	if provider == "" || state == "" {
		return "", "", "", "", 0, authWorkspaceRequiredError()
	}
	stateHash := authLoginStateHash(state)
	persisted := challenge
	persisted.State = ""
	payload, err := marshalPersistedAuthProviderChallenge(persisted)
	if err != nil {
		return "", "", "", "", 0, err
	}
	envelope, err := s.loginSecrets.Encrypt(ctx, workspaceID, stateHash, payload)
	if err != nil {
		return "", "", "", "", 0, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return workspaceID, provider, stateHash, envelope, now.UTC().UnixMilli(), nil
}

func (s AuthStore) claimAuthOTPDelivery(ctx context.Context, tx *sql.Tx, workspaceID, provider, subjectKeyHash string, now, nextAllowedAt time.Time) (bool, error) {
	nowMillis, nextMillis := now.UTC().UnixMilli(), nextAllowedAt.UTC().UnixMilli()
	update, updateArgs, buildErr := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_otp_delivery_limits", workspaceID).
		Set("provider_key", provider).Set("next_allowed_at", nextMillis).Set("updated_at", nowMillis).
		Where(query.And(query.Equal("subject_key_hash", subjectKeyHash), query.LessThanOrEqual("next_allowed_at", nowMillis))).Build()
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
	insert, insertArgs, buildErr := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_auth_otp_delivery_limits", workspaceID).
		Columns("subject_key_hash", "provider_key", "next_allowed_at", "created_at", "updated_at").
		Values(subjectKeyHash, provider, nextMillis, nowMillis, nowMillis).OnConflictDoNothing("workspace_id", "subject_key_hash").Build()
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
	nowMillis := now.UTC().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	updateStatement, updateArgs, buildErr := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).
		Set("consumed_at", nowMillis).Set("challenge_status", authmodel.AuthChallengeStatusConsumed).Set("updated_at", nowMillis).Where(query.And(
		query.Equal("state_hash", stateHash), query.Equal("provider_key", provider), query.Equal("challenge_status", authmodel.AuthChallengeStatusActive), query.Equal("consumed_at", int64(0)), query.GreaterThan("expires_at", nowMillis),
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
	selectStatement, selectArgs, buildErr := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).
		Columns("payload_json", "challenge_purpose", "delivery_ref", "delivery_error").Where(query.And(query.Equal("state_hash", stateHash), query.Equal("provider_key", provider))).Limit(1).Build()
	if buildErr != nil {
		return authmodel.AuthProviderChallenge{}, false, buildErr
	}
	var envelope, purpose string
	var deliveryRef, deliveryError sql.NullString
	if err := tx.QueryRowContext(ctx, selectStatement, selectArgs...).Scan(&envelope, &purpose, &deliveryRef, &deliveryError); err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	plain, err := s.loginSecrets.Decrypt(ctx, workspaceID, stateHash, envelope)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	challenge, err := unmarshalPersistedAuthProviderChallenge(plain)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	challenge.State, challenge.Status, challenge.Purpose = state, authmodel.AuthChallengeStatusConsumed, purpose
	challenge.DeliveryRef, challenge.DeliveryError = deliveryRef.String, deliveryError.String
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
	queryValue, args, buildErr := query.NewSelectBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions").Columns("workspace_id").Where(query.And(
		query.Equal("state_hash", authLoginStateHash(state)), query.Equal("provider_key", provider), query.Equal("consumed_at", int64(0)), query.GreaterThan("expires_at", now.UTC().UnixMilli()),
	)).OrderBy(query.Ascending("workspace_id")).Build()
	if buildErr != nil {
		return "", false, buildErr
	}
	rows, err := s.db.QueryContext(ctx, queryValue, args...)
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
	return workspaceID, true, nil
}

func (s AuthStore) ConsumeAuthOTPTransaction(ctx context.Context, workspaceID, provider, state, code string, allowedPurposes []string, expectedUserID string, maxAttempts int, now time.Time) (authmodel.AuthProviderChallenge, bool, error) {
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
	nowMillis, stateHash := now.UTC().UnixMilli(), authLoginStateHash(state)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	selectStatement, selectArgs, buildErr := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).
		Columns("payload_json", "attempts", "challenge_purpose", "delivery_ref", "delivery_error").Where(query.And(
		query.Equal("state_hash", stateHash), query.Equal("provider_key", provider), query.Equal("challenge_status", authmodel.AuthChallengeStatusActive), query.Equal("consumed_at", int64(0)), query.GreaterThan("expires_at", nowMillis),
	)).Limit(1).Build()
	if buildErr != nil {
		return authmodel.AuthProviderChallenge{}, false, buildErr
	}
	var envelope, purpose string
	var attempts int
	var deliveryRef, deliveryError sql.NullString
	if err := tx.QueryRowContext(ctx, selectStatement, selectArgs...).Scan(&envelope, &attempts, &purpose, &deliveryRef, &deliveryError); err != nil {
		if err == sql.ErrNoRows {
			return authmodel.AuthProviderChallenge{}, false, nil
		}
		return authmodel.AuthProviderChallenge{}, false, err
	}
	plain, err := s.loginSecrets.Decrypt(ctx, workspaceID, stateHash, envelope)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	challenge, err := unmarshalPersistedAuthProviderChallenge(plain)
	if err != nil {
		return authmodel.AuthProviderChallenge{}, false, err
	}
	challenge.State, challenge.Attempts, challenge.Purpose, challenge.Status = state, attempts, purpose, authmodel.AuthChallengeStatusActive
	challenge.DeliveryRef, challenge.DeliveryError = deliveryRef.String, deliveryError.String
	if !authOTPChallengeMatchesPurposeAndUser(challenge, allowedPurposes, expectedUserID) {
		return authmodel.AuthProviderChallenge{}, false, nil
	}
	valid := false
	if challenge.Type == "totp" && challenge.Provider == authmodel.TOTPProvider {
		valid, err = s.verifyTOTPFactor(ctx, tx, challenge, code, now, maxAttempts)
		if err != nil {
			return authmodel.AuthProviderChallenge{}, false, err
		}
	} else {
		valid = challenge.Code != "" && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(challenge.Code)), []byte(strings.TrimSpace(code))) == 1
	}
	updateBuilder := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).
		Set("attempts", attempts).Set("updated_at", nowMillis)
	if valid || attempts+1 >= maxAttempts {
		updateBuilder.Set("consumed_at", nowMillis)
		if valid {
			updateBuilder.Set("challenge_status", authmodel.AuthChallengeStatusConsumed)
		} else {
			updateBuilder.Set("challenge_status", authmodel.AuthChallengeStatusFailed)
		}
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
	updateStatement, updateArgs, buildErr := updateBuilder.Where(query.And(
		query.Equal("state_hash", stateHash), query.Equal("provider_key", provider), query.Equal("attempts", expectedAttempts), query.Equal("consumed_at", int64(0)),
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

func authOTPChallengeMatchesPurposeAndUser(challenge authmodel.AuthProviderChallenge, allowedPurposes []string, expectedUserID string) bool {
	purposeAllowed := len(allowedPurposes) == 0
	for _, purpose := range allowedPurposes {
		if strings.TrimSpace(purpose) == strings.TrimSpace(challenge.Purpose) {
			purposeAllowed = true
			break
		}
	}
	return purposeAllowed && (strings.TrimSpace(expectedUserID) == "" || strings.TrimSpace(challenge.UserID) == strings.TrimSpace(expectedUserID))
}

func nullableAuthText(value string) any {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return nil
}

func valueOrNowMillis(value string, fallback int64) int64 {
	if millis := identitypersistence.TimeMillis(value); millis != 0 {
		return millis
	}
	return fallback
}

func authWorkspaceRequiredError() error {
	_, err := authWorkspaceID("")
	return err
}
