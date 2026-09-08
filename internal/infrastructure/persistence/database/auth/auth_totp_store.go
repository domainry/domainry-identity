package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	"github.com/domainry/domainry-orm/query"
)

func totpFactorID(workspaceID, userID string) string {
	digest := sha256.Sum256([]byte(workspaceID + "\x00" + userID))
	return "totp_" + hex.EncodeToString(digest[:20])
}

func (s AuthStore) TOTPFactorState(ctx context.Context, workspaceID, userID string) (authmodel.TOTPFactorState, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.TOTPFactorState{}, err
	}
	id := totpFactorID(workspaceID, userID)
	statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", workspaceID).
		Columns("totp_secret", "provider_ref").Where(query.And(query.Equal("id", id), query.Equal("user_id", userID), query.Equal("provider", authmodel.TOTPProvider), query.Equal("status", "active"), query.IsNotNull("verified_at"))).Build()
	if err != nil {
		return authmodel.TOTPFactorState{}, err
	}
	var envelope, generation string
	if err := s.db.QueryRowContext(ctx, statement, args...).Scan(&envelope, &generation); err != nil {
		if err == sql.ErrNoRows {
			return authmodel.TOTPFactorState{}, nil
		}
		return authmodel.TOTPFactorState{}, err
	}
	plain, err := s.totpSecrets.Decrypt(ctx, workspaceID, id, envelope)
	if err != nil {
		return authmodel.TOTPFactorState{}, err
	}
	var secret authmodel.TOTPSecret
	if err := json.Unmarshal(plain, &secret); err != nil {
		return authmodel.TOTPFactorState{}, err
	}
	return authmodel.TOTPFactorState{Enabled: true, Generation: generation}, nil
}

func (s AuthStore) CreateTOTPEnrollment(ctx context.Context, challenge authmodel.AuthProviderChallenge, secret authmodel.TOTPSecret) error {
	ws, provider, stateHash, payload, now, err := s.prepareAuthLoginTransaction(ctx, challenge, time.Time{})
	if err != nil {
		return err
	}
	id := totpFactorID(ws, challenge.UserID)
	plain, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	envelope, err := s.totpSecrets.Encrypt(ctx, ws, id, plain)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A single stable row per user prevents concurrent enrollments from creating
	// two active factors. Replacement of an active binding requires revocation.
	insert, args, err := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", ws).
		Columns("id", "user_id", "factor_type", "label", "provider", "status", "created_at", "updated_at").
		Values(id, challenge.UserID, "totp", "验证码应用", authmodel.TOTPProvider, "pending", now, now).OnConflictDoNothing("workspace_id", "id").Build()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, insert, args...); err != nil {
		return err
	}
	update, args, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", ws).
		Set("totp_secret", envelope).Set("provider_ref", challenge.RequestID).Set("status", "pending").Set("verified_at", nil).
		Set("totp_step", -1).Set("updated_at", now).
		Where(query.And(query.Equal("id", id), query.Equal("user_id", challenge.UserID), query.NotEqual("status", "active"))).Build()
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, update, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return apperror.New(apperror.KindConflict, "auth.totp_already_enabled", nil, nil)
	}
	if err := s.insertAuthLoginTransaction(ctx, tx, ws, provider, stateHash, "", payload, challenge, now); err != nil {
		return err
	}
	return tx.Commit()
}

// verifyTOTPFactor runs inside the challenge-consumption transaction. The
// factor's replay counter and failure budget are shared by every challenge.
func (s AuthStore) verifyTOTPFactor(ctx context.Context, tx *sql.Tx, challenge authmodel.AuthProviderChallenge, code string, now time.Time, maxAttempts int) (bool, error) {
	ws, userID := challenge.WorkspaceID, challenge.UserID
	if userID == "" || challenge.RequestID == "" {
		return false, nil
	}
	id := totpFactorID(ws, userID)
	status := "active"
	if challenge.Purpose == authmodel.TOTPEnrollmentPurpose {
		status = "pending"
	}
	predicate := query.And(query.Equal("id", id), query.Equal("user_id", userID), query.Equal("provider", authmodel.TOTPProvider), query.Equal("status", status), query.Equal("provider_ref", challenge.RequestID))
	statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", ws).
		Columns("totp_secret", "totp_step", "totp_failures", "totp_locked_until").Where(predicate).Build()
	if err != nil {
		return false, err
	}
	var envelope string
	var step int64
	var failures int
	var lockedUntil sql.NullString
	if err := tx.QueryRowContext(ctx, statement, args...).Scan(&envelope, &step, &failures, &lockedUntil); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if lockedUntil.Valid {
		until, err := time.Parse(time.RFC3339, lockedUntil.String)
		if err != nil {
			return false, err
		}
		if until.After(now) {
			return false, nil
		}
	}
	plain, err := s.totpSecrets.Decrypt(ctx, ws, id, envelope)
	if err != nil {
		return false, err
	}
	var secret authmodel.TOTPSecret
	if err := json.Unmarshal(plain, &secret); err != nil {
		return false, err
	}
	matchedStep, valid := authpolicy.MatchTOTP(secret.Secret, code, now, step)
	nextFailures := failures + 1
	if lockedUntil.Valid {
		nextFailures = 1
	}
	update := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", ws).Set("updated_at", now.UTC().Format(time.RFC3339))
	if valid {
		update.Set("totp_step", matchedStep).Set("totp_failures", 0).Set("totp_locked_until", nil).Set("last_used_at", now.UTC().Format(time.RFC3339))
		if challenge.Purpose == authmodel.TOTPEnrollmentPurpose {
			update.Set("status", "active").Set("verified_at", now.UTC().Format(time.RFC3339))
		}
		if challenge.Purpose == authmodel.TOTPDisablePurpose {
			update.Set("status", "disabled").Set("totp_secret", nil)
		}
	} else {
		update.Set("totp_failures", nextFailures)
		if nextFailures >= maxAttempts {
			update.Set("totp_locked_until", now.Add(5*time.Minute).UTC().Format(time.RFC3339))
		} else {
			update.Set("totp_locked_until", nil)
		}
	}
	// Compare all mutable verification state, so concurrent requests cannot
	// reuse a step or lose failed attempts across processes.
	expectedLock := query.IsNull("totp_locked_until")
	if lockedUntil.Valid {
		expectedLock = query.Equal("totp_locked_until", strings.TrimSpace(lockedUntil.String))
	}
	statement, args, err = update.Where(query.And(predicate, query.Equal("totp_step", step), query.Equal("totp_failures", failures), expectedLock)).Build()
	if err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if changed != 1 {
		return false, apperror.New(apperror.KindConflict, "auth.totp_verification_conflict", nil, nil)
	}
	return valid, nil
}
