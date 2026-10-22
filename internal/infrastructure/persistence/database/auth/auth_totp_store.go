package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/entityid"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	"github.com/domainry/domainry-orm/query"
)

func (s AuthStore) TOTPFactorState(ctx context.Context, workspaceID, userID string) (authmodel.TOTPFactorState, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.TOTPFactorState{}, err
	}
	statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", workspaceID).
		Columns("mfa_factor_id", "totp_secret", "provider_ref").Where(query.And(query.Equal("user_id", userID), query.Equal("factor_type", "totp"), query.Equal("provider", authmodel.TOTPProvider), query.Equal("status", "active"), query.NotEqual("verified_at", int64(0)))).Build()
	if err != nil {
		return authmodel.TOTPFactorState{}, err
	}
	var factorID, envelope, generation string
	if err := s.db.QueryRowContext(ctx, statement, args...).Scan(&factorID, &envelope, &generation); err != nil {
		if err == sql.ErrNoRows {
			return authmodel.TOTPFactorState{}, nil
		}
		return authmodel.TOTPFactorState{}, err
	}
	plain, err := s.totpSecrets.Decrypt(ctx, workspaceID, factorID, envelope)
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
	candidateID, err := entityid.New("mfa")
	if err != nil {
		return err
	}
	plain, err := json.Marshal(secret)
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
		Columns("mfa_factor_id", "user_id", "factor_type", "label", "provider", "status", "created_at", "updated_at").
		Values(candidateID, challenge.UserID, "totp", "验证码应用", authmodel.TOTPProvider, "pending", now, now).
		OnConflictDoNothing("workspace_id", "user_id", "factor_type", "provider").Build()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, insert, args...); err != nil {
		return err
	}
	lookup, lookupArgs, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", ws).
		Columns("mfa_factor_id").Where(query.And(query.Equal("user_id", challenge.UserID), query.Equal("factor_type", "totp"), query.Equal("provider", authmodel.TOTPProvider))).Limit(1).Build()
	if err != nil {
		return err
	}
	var factorID string
	if err := tx.QueryRowContext(ctx, lookup, lookupArgs...).Scan(&factorID); err != nil {
		return err
	}
	envelope, err := s.totpSecrets.Encrypt(ctx, ws, factorID, plain)
	if err != nil {
		return err
	}
	update, args, err := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", ws).
		Set("totp_secret", envelope).Set("provider_ref", challenge.RequestID).Set("status", "pending").Set("verified_at", int64(0)).
		Set("totp_step", -1).Set("updated_at", now).
		Where(query.And(query.Equal("mfa_factor_id", factorID), query.Equal("user_id", challenge.UserID), query.NotEqual("status", "active"))).Build()
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
	status := "active"
	if challenge.Purpose == authmodel.TOTPEnrollmentPurpose {
		status = "pending"
	}
	predicate := query.And(query.Equal("user_id", userID), query.Equal("factor_type", "totp"), query.Equal("provider", authmodel.TOTPProvider), query.Equal("status", status), query.Equal("provider_ref", challenge.RequestID))
	statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", ws).
		Columns("mfa_factor_id", "totp_secret", "totp_step", "totp_failures", "totp_locked_until").Where(predicate).Build()
	if err != nil {
		return false, err
	}
	var factorID, envelope string
	var step int64
	var failures int
	var lockedUntil int64
	if err := tx.QueryRowContext(ctx, statement, args...).Scan(&factorID, &envelope, &step, &failures, &lockedUntil); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if lockedUntil != 0 {
		if time.UnixMilli(lockedUntil).After(now) {
			return false, nil
		}
	}
	plain, err := s.totpSecrets.Decrypt(ctx, ws, factorID, envelope)
	if err != nil {
		return false, err
	}
	var secret authmodel.TOTPSecret
	if err := json.Unmarshal(plain, &secret); err != nil {
		return false, err
	}
	matchedStep, valid := authpolicy.MatchTOTP(secret.Secret, code, now, step)
	nextFailures := failures + 1
	if lockedUntil != 0 {
		nextFailures = 1
	}
	update := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_mfa_factors", ws).Set("updated_at", now.UTC().UnixMilli())
	if valid {
		update.Set("totp_step", matchedStep).Set("totp_failures", 0).Set("totp_locked_until", int64(0)).Set("last_used_at", now.UTC().UnixMilli())
		if challenge.Purpose == authmodel.TOTPEnrollmentPurpose {
			update.Set("status", "active").Set("verified_at", now.UTC().UnixMilli())
		}
		if challenge.Purpose == authmodel.TOTPDisablePurpose {
			update.Set("status", "disabled").Set("totp_secret", nil)
		}
	} else {
		update.Set("totp_failures", nextFailures)
		if nextFailures >= maxAttempts {
			update.Set("totp_locked_until", now.Add(5*time.Minute).UTC().UnixMilli())
		} else {
			update.Set("totp_locked_until", int64(0))
		}
	}
	// Compare all mutable verification state, so concurrent requests cannot
	// reuse a step or lose failed attempts across processes.
	expectedLock := query.Equal("totp_locked_until", lockedUntil)
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
