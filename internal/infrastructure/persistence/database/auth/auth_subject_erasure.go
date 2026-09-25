package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/domainry/domainry-orm/query"
)

// EraseSubjectLoginArtifacts participates in Identity's subject-erasure
// transaction. Auth owns the encryption keys and interprets its own payloads;
// the privacy orchestrator never receives provider state or session secrets.
func (s AuthStore) EraseSubjectLoginArtifacts(ctx context.Context, tx *sql.Tx, workspaceID, userID, phone string) error {
	if tx == nil || strings.TrimSpace(userID) == "" {
		return fmt.Errorf("subject authentication erasure transaction is required")
	}
	if _, err := authWorkspaceID(workspaceID); err != nil {
		return err
	}
	statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).Columns("state_hash", "payload_json", "subject_key_hash").Build()
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	type challengeKey struct{ state, subject string }
	challenges := []challengeKey{}
	for rows.Next() {
		var state, envelope string
		var subject sql.NullString
		if err := rows.Scan(&state, &envelope, &subject); err != nil {
			rows.Close()
			return err
		}
		raw, err := s.loginSecrets.Decrypt(ctx, workspaceID, state, envelope)
		if err != nil {
			rows.Close()
			return fmt.Errorf("inspect subject login transaction: %w", err)
		}
		challenge, err := unmarshalPersistedAuthProviderChallenge(raw)
		if err != nil {
			rows.Close()
			return err
		}
		if challenge.UserID == userID || strings.TrimSpace(phone) != "" && strings.TrimSpace(challenge.Phone) == strings.TrimSpace(phone) {
			challenges = append(challenges, challengeKey{state: state, subject: subject.String})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, challenge := range challenges {
		statement, args, err := query.NewWorkspaceDeleteBuilder(s.store.SQLRenderer(), "_identity_auth_login_transactions", workspaceID).Where(query.Equal("state_hash", challenge.state)).Build()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, statement, args...); err != nil {
			return err
		}
		if challenge.subject == "" {
			continue
		}
		statement, args, err = query.NewWorkspaceDeleteBuilder(s.store.SQLRenderer(), "_identity_auth_otp_delivery_limits", workspaceID).Where(query.Equal("subject_key_hash", challenge.subject)).Build()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, statement, args...); err != nil {
			return err
		}
	}
	statement, args, err = query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_authorization_codes", workspaceID).Columns("code_hash", "session_json").Build()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	codes := []string{}
	for rows.Next() {
		var code, envelope string
		if err := rows.Scan(&code, &envelope); err != nil {
			rows.Close()
			return err
		}
		raw, err := s.codeSecrets.Decrypt(ctx, workspaceID, code, envelope)
		if err != nil {
			rows.Close()
			return fmt.Errorf("inspect subject authorization code: %w", err)
		}
		session, err := unmarshalPersistedAuthSession(raw)
		if err != nil {
			rows.Close()
			return err
		}
		if session.User.ID == userID {
			codes = append(codes, code)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, code := range codes {
		statement, args, err := query.NewWorkspaceDeleteBuilder(s.store.SQLRenderer(), "_identity_auth_authorization_codes", workspaceID).Where(query.Equal("code_hash", code)).Build()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, statement, args...); err != nil {
			return err
		}
	}
	return nil
}
