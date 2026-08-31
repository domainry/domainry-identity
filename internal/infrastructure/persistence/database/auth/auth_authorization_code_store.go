package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	"github.com/domainry/domainry-orm/query"
)

func authAuthorizationCodeHash(code string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s AuthStore) CreateAuthAuthorizationCode(ctx context.Context, value authmodel.AuthAuthorizationCode) error {
	workspaceID, err := authWorkspaceID(value.WorkspaceID)
	if err != nil {
		return err
	}
	codeHash := authAuthorizationCodeHash(value.Code)
	sessionJSON, err := json.Marshal(value.Session)
	if err != nil {
		return err
	}
	envelope, err := s.codeSecrets.Encrypt(ctx, workspaceID, codeHash, sessionJSON)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	statement, args, buildErr := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_auth_authorization_codes", workspaceID).
		Columns("code_hash", "application_key", "session_json", "redirect_url", "expires_at", "consumed_at", "created_at").
		Values(codeHash, strings.TrimSpace(value.ApplicationKey), envelope, strings.TrimSpace(value.RedirectURL), value.ExpiresAt, nil, valueOrNow(value.CreatedAt, now)).Build()
	if buildErr != nil {
		return buildErr
	}
	_, err = s.db.ExecContext(ctx, statement, args...)
	return err
}

func (s AuthStore) ConsumeAuthAuthorizationCode(ctx context.Context, workspaceID, code, applicationKey, redirectURL string, now time.Time) (authmodel.AuthSession, bool, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return authmodel.AuthSession{}, false, err
	}
	code = strings.TrimSpace(code)
	codeHash := authAuthorizationCodeHash(code)
	applicationKey, redirectURL = strings.TrimSpace(applicationKey), strings.TrimSpace(redirectURL)
	if code == "" || applicationKey == "" || redirectURL == "" {
		return authmodel.AuthSession{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowText := now.UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authmodel.AuthSession{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	updateStatement, updateArgs, buildErr := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_authorization_codes", workspaceID).
		Set("consumed_at", nowText).Where(query.And(
		query.Equal("code_hash", codeHash), query.Equal("application_key", applicationKey), query.Equal("redirect_url", redirectURL),
		query.IsNull("consumed_at"), query.GreaterThan("expires_at", nowText),
	)).Build()
	if buildErr != nil {
		return authmodel.AuthSession{}, false, buildErr
	}
	result, err := tx.ExecContext(ctx, updateStatement, updateArgs...)
	if err != nil {
		return authmodel.AuthSession{}, false, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return authmodel.AuthSession{}, false, err
	}
	selectStatement, selectArgs, buildErr := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_authorization_codes", workspaceID).
		Columns("session_json").Where(query.Equal("code_hash", codeHash)).Limit(1).Build()
	if buildErr != nil {
		return authmodel.AuthSession{}, false, buildErr
	}
	var envelope string
	if err := tx.QueryRowContext(ctx, selectStatement, selectArgs...).Scan(&envelope); err != nil {
		return authmodel.AuthSession{}, false, err
	}
	plain, err := s.codeSecrets.Decrypt(ctx, workspaceID, codeHash, envelope)
	if err != nil {
		return authmodel.AuthSession{}, false, err
	}
	var session authmodel.AuthSession
	if err := json.Unmarshal(plain, &session); err != nil {
		return authmodel.AuthSession{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return authmodel.AuthSession{}, false, err
	}
	return session, true, nil
}
