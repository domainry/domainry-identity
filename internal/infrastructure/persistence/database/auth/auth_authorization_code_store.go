package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
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
	_, err = s.db.ExecContext(ctx, "INSERT INTO "+s.store.TableIdentifier("auth_authorization_codes")+" ("+s.store.IdentityColumns("code_hash", "workspace_id", "application_key", "session_json", "redirect_url", "expires_at", "consumed_at", "created_at")+") VALUES ("+s.store.Placeholders(8)+")", codeHash, workspaceID, strings.TrimSpace(value.ApplicationKey), envelope, strings.TrimSpace(value.RedirectURL), value.ExpiresAt, nil, valueOrNow(value.CreatedAt, now))
	return err
}

func (s AuthStore) ConsumeAuthAuthorizationCode(ctx context.Context, code, applicationKey, redirectURL string, now time.Time) (authmodel.AuthSession, bool, error) {
	codeHash := authAuthorizationCodeHash(code)
	applicationKey, redirectURL = strings.TrimSpace(applicationKey), strings.TrimSpace(redirectURL)
	if codeHash == "" || applicationKey == "" || redirectURL == "" {
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
	result, err := tx.ExecContext(ctx, "UPDATE "+s.store.TableIdentifier("auth_authorization_codes")+" SET "+s.store.Identifier("consumed_at")+" = "+s.store.Placeholder(1)+" WHERE "+s.store.Identifier("code_hash")+" = "+s.store.Placeholder(2)+" AND "+s.store.Identifier("application_key")+" = "+s.store.Placeholder(3)+" AND "+s.store.Identifier("redirect_url")+" = "+s.store.Placeholder(4)+" AND "+s.store.Identifier("consumed_at")+" IS NULL AND "+s.store.Identifier("expires_at")+" > "+s.store.Placeholder(5), nowText, codeHash, applicationKey, redirectURL, nowText)
	if err != nil {
		return authmodel.AuthSession{}, false, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return authmodel.AuthSession{}, false, err
	}
	var workspaceID, envelope string
	if err := tx.QueryRowContext(ctx, "SELECT "+s.store.IdentityColumns("workspace_id", "session_json")+" FROM "+s.store.TableIdentifier("auth_authorization_codes")+" WHERE "+s.store.Identifier("code_hash")+" = "+s.store.Placeholder(1), codeHash).Scan(&workspaceID, &envelope); err != nil {
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
