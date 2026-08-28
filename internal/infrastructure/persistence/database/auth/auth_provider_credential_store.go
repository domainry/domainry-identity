package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type providerSecretPayload struct {
	ClientSecret    string `json:"client_secret,omitempty"`
	VerificationKey string `json:"verification_key,omitempty"`
	AccessToken     string `json:"access_token,omitempty"`
}

func (s AuthStore) ListAuthProviderCredentials(ctx context.Context, workspaceID string) ([]authmodel.AuthProviderCredential, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.store.IdentityColumns("provider_key", "configuration_json", "secret_envelope", "updated_by", "created_at", "updated_at")+" FROM "+s.store.TableIdentifier("auth_provider_credentials")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" ORDER BY "+s.store.Identifier("provider_key"), workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []authmodel.AuthProviderCredential{}
	for rows.Next() {
		var credential authmodel.AuthProviderCredential
		var configuration, envelope string
		if err := rows.Scan(&credential.ProviderKey, &configuration, &envelope, &credential.UpdatedBy, &credential.CreatedAt, &credential.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(configuration), &credential); err != nil {
			return nil, fmt.Errorf("decode auth provider credential %q: %w", credential.ProviderKey, err)
		}
		credential.WorkspaceID = workspaceID
		plain, err := s.secrets.Decrypt(ctx, workspaceID, credential.ProviderKey, envelope)
		if err != nil {
			return nil, fmt.Errorf("decrypt auth provider credential %q: %w", credential.ProviderKey, err)
		}
		var secret providerSecretPayload
		if err := json.Unmarshal(plain, &secret); err != nil {
			return nil, fmt.Errorf("decode auth provider secret %q: %w", credential.ProviderKey, err)
		}
		credential.ClientSecret, credential.VerificationKey, credential.AccessToken = secret.ClientSecret, secret.VerificationKey, secret.AccessToken
		result = append(result, credential)
	}
	return result, rows.Err()
}

func (s AuthStore) UpsertAuthProviderCredential(ctx context.Context, provider string, request authmodel.AuthProviderCredentialUpsertRequest, principal identitymodel.Principal) (authmodel.AuthProviderCredential, error) {
	workspaceID, err := authWorkspaceID(principal.WorkspaceID)
	provider = strings.ToLower(strings.TrimSpace(provider))
	if err != nil || provider == "" {
		return authmodel.AuthProviderCredential{}, fmt.Errorf("workspace and provider are required")
	}
	credential := authmodel.AuthProviderCredential{
		ProviderKey: provider, Label: strings.TrimSpace(request.Label), ConnectionKey: strings.TrimSpace(request.ConnectionKey), WorkspaceID: workspaceID,
		Type: strings.TrimSpace(request.Type), Adapter: strings.TrimSpace(request.Adapter), Issuer: strings.TrimSpace(request.Issuer), AuthURL: strings.TrimSpace(request.AuthURL),
		TokenURL: strings.TrimSpace(request.TokenURL), UserInfoURL: strings.TrimSpace(request.UserInfoURL), Scope: strings.TrimSpace(request.Scope),
		ListUsersURL: strings.TrimSpace(request.ListUsersURL), ClientID: strings.TrimSpace(request.ClientID), ClientSecret: strings.TrimSpace(request.ClientSecret), VerificationKey: strings.TrimSpace(request.VerificationKey),
		RedirectURL: strings.TrimSpace(request.RedirectURL), OTPProvider: strings.TrimSpace(request.OTPProvider), AccessToken: strings.TrimSpace(request.AccessToken),
		PhoneNumberID: strings.TrimSpace(request.PhoneNumberID), DefaultRoleKey: strings.TrimSpace(request.DefaultRoleKey), RoleMappings: append([]authmodel.AuthProviderRoleMapping(nil), request.RoleMappings...),
		UpdatedBy: strings.TrimSpace(principal.UserID),
	}
	if request.AutoCreateUsers != nil {
		credential.AutoCreateUsers = *request.AutoCreateUsers
	}
	current, found, err := s.authProviderCredential(ctx, workspaceID, provider)
	if err != nil {
		return authmodel.AuthProviderCredential{}, err
	}
	if found {
		credential.CreatedAt = current.CreatedAt
		if credential.ClientSecret == "" {
			credential.ClientSecret = current.ClientSecret
		}
		if credential.VerificationKey == "" {
			credential.VerificationKey = current.VerificationKey
		}
		if credential.AccessToken == "" {
			credential.AccessToken = current.AccessToken
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if credential.CreatedAt == "" {
		credential.CreatedAt = now
	}
	credential.UpdatedAt = now
	configuration, err := json.Marshal(credential)
	if err != nil {
		return authmodel.AuthProviderCredential{}, err
	}
	secretJSON, _ := json.Marshal(providerSecretPayload{ClientSecret: credential.ClientSecret, VerificationKey: credential.VerificationKey, AccessToken: credential.AccessToken})
	envelope, err := s.secrets.Encrypt(ctx, workspaceID, provider, secretJSON)
	if err != nil {
		return authmodel.AuthProviderCredential{}, fmt.Errorf("encrypt auth provider credential: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authmodel.AuthProviderCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.store.TableIdentifier("auth_provider_credentials")+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("provider_key")+" = "+s.store.Placeholder(2), workspaceID, provider); err != nil {
		return authmodel.AuthProviderCredential{}, err
	}
	query := "INSERT INTO " + s.store.TableIdentifier("auth_provider_credentials") + " (" + s.store.IdentityColumns("workspace_id", "provider_key", "configuration_json", "secret_envelope", "updated_by", "created_at", "updated_at") + ") VALUES (" + s.store.Placeholders(7) + ")"
	if _, err := tx.ExecContext(ctx, query, workspaceID, provider, string(configuration), envelope, credential.UpdatedBy, credential.CreatedAt, credential.UpdatedAt); err != nil {
		return authmodel.AuthProviderCredential{}, err
	}
	if err := tx.Commit(); err != nil {
		return authmodel.AuthProviderCredential{}, err
	}
	return credential, nil
}

func (s AuthStore) authProviderCredential(ctx context.Context, workspaceID, provider string) (authmodel.AuthProviderCredential, bool, error) {
	values, err := s.ListAuthProviderCredentials(ctx, workspaceID)
	if err != nil && err != sql.ErrNoRows {
		return authmodel.AuthProviderCredential{}, false, err
	}
	for _, value := range values {
		if value.ProviderKey == provider {
			return value, true, nil
		}
	}
	return authmodel.AuthProviderCredential{}, false, nil
}
