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
	"github.com/domainry/domainry-orm/query"
)

type providerSecretPayload struct {
	ClientSecret    string `json:"client_secret,omitempty"`
	VerificationKey string `json:"verification_key,omitempty"`
}

func (s AuthStore) ListAuthProviderCredentials(ctx context.Context, workspaceID string) ([]authmodel.AuthProviderCredential, error) {
	workspaceID, err := authWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, args, buildErr := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_provider_credentials", workspaceID).
		Columns("provider_key", "configuration_json", "secret_envelope", "updated_by", "created_at", "updated_at").OrderBy(query.Ascending("provider_key")).Build()
	if buildErr != nil {
		return nil, buildErr
	}
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []authmodel.AuthProviderCredential{}
	for rows.Next() {
		credential, err := s.scanAuthProviderCredential(ctx, workspaceID, rows)
		if err != nil {
			return nil, err
		}
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
		RedirectURL: strings.TrimSpace(request.RedirectURL), OTPProvider: strings.TrimSpace(request.OTPProvider), AllowedPurposes: append([]string(nil), request.AllowedPurposes...),
		DefaultRoleKey: strings.TrimSpace(request.DefaultRoleKey), RoleMappings: append([]authmodel.AuthProviderRoleMapping(nil), request.RoleMappings...),
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
	secretJSON, _ := json.Marshal(providerSecretPayload{ClientSecret: credential.ClientSecret, VerificationKey: credential.VerificationKey})
	envelope, err := s.secrets.Encrypt(ctx, workspaceID, provider, secretJSON)
	if err != nil {
		return authmodel.AuthProviderCredential{}, fmt.Errorf("encrypt auth provider credential: %w", err)
	}
	insert := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), "_identity_auth_provider_credentials", workspaceID).
		Columns("provider_key", "configuration_json", "secret_envelope", "updated_by", "created_at", "updated_at").
		Values(provider, string(configuration), envelope, credential.UpdatedBy, credential.CreatedAt, credential.UpdatedAt)
	insert.OnConflictDoUpdate([]string{"workspace_id", "provider_key"},
		query.AssignExpression("configuration_json", query.InsertedValue("configuration_json")),
		query.AssignExpression("secret_envelope", query.InsertedValue("secret_envelope")),
		query.AssignExpression("updated_by", query.InsertedValue("updated_by")),
		query.AssignExpression("created_at", query.InsertedValue("created_at")),
		query.AssignExpression("updated_at", query.InsertedValue("updated_at")),
	)
	statement, args, buildErr := insert.Build()
	if buildErr != nil {
		return authmodel.AuthProviderCredential{}, buildErr
	}
	if _, err := s.db.ExecContext(ctx, statement, args...); err != nil {
		return authmodel.AuthProviderCredential{}, err
	}
	return credential, nil
}

func (s AuthStore) authProviderCredential(ctx context.Context, workspaceID, provider string) (authmodel.AuthProviderCredential, bool, error) {
	statement, args, buildErr := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_auth_provider_credentials", workspaceID).
		Columns("provider_key", "configuration_json", "secret_envelope", "updated_by", "created_at", "updated_at").
		Where(query.Equal("provider_key", provider)).Limit(1).Build()
	if buildErr != nil {
		return authmodel.AuthProviderCredential{}, false, buildErr
	}
	credential, err := s.scanAuthProviderCredential(ctx, workspaceID, s.db.QueryRowContext(ctx, statement, args...))
	if err == sql.ErrNoRows {
		return authmodel.AuthProviderCredential{}, false, nil
	}
	return credential, err == nil, err
}

type authProviderCredentialScanner interface{ Scan(...any) error }

func (s AuthStore) scanAuthProviderCredential(ctx context.Context, workspaceID string, scanner authProviderCredentialScanner) (authmodel.AuthProviderCredential, error) {
	var credential authmodel.AuthProviderCredential
	var configuration, envelope string
	if err := scanner.Scan(&credential.ProviderKey, &configuration, &envelope, &credential.UpdatedBy, &credential.CreatedAt, &credential.UpdatedAt); err != nil {
		return credential, err
	}
	if err := json.Unmarshal([]byte(configuration), &credential); err != nil {
		return credential, fmt.Errorf("decode auth provider credential %q: %w", credential.ProviderKey, err)
	}
	credential.WorkspaceID = workspaceID
	plain, err := s.secrets.Decrypt(ctx, workspaceID, credential.ProviderKey, envelope)
	if err != nil {
		return credential, fmt.Errorf("decrypt auth provider credential %q: %w", credential.ProviderKey, err)
	}
	var secret providerSecretPayload
	if err := json.Unmarshal(plain, &secret); err != nil {
		return credential, fmt.Errorf("decode auth provider secret %q: %w", credential.ProviderKey, err)
	}
	credential.ClientSecret, credential.VerificationKey = secret.ClientSecret, secret.VerificationKey
	return credential, nil
}
