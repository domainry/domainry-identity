package auth

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type authProviderEdgeWriter struct {
	credential authmodel.AuthProviderCredential
	err        error
	request    authmodel.AuthProviderCredentialUpsertRequest
	provider   string
	calls      int
	onCall     func()
}

func (w *authProviderEdgeWriter) UpsertAuthProviderCredential(_ context.Context, provider string, request authmodel.AuthProviderCredentialUpsertRequest, _ identitymodel.Principal) (authmodel.AuthProviderCredential, error) {
	w.calls++
	w.provider, w.request = provider, request
	if w.onCall != nil {
		w.onCall()
	}
	return w.credential, w.err
}

func TestAuthProviderSaveSetupEdges(t *testing.T) {
	config := map[string]any{"key": "oidc", "type": "oidc", "issuer": "issuer", "auth_url": "auth", "token_url": "token", "userinfo_url": "user-info", "scope": "openid", "redirect_url": "redirect"}
	principal := authMutationPrincipal()
	invalidWorkspace := principal
	invalidWorkspace.WorkspaceID = " "
	if _, err := NewAuthProviderApplicationService([]map[string]any{config}, false).SaveSetup(t.Context(), "oidc", authmodel.AuthProviderCredentialUpsertRequest{}, invalidWorkspace); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("invalid workspace error=%v", err)
	}
	nonAdmin := principal
	nonAdmin.Role.Permissions = nil
	if _, err := NewAuthProviderApplicationService([]map[string]any{config}, false).SaveSetup(t.Context(), "oidc", authmodel.AuthProviderCredentialUpsertRequest{}, nonAdmin); apperror.CodeOf(err) != "auth.permission_denied" {
		t.Fatalf("non-admin error=%v", err)
	}
	if _, err := NewAuthProviderApplicationService([]map[string]any{config}, false).SaveSetup(t.Context(), "oidc", authmodel.AuthProviderCredentialUpsertRequest{}, identitymodel.Principal{}); apperror.CodeOf(err) != "auth.token_required" {
		t.Fatalf("unknown principal error=%v", err)
	}
	if _, err := NewAuthProviderApplicationService([]map[string]any{config}, false).SaveSetup(t.Context(), "oidc", authmodel.AuthProviderCredentialUpsertRequest{}, principal); apperror.CodeOf(err) != "auth.provider_credential_writer_not_configured" {
		t.Fatalf("missing writer error=%v", err)
	}
	writer := &authProviderEdgeWriter{err: errors.New("write failed")}
	service := NewAuthProviderApplicationService([]map[string]any{config}, false, writer)
	if _, err := service.SaveSetup(t.Context(), "missing", authmodel.AuthProviderCredentialUpsertRequest{}, principal); apperror.CodeOf(err) != "auth.provider_unknown" {
		t.Fatalf("unknown provider error=%v", err)
	}
	writer.err = nil
	writer.credential = authmodel.AuthProviderCredential{ProviderKey: "partner_oidc", Type: "oidc", Issuer: "https://id.example", AuthURL: "https://id.example/authorize", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app.example/callback"}
	custom, err := service.SaveSetup(t.Context(), "partner_oidc", authmodel.AuthProviderCredentialUpsertRequest{Type: "oidc", Issuer: "https://id.example", AuthURL: "https://id.example/authorize", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app.example/callback"}, principal)
	if err != nil || !custom.Enabled || custom.Key != "partner_oidc" {
		t.Fatalf("custom provider=%+v err=%v", custom, err)
	}
	if _, ok := service.Find(t.Context(), "partner_oidc"); !ok {
		t.Fatal("custom provider was not made effective")
	}
	writer.err = errors.New("write failed")
	if _, err := service.SaveSetup(t.Context(), "oidc", authmodel.AuthProviderCredentialUpsertRequest{}, principal); !errors.Is(err, writer.err) {
		t.Fatalf("writer error=%v", err)
	}
	if writer.request.Type != "oidc" || writer.request.Issuer != "issuer" || writer.request.AuthURL != "auth" || writer.request.TokenURL != "token" || writer.request.UserInfoURL != "user-info" || writer.request.Scope != "openid" || writer.request.RedirectURL != "redirect" {
		t.Fatalf("defaults not applied: %+v", writer.request)
	}

	writer.err = nil
	writer.credential = authmodel.AuthProviderCredential{ProviderKey: "oidc", Type: "oidc", ClientID: "client", ClientSecret: "secret", RedirectURL: "redirect", AutoCreateUsers: true, DefaultRoleKey: "operator", RoleMappings: []authmodel.AuthProviderRoleMapping{{Claim: "groups", Match: "ops", RoleKey: "operator"}}, UpdatedAt: "now"}
	updated, err := service.SaveSetup(t.Context(), "OIDC", authmodel.AuthProviderCredentialUpsertRequest{Type: "oidc", Issuer: "custom-issuer"}, principal)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Enabled || updated.ClientID != "client" || !updated.ClientSecretConfigured || updated.ConfiguredFrom != "setup" || len(updated.RoleMappings) != 1 {
		t.Fatalf("updated=%+v", updated)
	}
	if writer.request.Type != "oidc" || writer.request.Issuer != "custom-issuer" {
		t.Fatalf("explicit request overwritten: %+v", writer.request)
	}
	if _, err := service.SaveSetup(t.Context(), "oidc", authmodel.AuthProviderCredentialUpsertRequest{Type: "custom"}, principal); apperror.CodeOf(err) != "auth.provider_type_change_not_allowed" {
		t.Fatalf("unsupported provider type error=%v", err)
	}
	explicit := authmodel.AuthProviderCredentialUpsertRequest{Type: "oidc", Issuer: "i", AuthURL: "a", TokenURL: "t", UserInfoURL: "u", Scope: "s", RedirectURL: "r"}
	if _, err := service.SaveSetup(t.Context(), "oidc", explicit, principal); err != nil || !reflect.DeepEqual(writer.request, explicit) {
		t.Fatalf("explicit request=%+v err=%v", writer.request, err)
	}
	writer.onCall = func() { service.AuthProviderDomainService = authdomain.NewAuthProviderDomainService(nil, false) }
	if _, err := service.SaveSetup(t.Context(), "oidc", explicit, principal); apperror.CodeOf(err) != "auth.provider_unknown" {
		t.Fatalf("provider replacement race error=%v", err)
	}
}

func TestAuthProviderCredentialProjectionEdges(t *testing.T) {
	otp := NewAuthProviderApplicationService([]map[string]any{{"key": "otp", "type": "otp"}}, false)
	config, _ := otp.Find(t.Context(), "otp")
	authProviderApplyCredential(&config, authmodel.AuthProviderCredential{Type: "otp", OTPProvider: "whatsapp", AccessToken: "token", PhoneNumberID: "phone", RoleMappings: []authmodel.AuthProviderRoleMapping{{Claim: "team", Match: "support", RoleKey: "agent"}}})
	if !config.Enabled || !config.AccessTokenConfigured || !config.PhoneNumberIDConfigured || len(config.RoleMappings) != 1 {
		t.Fatalf("otp config=%+v", config)
	}

	merged := MergeTypedAuthProviderCredentials([]map[string]any{{"key": "OIDC", "type": "oidc"}, {"key": "local", "type": "password"}}, []authmodel.AuthProviderCredential{{ProviderKey: " oidc ", Type: "oidc", Issuer: "https://id.example", AuthURL: "https://id.example/authorize", ClientID: "client", ClientSecret: "secret", RedirectURL: "redirect"}})
	if len(merged) != 2 || merged[0]["enabled"] != true || merged[1]["enabled"] != false {
		t.Fatalf("merged=%#v", merged)
	}

	if NewAuthProviderFlowApplicationService(nil, nil).AuthProviderFlowDomainService == nil {
		t.Fatal("nil-owner provider flow was not constructed")
	}
	authService := &AuthApplicationService{}
	providerService := NewAuthProviderApplicationService(nil, false)
	if NewAuthProviderFlowApplicationService(authService, providerService).AuthProviderFlowDomainService == nil {
		t.Fatal("provider flow owners were not wired")
	}
}

func TestLINEProviderCanSelectLIFFTokenExchangeWithoutClientSecret(t *testing.T) {
	writer := &authProviderEdgeWriter{credential: authmodel.AuthProviderCredential{
		ProviderKey: "line", Type: "code_exchange", Adapter: "line_liff", ClientID: "channel-id", AutoCreateUsers: true, DefaultRoleKey: "member_onboarding",
	}}
	service := NewAuthProviderApplicationService([]map[string]any{{"key": "line", "type": "oidc"}}, false, writer)
	config, err := service.SaveSetup(t.Context(), "line", authmodel.AuthProviderCredentialUpsertRequest{
		Type: "code_exchange", Adapter: "line_liff", ClientID: "channel-id", AutoCreateUsers: boolPointer(true), DefaultRoleKey: "member_onboarding",
	}, authMutationPrincipal())
	if err != nil || !config.Enabled || config.ClientID != "channel-id" || config.ClientSecretConfigured || config.DefaultRoleKey != "member_onboarding" {
		t.Fatalf("LINE LIFF config=%+v err=%v", config, err)
	}
}

func boolPointer(value bool) *bool { return &value }
