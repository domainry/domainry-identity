package auth

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type workspaceGuardAuthRepository struct{ calls int }

func (r *workspaceGuardAuthRepository) GetIdentityCredential(context.Context, string, string) (identitymodel.IdentityCredential, bool, error) {
	r.calls++
	return identitymodel.IdentityCredential{}, false, nil
}
func (r *workspaceGuardAuthRepository) UpsertIdentityCredential(context.Context, string, identitymodel.IdentityCredential) error {
	r.calls++
	return nil
}
func (r *workspaceGuardAuthRepository) RecordIdentityLoginSuccess(context.Context, string, string, string) error {
	r.calls++
	return nil
}
func (r *workspaceGuardAuthRepository) CreateAuthRefreshToken(context.Context, string, identitymodel.AuthRefreshToken) error {
	r.calls++
	return nil
}
func (r *workspaceGuardAuthRepository) GetAuthRefreshTokenByHash(context.Context, string, string) (identitymodel.AuthRefreshToken, bool, error) {
	r.calls++
	return identitymodel.AuthRefreshToken{}, false, nil
}
func (r *workspaceGuardAuthRepository) RevokeAuthRefreshToken(context.Context, string, string, string, string) error {
	r.calls++
	return nil
}
func (r *workspaceGuardAuthRepository) ListAuthRefreshTokensForUser(context.Context, string, string) ([]identitymodel.AuthRefreshToken, error) {
	r.calls++
	return nil, nil
}
func (r *workspaceGuardAuthRepository) RevokeAuthRefreshTokensForUser(context.Context, string, string, string) (int, error) {
	r.calls++
	return 0, nil
}
func (r *workspaceGuardAuthRepository) ListIdentityExternalAccounts(context.Context, string, string) ([]identitymodel.IdentityExternalAccount, error) {
	r.calls++
	return nil, nil
}
func (r *workspaceGuardAuthRepository) UpsertIdentityExternalAccount(context.Context, string, identitymodel.IdentityExternalAccount) error {
	r.calls++
	return nil
}
func (r *workspaceGuardAuthRepository) RemoveIdentityExternalAccount(context.Context, string, string) error {
	r.calls++
	return nil
}
func (r *workspaceGuardAuthRepository) TryBeginAuthMutation(context.Context, string, authmodel.AuthMutationClaimRequest) (authmodel.AuthMutationClaimResult, error) {
	r.calls++
	return authmodel.AuthMutationClaimResult{}, nil
}
func (r *workspaceGuardAuthRepository) CompleteAuthMutation(context.Context, string, authmodel.AuthMutationCompletion) (authmodel.AuthMutationReceipt, error) {
	r.calls++
	return authmodel.AuthMutationReceipt{}, nil
}

type workspaceGuardProviderWriter struct{ calls int }

func (writer *workspaceGuardProviderWriter) UpsertAuthProviderCredential(context.Context, string, authmodel.AuthProviderCredentialUpsertRequest, identitymodel.Principal) (authmodel.AuthProviderCredential, error) {
	writer.calls++
	return authmodel.AuthProviderCredential{}, nil
}

func TestAuthApplicationAuthorizesWorkspaceBeforeRepositoryAccess(t *testing.T) {
	repository := &workspaceGuardAuthRepository{}
	service := &AuthApplicationService{repository: repository, mutations: repository, pepper: []byte("pepper")}
	principal := identitymodel.Principal{Known: true, UserID: "user", Role: identitymodel.RoleSchema{Permissions: []string{"identity.security.write"}}}
	for _, call := range []func() error{
		func() error {
			_, err := service.ChangePasswordIdempotent(t.Context(), principal, "key", "old", "new")
			return err
		},
		func() error {
			_, err := service.ResetPasswordIdempotent(t.Context(), principal, "key", "user", "new", false)
			return err
		},
	} {
		if err := call(); err == nil || apperror.KindOf(err) != apperror.KindForbidden {
			t.Fatalf("missing auth workspace was not rejected: %v", err)
		}
	}
	if repository.calls != 0 {
		t.Fatalf("auth repository was called %d times before workspace authorization", repository.calls)
	}

	writer := &workspaceGuardProviderWriter{}
	provider := NewAuthProviderApplicationService([]map[string]any{{"key": "oidc", "type": "oidc"}}, false, writer)
	if _, err := provider.SaveSetup(t.Context(), "oidc", authmodel.AuthProviderCredentialUpsertRequest{}, principal); err == nil || apperror.KindOf(err) != apperror.KindForbidden {
		t.Fatalf("missing provider workspace was not rejected: %v", err)
	}
	if writer.calls != 0 {
		t.Fatalf("provider writer was called %d times before workspace authorization", writer.calls)
	}
}
