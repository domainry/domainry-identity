package identity_test

import (
	"context"
	"strings"
	"testing"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitybusiness "github.com/domainry/domainry-identity/internal/domain/identity/service"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestExternalLoginCreatesLinksAndReusesIdentity(t *testing.T) {
	auth, identity, _ := newExternalAuthFixture(t)
	ctx := t.Context()

	if _, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "oidc"}, true); err == nil {
		t.Fatal("expected missing provider subject to be rejected")
	}
	if _, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Subject: "subject"}, true); err == nil {
		t.Fatal("expected missing provider to be rejected")
	}
	if _, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "unlinked"}, false); err == nil {
		t.Fatal("expected disabled automatic creation to reject an unlinked account")
	}

	assertion := authmodel.AuthExternalIdentityAssertion{
		Provider:    " OIDC ",
		Subject:     " Sales.User/01 ",
		Email:       " sales.user@example.com ",
		Phone:       " +86-10086 ",
		DisplayName: " Sales User ",
		AvatarURL:   " https://example.com/avatar.png ",
		Metadata:    " {\"tenant\":\"example\"} ",
		Claims:      map[string]string{"org_id": "dept_sales", "organization_path": "/sales", "group": "seller"},
	}
	policy := authmodel.AuthExternalLoginPolicy{
		AutoCreateUsers: true,
		DefaultRoleKey:  "sales",
		RoleMappings: []authmodel.AuthExternalRoleMapping{
			{Claim: "", Match: "seller", RoleKey: "sales"},
			{Claim: "group", Match: "missing", RoleKey: "missing"},
			{Claim: "group", Match: "seller", RoleKey: "admin"},
			{Claim: "email_domain", Match: "example.com", RoleKey: "sales"},
		},
	}
	session, err := auth.ExternalLoginWithPolicy(ctx, "workspace-primary", assertion, policy)
	if err != nil {
		t.Fatalf("create external identity user: %v", err)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Fatalf("expected issued session tokens, got %#v", session)
	}
	if session.User.Name != "Sales User" || session.User.Email != "sales.user@example.com" {
		t.Fatalf("unexpected external user projection: %#v", session.User)
	}
	if session.DefaultRole != "sales" {
		t.Fatalf("expected non-privileged mapped role, got %#v", session.Roles)
	}

	accounts, err := auth.ListExternalAccounts(ctx, "workspace-primary", session.User.ID)
	if err != nil {
		t.Fatalf("list linked external accounts: %v", err)
	}
	if len(accounts) != 1 || accounts[0].Provider != "oidc" || accounts[0].ProviderSubject != "Sales.User/01" {
		t.Fatalf("unexpected linked accounts: %#v", accounts)
	}

	reused, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "OIDC", Subject: "Sales.User/01"}, false)
	if err != nil {
		t.Fatalf("reuse linked external identity: %v", err)
	}
	if reused.User.ID != session.User.ID {
		t.Fatalf("expected linked identity %q, got %q", session.User.ID, reused.User.ID)
	}

	user, ok, err := identity.UserByID(ctx, session.User.ID)
	if err != nil || !ok {
		t.Fatalf("load created external user: ok=%v err=%v", ok, err)
	}
	user.Status = identitymodel.IdentityStatusDisabled
	if err := identity.UpsertUser(ctx, user); err != nil {
		t.Fatalf("disable external user: %v", err)
	}
	if _, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "Sales.User/01"}, false); err == nil {
		t.Fatal("expected disabled linked user to be rejected")
	}
}

func TestExternalLoginLinksVerifiedEmailAndAppliesSafeRoleFallback(t *testing.T) {
	auth, identity, _ := newExternalAuthFixture(t)
	ctx := t.Context()
	if err := identity.UpsertUser(ctx, identitymodel.IdentityUser{
		ID: "existing-user", Name: "Existing", Email: "existing@example.com", Status: identitymodel.IdentityStatusActive,
	}); err != nil {
		t.Fatalf("seed existing user: %v", err)
	}

	session, err := auth.ExternalLoginWithPolicy(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{
		Provider: "saml", Subject: "existing-subject", Email: " existing@example.com ",
	}, authmodel.AuthExternalLoginPolicy{AutoCreateUsers: true, DefaultRoleKey: "admin"})
	if err != nil {
		t.Fatalf("link existing user by email: %v", err)
	}
	if session.User.ID != "existing-user" {
		t.Fatalf("expected existing user link, got %#v", session.User)
	}
	if session.DefaultRole == "admin" {
		t.Fatalf("privileged default role must not be assigned automatically: %#v", session.Roles)
	}

	if err := identity.UpsertUser(ctx, identitymodel.IdentityUser{
		ID: "disabled-email", Name: "Disabled", Email: "disabled@example.com", Status: identitymodel.IdentityStatusDisabled,
	}); err != nil {
		t.Fatalf("seed disabled user: %v", err)
	}
	if _, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{
		Provider: "saml", Subject: "disabled-subject", Email: "disabled@example.com",
	}, true); err == nil {
		t.Fatal("expected disabled email identity to be rejected")
	}
}

func TestExternalAccountBindingLifecycleAndConflicts(t *testing.T) {
	auth, identity, _ := newExternalAuthFixture(t)
	ctx := t.Context()
	for _, user := range []identitymodel.IdentityUser{
		{ID: "user-a", Name: "User A", Email: "a@example.com", Status: identitymodel.IdentityStatusActive},
		{ID: "user-b", Name: "User B", Email: "b@example.com", Status: identitymodel.IdentityStatusActive},
	} {
		if err := identity.UpsertUser(ctx, user); err != nil {
			t.Fatalf("seed user %s: %v", user.ID, err)
		}
	}

	invalidAssertions := []struct {
		userID    string
		assertion authmodel.AuthExternalIdentityAssertion
	}{
		{"", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}},
		{"user-a", authmodel.AuthExternalIdentityAssertion{Subject: "subject"}},
		{"user-a", authmodel.AuthExternalIdentityAssertion{Provider: "oidc"}},
	}
	for _, testCase := range invalidAssertions {
		if _, err := auth.BindExternalAccount(ctx, "workspace-primary", testCase.userID, testCase.assertion); err == nil {
			t.Fatalf("expected invalid binding to fail: %#v", testCase)
		}
	}
	if _, err := auth.BindExternalAccount(ctx, "workspace-primary", "missing", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}); err == nil {
		t.Fatal("expected binding for missing user to fail")
	}

	account, err := auth.BindExternalAccount(ctx, "workspace-primary", "user-a", authmodel.AuthExternalIdentityAssertion{
		Provider: " OIDC ", Subject: " subject ", DisplayName: " User A ",
	})
	if err != nil {
		t.Fatalf("bind external account: %v", err)
	}
	if _, err := auth.BindExternalAccount(ctx, "workspace-primary", "user-a", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}); err != nil {
		t.Fatalf("rebinding the same provider subject to the same user should be idempotent: %v", err)
	}
	if _, err := auth.BindExternalAccount(ctx, "workspace-primary", "user-b", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}); err == nil {
		t.Fatal("expected provider subject binding conflict")
	}
	if err := auth.UnbindExternalAccount(ctx, "workspace-primary", "user-a", "oidc", "missing"); err == nil {
		t.Fatal("expected missing account unbind to fail")
	}
	if err := auth.UnbindExternalAccount(ctx, "workspace-primary", "", "oidc", account.ID); err == nil {
		t.Fatal("expected invalid unbind request to fail")
	}
	if err := auth.UnbindExternalAccount(ctx, "workspace-primary", "user-a", "", account.ID); err == nil {
		t.Fatal("expected blank unbind provider to fail")
	}
	if err := auth.UnbindExternalAccount(ctx, "workspace-primary", "user-a", "oidc", ""); err == nil {
		t.Fatal("expected blank unbind account id to fail")
	}
	if err := auth.UnbindExternalAccount(ctx, "workspace-primary", "user-a", "saml", account.ID); err == nil {
		t.Fatal("expected mismatched provider unbind to fail")
	}
	if err := auth.UnbindExternalAccount(ctx, "workspace-primary", "user-a", "OIDC", account.ID); err != nil {
		t.Fatalf("unbind external account: %v", err)
	}
	accounts, err := auth.ListExternalAccounts(ctx, "workspace-primary", "user-a")
	if err != nil || len(accounts) != 0 {
		t.Fatalf("expected binding removal, accounts=%#v err=%v", accounts, err)
	}
	if _, err := auth.ListExternalAccounts(ctx, "workspace-primary", " "); err == nil {
		t.Fatal("expected empty user account listing to fail")
	}
}

func TestExternalLoginGeneratesStableSafeUserIdentifiers(t *testing.T) {
	auth, identity, _ := newExternalAuthFixture(t)
	ctx := t.Context()
	longSubject := strings.Repeat("Long.Subject/", 10)
	if _, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "OIDC", Subject: longSubject}, true); err == nil {
		t.Fatal("expected automatic external user creation without email to fail explicitly")
	}
	first, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "OIDC", Subject: longSubject, Email: "long@example.com"}, true)
	if err != nil {
		t.Fatalf("create long external identity: %v", err)
	}
	if len(first.User.ID) > 64 || first.User.Name != "long@example.com" {
		t.Fatalf("unexpected normalized external user: %#v", first.User)
	}
	second, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "###", Subject: "###", Email: "fallback@example.com"}, true)
	if err != nil {
		t.Fatalf("create fallback identity: %v", err)
	}
	if second.User.Name != "fallback@example.com" {
		t.Fatalf("expected email name fallback, got %#v", second.User)
	}
	if second.User.ID != "external_user" {
		t.Fatalf("expected safe identifier fallback, got %q", second.User.ID)
	}
	if err := identity.UpsertUser(ctx, identitymodel.IdentityUser{ID: "oidc_collision", Name: "Collision", Email: "collision-seed@example.com", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatalf("seed colliding identity: %v", err)
	}
	collision, err := auth.ExternalLoginWithPolicy(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "collision", Email: "collision@example.com"}, authmodel.AuthExternalLoginPolicy{AutoCreateUsers: true, DefaultRoleKey: "sales"})
	if err != nil {
		t.Fatalf("create identity after id collision: %v", err)
	}
	if collision.User.ID != "oidc_collision_1" || collision.DefaultRole != "sales" {
		t.Fatalf("unexpected collision resolution or safe default role: %#v", collision)
	}
	if _, err := auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "{", Email: "brace@example.com"}, true); err != nil {
		t.Fatalf("create identity containing non-identifier rune: %v", err)
	}
}

func newExternalAuthFixture(t *testing.T) (*authdomain.AuthDomainService, *identitybusiness.IdentityDomainService, *externalAuthRepository) {
	t.Helper()
	repository := identitypersistence.NewMemoryIdentityStore()
	identity, _ := identitybusiness.NewIdentityDomainService(repository, []identitymodel.IdentityPermissionDefinition{currentPermission("identity.roles.list", "identity.roles", "list")}).ForWorkspace("workspace-primary")
	if err := identity.UpsertOrganizationUnit(t.Context(), identitymodel.IdentityOrganizationUnit{ID: "dept_sales", Code: "dept_sales", NodeType: identitymodel.IdentityOrganizationUnitDepartment, Name: "Sales", Path: "/sales", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatalf("seed sales organizationUnit: %v", err)
	}
	for _, role := range []identitymodel.IdentityRole{
		{ID: "role-sales", Key: "sales", Label: "Sales", Status: identitymodel.IdentityStatusActive},
		{ID: "role-admin", Key: "admin", Label: "Admin", Status: identitymodel.IdentityStatusActive},
		{ID: "role-disabled", Key: "disabled", Label: "Disabled", Status: identitymodel.IdentityStatusDisabled},
	} {
		seedIdentityDirectoryRole(t, repository, "workspace-primary", role)
	}
	identity.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "sales", Name: "Sales"},
		{Key: "admin", Name: "Admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list"), RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
		{Key: "disabled", Name: "Disabled"},
	})
	authRepository := &externalAuthRepository{accounts: map[string]identitymodel.IdentityExternalAccount{}, refreshTokens: map[string]identitymodel.AuthRefreshToken{}}
	return authdomain.NewAuthDomainService(identity, authRepository, "test-secret", "Password@2026", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{}), identity, authRepository
}

type externalAuthRepository struct {
	accounts      map[string]identitymodel.IdentityExternalAccount
	refreshTokens map[string]identitymodel.AuthRefreshToken
}

func (r *externalAuthRepository) GetIdentityCredential(context.Context, string, string) (identitymodel.IdentityCredential, bool, error) {
	return identitymodel.IdentityCredential{}, false, nil
}

func (r *externalAuthRepository) UpsertIdentityCredential(context.Context, string, identitymodel.IdentityCredential) error {
	return nil
}

func (r *externalAuthRepository) RecordIdentityLoginSuccess(context.Context, string, string, string) error {
	return nil
}

func (r *externalAuthRepository) CreateAuthRefreshToken(_ context.Context, _ string, token identitymodel.AuthRefreshToken) error {
	r.refreshTokens[token.TokenHash] = token
	return nil
}

func (r *externalAuthRepository) GetAuthRefreshTokenByHash(_ context.Context, _, tokenHash string) (identitymodel.AuthRefreshToken, bool, error) {
	token, ok := r.refreshTokens[tokenHash]
	return token, ok, nil
}

func (r *externalAuthRepository) RevokeAuthRefreshToken(_ context.Context, _, tokenID, revokedAt, replacedByID string) error {
	for hash, token := range r.refreshTokens {
		if token.ID == tokenID {
			token.RevokedAt = revokedAt
			token.ReplacedByID = replacedByID
			r.refreshTokens[hash] = token
		}
	}
	return nil
}

func (r *externalAuthRepository) ListAuthRefreshTokensForUser(_ context.Context, _, userID string) ([]identitymodel.AuthRefreshToken, error) {
	result := []identitymodel.AuthRefreshToken{}
	for _, token := range r.refreshTokens {
		if token.UserID == userID {
			result = append(result, token)
		}
	}
	return result, nil
}

func (r *externalAuthRepository) RevokeAuthRefreshTokensForUser(_ context.Context, _, userID, revokedAt string) (int, error) {
	count := 0
	for hash, token := range r.refreshTokens {
		if token.UserID == userID && token.RevokedAt == "" {
			token.RevokedAt = revokedAt
			r.refreshTokens[hash] = token
			count++
		}
	}
	return count, nil
}

func (r *externalAuthRepository) ListIdentityExternalAccounts(_ context.Context, _, userID string) ([]identitymodel.IdentityExternalAccount, error) {
	result := []identitymodel.IdentityExternalAccount{}
	for _, account := range r.accounts {
		if userID == "" || account.UserID == userID {
			result = append(result, account)
		}
	}
	return result, nil
}

func (r *externalAuthRepository) UpsertIdentityExternalAccount(_ context.Context, _ string, account identitymodel.IdentityExternalAccount) error {
	r.accounts[account.ID] = account
	return nil
}

func (r *externalAuthRepository) RemoveIdentityExternalAccount(_ context.Context, _, accountID string) error {
	delete(r.accounts, accountID)
	return nil
}
