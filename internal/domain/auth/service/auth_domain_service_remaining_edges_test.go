package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestAccessTokenHeaderPayloadAndCancellationEdges(t *testing.T) {
	auth, _, repository := newFaultAuthDomainService()
	auth.secret = []byte("secret")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := auth.VerifyAccessToken(cancelled, "ignored"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verification=%v", err)
	}

	repository.refreshTokens = []identitymodel.AuthRefreshToken{{UserID: "user", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}}
	validClaims, err := json.Marshal(authmodel.AuthClaims{Subject: "user", WorkspaceID: "workspace-primary", SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	validPayload := base64.RawURLEncoding.EncodeToString(validClaims)
	for _, test := range []struct {
		name        string
		header      []byte
		payload     string
		rawHeader   string
		wantSuccess bool
	}{
		{name: "header encoding", rawHeader: "%", payload: validPayload},
		{name: "header json", header: []byte("["), payload: validPayload},
		{name: "unknown kid", header: []byte(`{"alg":"HS256","kid":"missing"}`), payload: validPayload},
		{name: "payload encoding", header: []byte(`{"alg":"HS256"}`), payload: "%"},
		{name: "payload json", header: []byte(`{"alg":"HS256"}`), payload: base64.RawURLEncoding.EncodeToString([]byte("["))},
		{name: "legacy no kid is rejected", header: []byte(`{"alg":"HS256"}`), payload: validPayload},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := test.rawHeader
			if header == "" {
				header = base64.RawURLEncoding.EncodeToString(test.header)
			}
			signed := header + "." + test.payload
			token := signed + "." + signHS256([]byte(signed), auth.secret)
			claims, err := auth.VerifyAccessToken(t.Context(), token)
			if test.wantSuccess {
				if err != nil || claims.Subject != "user" {
					t.Fatalf("claims=%+v err=%v", claims, err)
				}
			} else if err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}

func TestSigningKeyAndDomainErrorValidationEdges(t *testing.T) {
	auth := NewAuthDomainService(nil, nil, "secret", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	for _, test := range []struct {
		kid, secret string
		keys        map[string]string
	}{
		{kid: "", secret: "secret"},
		{kid: "kid", secret: ""},
		{kid: "kid", secret: "secret", keys: map[string]string{"": "old"}},
		{kid: "kid", secret: "secret", keys: map[string]string{"old": ""}},
		{kid: "kid", secret: "secret", keys: map[string]string{"kid": "other"}},
	} {
		if err := auth.ConfigureSigningKeys(test.kid, test.secret, test.keys); err == nil {
			t.Fatalf("invalid signing keys accepted: %+v", test)
		}
	}
	err := authDomainError(apperror.KindBadRequest, "auth.test", " ", "ignored", "field", "value")
	appErr := err.(*apperror.AppError)
	if len(appErr.Params) != 1 || appErr.Params["field"] != "value" {
		t.Fatalf("sanitized params=%v", appErr.Params)
	}
}

func TestAuthDomainConstructorExplicitConfiguration(t *testing.T) {
	policy := authpolicy.AuthPasswordPolicy{MinLength: 12}
	auth := NewAuthDomainService(nil, nil, "explicit", "Password@1", time.Minute, time.Hour, 2, time.Minute, time.Minute, 2, policy)
	if string(auth.secret) != "explicit" || auth.accessTTL != time.Minute || auth.refreshTTL != time.Hour || auth.maxLoginFailures != 2 || auth.passwordPolicy.MinLength != 12 {
		t.Fatalf("explicit auth configuration=%+v", auth)
	}
	defaults := NewAuthDomainService(nil, nil, "", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	if len(defaults.secret) == 0 {
		t.Fatal("default auth secret missing")
	}
	_ = notFound("auth.not_found")
	_ = internalError("test", errors.New("cause"))
}

func TestOTPResendStoredChallengeShortCircuitEdges(t *testing.T) {
	now := time.Now().UTC()
	tests := []authmodel.AuthProviderChallenge{
		{WorkspaceID: "other", Provider: "otp", Phone: "phone", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{WorkspaceID: "workspace-a", Provider: "other", Phone: "phone", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{WorkspaceID: "workspace-a", Provider: "otp", Phone: "other", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{WorkspaceID: "workspace-a", Provider: "otp", Phone: "phone", ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)},
		{WorkspaceID: "workspace-a", Provider: "otp", Phone: "phone", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), CreatedAt: "invalid"},
		{WorkspaceID: "workspace-a", Provider: "otp", Phone: "phone", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), CreatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)},
	}
	for index, challenge := range tests {
		auth := newChallengeTestAuth(time.Hour, 2)
		auth.challenges["stored"] = challenge
		if _, err := auth.BeginOTPLogin(t.Context(), "workspace-a", "otp", "phone"); err != nil {
			t.Fatalf("case %d begin OTP: %v", index, err)
		}
	}
	auth, _, _ := newFaultAuthDomainService()
	auth.otpResendCooldown = time.Hour
	auth.otpMaxAttempts = 2
	auth.challenges["state"] = authmodel.AuthProviderChallenge{Provider: "oidc", WorkspaceID: "workspace-a", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if _, err := auth.ConsumeProviderChallenge(t.Context(), "workspace-a", "saml", "state"); err == nil {
		t.Fatal("mismatched provider challenge accepted")
	}
	auth.challenges["otp-provider-mismatch"] = authmodel.AuthProviderChallenge{Provider: "other", WorkspaceID: "workspace-a", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if _, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-a", "otp", "otp-provider-mismatch", "code"); err == nil {
		t.Fatal("mismatched OTP provider accepted")
	}
}

func TestProviderConfigurationAndFlowRemainingEdges(t *testing.T) {
	empty := NewAuthProviderDomainService([]map[string]any{{"key": ""}}, true)
	if safe := empty.ListSafe(t.Context()); len(safe) != 1 || safe[0]["key"] != "local" {
		t.Fatalf("default provider list=%v", safe)
	}
	policy := empty.AuthExternalLoginPolicy(t.Context(), authmodel.AuthProviderConfig{})
	if !policy.AutoCreateUsers {
		t.Fatal("default auto-create policy was not used")
	}

	auth, _, _ := newFaultAuthDomainService()
	auth.otpResendCooldown = time.Hour
	auth.otpMaxAttempts = 2
	providers := NewAuthProviderDomainService([]map[string]any{
		{"key": "otp", "type": "otp", "enabled": true, "otp_provider": "real"},
		{"key": "saml", "type": "saml", "enabled": true},
		{"key": "oidc", "type": "oidc", "enabled": true},
		{"key": "unsupported", "type": "custom", "enabled": true},
	}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	if safe := providers.ListSafe(t.Context()); len(safe) != 4 {
		t.Fatalf("configured provider list=%v", safe)
	}
	if _, err := flows.Start(t.Context(), "workspace-a", "unsupported", "GET", ""); err == nil {
		t.Fatal("unsupported provider flow started")
	}
	if _, err := flows.Start(t.Context(), "", "otp", "POST", "phone"); err == nil {
		t.Fatal("OTP start with invalid workspace accepted")
	}
	realOTP, err := flows.Start(t.Context(), "workspace-a", "otp", "POST", "phone")
	if err != nil || realOTP.Code != "" {
		t.Fatalf("real OTP start=%+v err=%v", realOTP, err)
	}
	storedCode := auth.challenges[realOTP.State].Code
	if _, err := flows.VerifyOTP(t.Context(), "workspace-a", "otp", realOTP.State, storedCode); err == nil {
		t.Fatal("OTP without linkable email unexpectedly completed login")
	}
	if _, err := flows.VerifyOTP(t.Context(), "workspace-a", "oidc", "state", "code"); err == nil {
		t.Fatal("OIDC provider accepted by OTP verifier")
	}
	started, err := flows.Start(t.Context(), "workspace-a", "saml", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := flows.ConsumeCallbackChallenge(t.Context(), "workspace-a", "saml", started.State); err != nil {
		t.Fatalf("SAML callback challenge: %v", err)
	}
	mismatched, err := flows.Start(t.Context(), "workspace-a", "saml", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	challenge := auth.challenges[mismatched.State]
	challenge.RedirectURL = "https://unexpected.example/callback"
	auth.challenges[mismatched.State] = challenge
	if _, _, err := flows.ConsumeCallbackChallenge(t.Context(), "workspace-a", "saml", mismatched.State); err == nil {
		t.Fatal("callback with mismatched redirect accepted")
	}
}

func TestOTPIdentityEmailCoversDigitsLettersSymbolsAndFallback(t *testing.T) {
	if got := otpIdentityEmail(" +ABcd-19 "); got != "abcd19@otp.identity.invalid" {
		t.Fatalf("normalized email=%q", got)
	}
	if got := otpIdentityEmail("a{A["); got != "aa@otp.identity.invalid" {
		t.Fatalf("range-boundary email=%q", got)
	}
	if got := otpIdentityEmail("---"); got != "verified@otp.identity.invalid" {
		t.Fatalf("fallback email=%q", got)
	}
}

type authWritebackProbe struct{ err error }

func (p authWritebackProbe) WriteAuthProviderExternalIdentity(context.Context, authmodel.AuthExternalIdentityAssertion, authmodel.AuthSession) error {
	return p.err
}

func TestProviderCallbackWritebackAndSessionWorkspaceEdges(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	if _, err := auth.issueSession(t.Context(), "", identitymodel.IdentityUser{}); err == nil {
		t.Fatal("session issued for invalid workspace")
	}
	providers := NewAuthProviderDomainService(nil, false)
	failure := errors.New("writeback failed")
	flows := NewAuthProviderFlowDomainService(auth, providers, authWritebackProbe{err: failure})
	config := authmodel.AuthProviderConfig{AutoCreateConfigured: true, AutoCreateUsers: true}
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject", Email: "user@example.test"}
	if _, err := flows.CompleteCallback(t.Context(), "workspace-a", config, assertion); !errors.Is(err, failure) {
		t.Fatalf("writeback failure=%v", err)
	}
	successFlows := NewAuthProviderFlowDomainService(auth, providers, authWritebackProbe{})
	assertion.Subject = "success-subject"
	assertion.Email = "success-writeback@example.test"
	if _, err := successFlows.CompleteCallback(t.Context(), "workspace-a", config, assertion); err != nil {
		t.Fatalf("successful writeback callback: %v", err)
	}
}

type removingAuthRepository struct {
	*faultExternalAuthRepository
	removed string
}

func (r *removingAuthRepository) RemoveIdentityExternalAccount(_ context.Context, _ string, accountID string) error {
	r.removed = accountID
	return nil
}

func TestExternalIdentitySuccessAndValidationEdges(t *testing.T) {
	auth, identities, repository := newFaultAuthDomainService()
	for _, assertion := range []authmodel.AuthExternalIdentityAssertion{
		{Subject: "subject"},
		{Provider: "oidc"},
	} {
		if _, err := auth.ExternalLogin(t.Context(), "workspace-a", assertion, true); err == nil {
			t.Fatalf("invalid assertion accepted: %+v", assertion)
		}
	}
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject", Email: "user@example.test", DisplayName: "User"}
	if _, err := auth.ExternalLogin(t.Context(), "workspace-a", assertion, false); err == nil {
		t.Fatal("unlinked identity accepted without auto-create")
	}
	failingAuth, failingIdentities, _ := newFaultAuthDomainService()
	failingIdentities.upsertUserErr = errors.New("create failed")
	if _, err := failingAuth.ExternalLogin(t.Context(), "workspace-a", assertion, true); err == nil {
		t.Fatal("external identity creation failure was ignored")
	}

	disabled := activeExternalIdentityUser("disabled", assertion.Email)
	disabled.Status = identitymodel.IdentityStatusDisabled
	identities.users = []identitymodel.IdentityUser{disabled}
	if _, _, err := auth.externalLoginUserByVerifiedEmail(t.Context(), assertion); err == nil {
		t.Fatal("disabled verified-email identity accepted")
	}
	if _, ok, err := auth.externalLoginUserByVerifiedEmail(t.Context(), authmodel.AuthExternalIdentityAssertion{}); err != nil || ok {
		t.Fatalf("empty verified email: ok=%v err=%v", ok, err)
	}

	active := activeExternalIdentityUser("active", assertion.Email)
	identities.users = []identitymodel.IdentityUser{active}
	session, err := auth.ExternalLogin(t.Context(), "workspace-a", assertion, true)
	if err != nil || session.User.ID != active.ID || len(repository.accounts) != 1 {
		t.Fatalf("verified-email login session=%+v accounts=%+v err=%v", session, repository.accounts, err)
	}
	repository.accounts = []identitymodel.IdentityExternalAccount{{ID: "linked", UserID: active.ID, Provider: "oidc", ProviderSubject: "subject"}}
	session, err = auth.ExternalLogin(t.Context(), "workspace-a", assertion, true)
	if err != nil || session.User.ID != active.ID {
		t.Fatalf("linked login session=%+v err=%v", session, err)
	}
	identities.users[0].Status = identitymodel.IdentityStatusDisabled
	if _, err := auth.ExternalLogin(t.Context(), "workspace-a", assertion, true); err == nil {
		t.Fatal("linked disabled identity accepted")
	}

	if _, err := auth.ListExternalAccounts(t.Context(), "workspace-a", ""); err == nil {
		t.Fatal("external accounts listed without user")
	}
	if accounts, err := auth.ListExternalAccounts(t.Context(), "workspace-a", active.ID); err != nil || len(accounts) == 0 {
		t.Fatalf("external accounts=%+v err=%v", accounts, err)
	}
	identities.users = []identitymodel.IdentityUser{active}
	for _, test := range []struct {
		userID    string
		assertion authmodel.AuthExternalIdentityAssertion
	}{
		{assertion: assertion},
		{userID: active.ID, assertion: authmodel.AuthExternalIdentityAssertion{Subject: "subject"}},
		{userID: active.ID, assertion: authmodel.AuthExternalIdentityAssertion{Provider: "oidc"}},
	} {
		if _, err := auth.BindExternalAccount(t.Context(), "workspace-a", test.userID, test.assertion); err == nil {
			t.Fatalf("invalid bind accepted: %+v", test)
		}
	}
	if _, err := auth.BindExternalAccount(t.Context(), "workspace-a", "missing", assertion); err == nil {
		t.Fatal("missing bind user accepted")
	}
	repository.accounts = []identitymodel.IdentityExternalAccount{{ID: "same", UserID: active.ID, Provider: "oidc", ProviderSubject: "subject"}}
	account, err := auth.BindExternalAccount(t.Context(), "workspace-a", active.ID, assertion)
	if err != nil || account.ID != "same" {
		t.Fatalf("idempotent bind=%+v err=%v", account, err)
	}
	repository.accounts[0].UserID = "other"
	if _, err := auth.BindExternalAccount(t.Context(), "workspace-a", active.ID, assertion); err == nil {
		t.Fatal("cross-user external account rebound")
	}
	repository.accounts = nil
	newAssertion := assertion
	newAssertion.Subject = "new-subject"
	if account, err := auth.BindExternalAccount(t.Context(), "workspace-a", active.ID, newAssertion); err != nil || account.ID == "" {
		t.Fatalf("new external account=%+v err=%v", account, err)
	}

	removing := &removingAuthRepository{faultExternalAuthRepository: repository}
	auth.identityStore = removing
	for _, input := range [][3]string{{"", "oidc", "same"}, {active.ID, "", "same"}, {active.ID, "oidc", ""}} {
		if err := auth.UnbindExternalAccount(t.Context(), "workspace-a", input[0], input[1], input[2]); err == nil {
			t.Fatalf("invalid unbind accepted: %v", input)
		}
	}
	repository.accounts = []identitymodel.IdentityExternalAccount{{ID: "target", UserID: active.ID, Provider: "other", ProviderSubject: "subject"}, {ID: "target", UserID: active.ID, Provider: "oidc", ProviderSubject: "subject"}}
	if err := auth.UnbindExternalAccount(t.Context(), "workspace-a", active.ID, "oidc", "target"); err != nil || removing.removed != "target" {
		t.Fatalf("unbind removed=%q err=%v", removing.removed, err)
	}
	if err := auth.UnbindExternalAccount(t.Context(), "workspace-a", active.ID, "oidc", "missing"); err == nil {
		t.Fatal("missing external account unbound")
	}
	repository.accounts = []identitymodel.IdentityExternalAccount{{Provider: "other", ProviderSubject: "subject"}, {Provider: "oidc", ProviderSubject: "other"}, {Provider: "oidc", ProviderSubject: "subject"}}
	if account, ok, err := auth.externalAccountByProviderSubject(t.Context(), "workspace-a", "oidc", "subject"); err != nil || !ok || account.Provider != "oidc" {
		t.Fatalf("external account lookup=%+v ok=%v err=%v", account, ok, err)
	}
}

func TestExternalIdentityCreationAndRoleMappingEdges(t *testing.T) {
	auth, identities, _ := newFaultAuthDomainService()
	if _, err := auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}, authmodel.AuthExternalLoginPolicy{}); err == nil {
		t.Fatal("external identity created without email")
	}
	if _, err := auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{Provider: "wechat_mini_program", Subject: "open-id"}, authmodel.AuthExternalLoginPolicy{}); err == nil {
		t.Fatal("unverified wechat subject created without email")
	}
	createdFromWeChat, err := auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{Provider: "wechat_mini_program", Subject: "open-id", ProviderSubjectVerified: true}, authmodel.AuthExternalLoginPolicy{})
	if err != nil || createdFromWeChat.Email != verifiedSubjectPlaceholderEmail("wechat_mini_program", "open-id") || !strings.HasSuffix(createdFromWeChat.Email, "@external.invalid") {
		t.Fatalf("verified wechat identity=%+v err=%v", createdFromWeChat, err)
	}
	createdFromLINE, err := auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{Provider: "line", Subject: "line-user", ProviderSubjectVerified: true}, authmodel.AuthExternalLoginPolicy{})
	if err != nil || !strings.HasPrefix(createdFromLINE.Email, "line-liff-") || !strings.HasSuffix(createdFromLINE.Email, "@external.invalid") {
		t.Fatalf("verified LINE identity=%+v err=%v", createdFromLINE, err)
	}
	identities.users = []identitymodel.IdentityUser{activeExternalIdentityUser("oidc_subject", "existing@example.test")}
	created, err := auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{
		Provider: "OIDC", Subject: "Subject", Email: "new@example.test", DisplayName: "Named User",
	}, authmodel.AuthExternalLoginPolicy{})
	if err != nil || created.ID != "oidc_subject_1" || created.Name != "Named User" {
		t.Fatalf("collision create=%+v err=%v", created, err)
	}
	created, err = auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{
		Provider: "!!", Subject: "@@", Email: "fallback@example.test",
	}, authmodel.AuthExternalLoginPolicy{})
	if err != nil || created.ID != "external_user" || created.Name != "fallback@example.test" {
		t.Fatalf("fallback create=%+v err=%v", created, err)
	}
	created, err = auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{
		Provider: "oidc", Subject: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789", Email: "long@example.test",
	}, authmodel.AuthExternalLoginPolicy{})
	if err != nil || len(created.ID) != 64 {
		t.Fatalf("long create=%+v err=%v", created, err)
	}
	if _, err := auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "brace{", Email: "brace@example.test"}, authmodel.AuthExternalLoginPolicy{}); err != nil {
		t.Fatalf("punctuation identity creation: %v", err)
	}

	identities.roles = []identitymodel.IdentityRole{
		{ID: "disabled", Key: "disabled", Status: identitymodel.IdentityStatusDisabled},
		{ID: "admin", Key: "admin", Status: identitymodel.IdentityStatusActive},
		{ID: "sales", Key: "sales", Status: identitymodel.IdentityStatusActive},
	}
	role, ok, err := auth.roleForExternalAssertion(t.Context(), authmodel.AuthExternalIdentityAssertion{Claims: map[string]string{"group": "seller"}}, authmodel.AuthExternalLoginPolicy{RoleMappings: []authmodel.AuthExternalRoleMapping{
		{Claim: "group", Match: "seller", RoleKey: "missing"},
		{Claim: "group", Match: "seller", RoleKey: "admin"},
		{Claim: "group", Match: "other", RoleKey: "sales"},
		{Claim: "group", Match: "seller", RoleKey: "sales"},
	}})
	if err != nil || !ok || role.Key != "sales" {
		t.Fatalf("mapped role=%+v ok=%v err=%v", role, ok, err)
	}
	created, err = auth.createExternalIdentityUser(t.Context(), authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "assigned", Email: "assigned@example.test", Claims: map[string]string{"group": "seller"}}, authmodel.AuthExternalLoginPolicy{RoleMappings: []authmodel.AuthExternalRoleMapping{{Claim: "group", Match: "seller", RoleKey: "sales"}}})
	if err != nil || created.ID == "" {
		t.Fatalf("assigned identity=%+v err=%v", created, err)
	}
}

func TestWeChatExternalLoginReusesOrphanAndSkipsBindingManagedDefaultRole(t *testing.T) {
	auth, identities, repository := newFaultAuthDomainService()
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "wechat_mini_program", Subject: "open-id", ProviderSubjectVerified: true}
	placeholder := verifiedSubjectPlaceholderEmail(assertion.Provider, assertion.Subject)
	identities.users = append(identities.users, identitymodel.IdentityUser{ID: "orphan", Name: placeholder, Email: placeholder, Status: identitymodel.IdentityStatusActive})
	identities.roles = append(identities.roles, identitymodel.IdentityRole{ID: "member", Key: "member", Status: identitymodel.IdentityStatusActive})
	identities.roleDefinitions["member"] = identitymodel.RoleSchema{
		Key: "member", Audience: identitymodel.IdentityRoleAudienceBusiness, RequiredBindingKey: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged,
	}

	session, err := auth.ExternalLoginWithPolicy(t.Context(), "workspace-primary", assertion, authmodel.AuthExternalLoginPolicy{AutoCreateUsers: true, DefaultRoleKey: "member"})
	if err != nil {
		t.Fatalf("recover verified wechat login: %v", err)
	}
	if session.User.ID != "orphan" || len(identities.users) != 1 {
		t.Fatalf("orphan was not reused: session=%+v users=%+v", session.User, identities.users)
	}
	if len(identities.roleAssignments) != 0 {
		t.Fatalf("binding-managed role was assigned without a binding: %+v", identities.roleAssignments)
	}
	if len(repository.accounts) != 1 || repository.accounts[0].UserID != "orphan" {
		t.Fatalf("external account was not linked to orphan: %+v", repository.accounts)
	}
}

func TestLinkedExternalLoginBackfillsOnlySafeDefaultRole(t *testing.T) {
	newFixture := func(definition identitymodel.RoleSchema) (*AuthDomainService, *faultExternalIdentityRepository, *faultExternalAuthRepository) {
		auth, identities, repository := newFaultAuthDomainService()
		identities.users = append(identities.users, identitymodel.IdentityUser{ID: "linked", Name: "Linked", Email: "linked@example.test", Status: identitymodel.IdentityStatusActive})
		identities.roles = append(identities.roles, identitymodel.IdentityRole{ID: "default-role", Key: "default-role", Status: identitymodel.IdentityStatusActive})
		identities.roleDefinitions["default-role"] = definition
		repository.accounts = append(repository.accounts, identitymodel.IdentityExternalAccount{ID: "external", UserID: "linked", Provider: "oidc", ProviderSubject: "subject"})
		return auth, identities, repository
	}

	t.Run("manual normal role is added once", func(t *testing.T) {
		auth, identities, _ := newFixture(identitymodel.RoleSchema{Key: "default-role", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskNormal})
		policy := authmodel.AuthExternalLoginPolicy{DefaultRoleKey: "default-role"}
		assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}
		for range 2 {
			if _, err := auth.ExternalLoginWithPolicy(t.Context(), "workspace-primary", assertion, policy); err != nil {
				t.Fatalf("linked login: %v", err)
			}
		}
		if len(identities.roleAssignments) != 1 || identities.roleAssignments[0].RoleID != "default-role" {
			t.Fatalf("default role assignments=%+v", identities.roleAssignments)
		}
	})

	for name, definition := range map[string]identitymodel.RoleSchema{
		"system managed":  {Key: "default-role", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged},
		"privileged risk": {Key: "default-role", AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
	} {
		t.Run(name+" is denied", func(t *testing.T) {
			auth, identities, _ := newFixture(definition)
			if _, err := auth.ExternalLoginWithPolicy(t.Context(), "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}, authmodel.AuthExternalLoginPolicy{DefaultRoleKey: "default-role"}); err != nil {
				t.Fatalf("linked login with denied default role: %v", err)
			}
			if len(identities.roleAssignments) != 0 {
				t.Fatalf("unsafe default role assigned: %+v", identities.roleAssignments)
			}
		})
	}

	t.Run("exact permission does not imply privileged risk", func(t *testing.T) {
		auth, identities, _ := newFixture(identitymodel.RoleSchema{
			Key: "default-role", AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list"), RiskLevel: identitymodel.IdentityRoleRiskNormal,
		})
		if _, err := auth.ExternalLoginWithPolicy(t.Context(), "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject"}, authmodel.AuthExternalLoginPolicy{DefaultRoleKey: "default-role"}); err != nil {
			t.Fatalf("linked login with exact-permission default role: %v", err)
		}
		if len(identities.roleAssignments) != 1 {
			t.Fatalf("normal-risk role was inferred as privileged: %+v", identities.roleAssignments)
		}
	})
}

type assertionAdapter struct {
	assertion authmodel.AuthExternalIdentityAssertion
	err       error
}

func (a assertionAdapter) Exchange(context.Context, string, authmodel.AuthProviderConfig, authmodel.AuthProviderChallenge, authmodel.AuthProviderCallbackInput) (authmodel.AuthExternalIdentityAssertion, error) {
	return a.assertion, a.err
}

func TestProviderFlowErrorAndNoWritebackEdges(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	providers := NewAuthProviderDomainService([]map[string]any{{"key": "otp", "type": "otp", "enabled": true}, {"key": "saml", "type": "saml", "enabled": true}}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	if _, err := flows.VerifyOTP(t.Context(), "workspace-a", "missing", "state", "code"); err == nil {
		t.Fatal("missing OTP provider accepted")
	}
	if _, err := flows.VerifyOTP(t.Context(), "workspace-a", "otp", "missing", "code"); err == nil {
		t.Fatal("missing OTP state accepted")
	}
	if _, _, err := flows.ConsumeCallbackChallenge(t.Context(), "workspace-a", "missing", "state"); err == nil {
		t.Fatal("missing callback provider accepted")
	}
	if _, _, err := flows.ConsumeCallbackChallenge(t.Context(), "workspace-a", "otp", "state"); err == nil {
		t.Fatal("OTP callback accepted")
	}
	if _, err := flows.CompleteCallback(t.Context(), "workspace-a", authmodel.AuthProviderConfig{}, authmodel.AuthExternalIdentityAssertion{}); err == nil {
		t.Fatal("invalid callback assertion completed")
	}
	config := authmodel.AuthProviderConfig{AutoCreateConfigured: true, AutoCreateUsers: true}
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject", Email: "success@example.test"}
	if _, err := flows.CompleteCallback(t.Context(), "workspace-a", config, assertion); err != nil {
		t.Fatalf("callback without writeback: %v", err)
	}
	if _, err := flows.ExchangeAndCompleteCallback(t.Context(), "workspace-a", "saml", "missing", authmodel.AuthProviderCallbackInput{}, assertionAdapter{}); err == nil {
		t.Fatal("invalid callback state exchanged")
	}
	started, err := auth.BeginSAMLLogin(t.Context(), "workspace-a", "saml", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flows.ExchangeAndCompleteCallback(t.Context(), "workspace-a", "saml", started.State, authmodel.AuthProviderCallbackInput{}, assertionAdapter{assertion: authmodel.AuthExternalIdentityAssertion{}}); err == nil {
		t.Fatal("invalid exchanged assertion completed")
	}
}
