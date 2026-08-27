package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
)

func newChallengeTestAuth(cooldown time.Duration, attempts int) *AuthDomainService {
	return NewAuthDomainService(nil, nil, "secret", "", 0, 0, 0, 0, cooldown, attempts, authpolicy.AuthPasswordPolicy{})
}

func TestProviderAndSAMLChallengeValidationLifecycle(t *testing.T) {
	auth := newChallengeTestAuth(0, 2)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, call := range []func() error{
		func() error {
			_, err := auth.BeginProviderLogin(cancelled, "workspace-a", "oidc", "https://id.example/auth", "client", "https://app.example/callback", "openid")
			return err
		},
		func() error {
			_, err := auth.BeginSAMLLogin(cancelled, "workspace-a", "saml", "https://id.example/sso", "entity", "https://app.example/acs")
			return err
		},
		func() error { _, err := auth.ConsumeProviderChallenge(cancelled, "oidc", "state"); return err },
	} {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error=%v", err)
		}
	}
	for _, workspace := range []string{"", "   "} {
		if _, err := auth.BeginProviderLogin(t.Context(), workspace, "oidc", "https://id.example/auth", "client", "https://app.example/callback", "openid"); err == nil {
			t.Fatalf("invalid workspace %q accepted", workspace)
		}
		if _, err := auth.BeginSAMLLogin(t.Context(), workspace, "saml", "https://id.example/sso", "entity", "https://app.example/acs"); err == nil {
			t.Fatalf("invalid SAML workspace %q accepted", workspace)
		}
	}
	for _, provider := range []string{"", "local"} {
		if _, err := auth.BeginProviderLogin(t.Context(), "workspace-a", provider, "https://id.example/auth", "client", "https://app.example/callback", "openid"); err == nil {
			t.Fatalf("invalid provider %q accepted", provider)
		}
		if _, err := auth.BeginSAMLLogin(t.Context(), "workspace-a", provider, "https://id.example/sso", "entity", "https://app.example/acs"); err == nil {
			t.Fatalf("invalid SAML provider %q accepted", provider)
		}
	}
	started, err := auth.BeginProviderLogin(t.Context(), " workspace-a ", " OIDC ", "https://id.example/auth", "client", "https://app.example/callback", "openid profile")
	if err != nil || started.Provider != "oidc" || started.State == "" || started.Nonce == "" || !strings.Contains(started.AuthURL, "state=") || !strings.Contains(started.AuthURL, "nonce=") {
		t.Fatalf("OIDC start=%+v err=%v", started, err)
	}
	if _, err := auth.ConsumeProviderChallenge(t.Context(), "saml", started.State); err == nil {
		t.Fatal("provider mismatch accepted")
	}
	if _, err := auth.ConsumeProviderChallenge(t.Context(), "oidc", started.State); err == nil {
		t.Fatal("mismatched consume should invalidate the state")
	}
	saml, err := auth.BeginSAMLLogin(t.Context(), "workspace-a", "SAML", "https://id.example/sso", "entity", "https://app.example/acs")
	if err != nil || saml.Provider != "saml" || saml.State == "" || saml.Nonce != "" || !strings.Contains(saml.AuthURL, "SAMLRequest=") {
		t.Fatalf("SAML start=%+v err=%v", saml, err)
	}
	challenge, err := auth.ConsumeProviderChallenge(t.Context(), "saml", saml.State)
	if err != nil || challenge.WorkspaceID != "workspace-a" {
		t.Fatalf("challenge=%+v err=%v", challenge, err)
	}
	if _, err := auth.ConsumeProviderChallenge(t.Context(), "saml", saml.State); err == nil {
		t.Fatal("consumed SAML state replayed")
	}
	for state, challenge := range map[string]authmodel.AuthProviderChallenge{
		"expired":       {Provider: "oidc", WorkspaceID: "workspace-a", ExpiresAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)},
		"bad-workspace": {Provider: "oidc", WorkspaceID: "", ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339)},
	} {
		auth.challenges[state] = challenge
		if _, err := auth.ConsumeProviderChallenge(t.Context(), "oidc", state); err == nil || auth.challenges[state].State != "" {
			t.Fatalf("invalid stored challenge %q accepted or retained", state)
		}
	}
	for _, input := range []struct{ provider, state string }{{"", "state"}, {"oidc", ""}} {
		if _, err := auth.ConsumeProviderChallenge(t.Context(), input.provider, input.state); err == nil {
			t.Fatalf("invalid consume input=%+v accepted", input)
		}
	}
}

func TestOTPChallengeRateLimitAttemptsExpiryAndWorkspaceIsolation(t *testing.T) {
	auth := newChallengeTestAuth(time.Hour, 2)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := auth.BeginOTPLogin(cancelled, "workspace-a", "otp", "10000000002"); !errors.Is(err, context.Canceled) {
		t.Fatalf("begin cancellation=%v", err)
	}
	if _, err := auth.ConsumeOTPChallenge(cancelled, "workspace-a", "otp", "state", "code"); !errors.Is(err, context.Canceled) {
		t.Fatalf("consume cancellation=%v", err)
	}
	for _, input := range []struct{ workspace, provider, phone string }{
		{"", "otp", "10000000002"}, {"   ", "otp", "10000000002"}, {"workspace-a", "", "10000000002"}, {"workspace-a", "otp", ""},
	} {
		if _, err := auth.BeginOTPLogin(t.Context(), input.workspace, input.provider, input.phone); err == nil {
			t.Fatalf("invalid OTP start=%+v accepted", input)
		}
	}
	started, err := auth.BeginOTPLogin(t.Context(), "workspace-a", "OTP", " 10000000002 ")
	if err != nil || started.Code == "" || len(started.Code) != 6 {
		t.Fatalf("OTP start=%+v err=%v", started, err)
	}
	if _, err := auth.BeginOTPLogin(t.Context(), "workspace-a", "otp", "10000000002"); err == nil {
		t.Fatal("OTP resend cooldown was not enforced")
	}
	if _, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-b", "otp", started.State, started.Code); err == nil {
		t.Fatal("cross-workspace OTP accepted")
	}
	if _, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-a", "otp", started.State, "wrong"); err == nil || auth.challenges[started.State].Attempts != 1 {
		t.Fatalf("first wrong attempt err=%v challenge=%+v", err, auth.challenges[started.State])
	}
	if _, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-a", "otp", started.State, "wrong"); err == nil {
		t.Fatal("second wrong attempt accepted")
	}
	if _, ok := auth.challenges[started.State]; ok {
		t.Fatal("OTP challenge retained after max attempts")
	}
	if _, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-a", "otp", started.State, started.Code); err == nil {
		t.Fatal("exhausted OTP challenge accepted")
	}

	auth.otpResendCooldown = 0
	valid, err := auth.BeginOTPLogin(t.Context(), "workspace-a", "otp", "10000000003")
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-a", "otp", valid.State, " "+valid.Code+" ")
	if err != nil || assertion.Provider != "otp" || assertion.Subject != "10000000003" || assertion.Email != "10000000003@otp.identity.invalid" || assertion.Metadata != `{"source":"otp","phone_verified":true}` {
		t.Fatalf("assertion=%+v err=%v", assertion, err)
	}
	auth.challenges["expired"] = authmodel.AuthProviderChallenge{WorkspaceID: "workspace-a", Provider: "otp", State: "expired", Code: "123456", ExpiresAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)}
	if _, err := auth.ConsumeOTPChallenge(t.Context(), "workspace-a", "otp", "expired", "123456"); err == nil {
		t.Fatal("expired OTP accepted")
	}
	for _, input := range []struct{ workspace, provider, state string }{{"", "otp", "state"}, {"workspace-a", "", "state"}, {"workspace-a", "otp", ""}} {
		if _, err := auth.ConsumeOTPChallenge(t.Context(), input.workspace, input.provider, input.state, "code"); err == nil {
			t.Fatalf("invalid OTP consume=%+v accepted", input)
		}
	}
}
