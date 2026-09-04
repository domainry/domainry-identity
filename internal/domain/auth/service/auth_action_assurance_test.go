package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestActionAssuranceReceiptIsSignedShortLivedAndSubjectBound(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	challenge := authmodel.AuthProviderChallenge{
		WorkspaceID: "workspace-primary",
		UserID:      "user-a",
		State:       "challenge-a",
		Purpose:     authmodel.AuthChallengePurposeAction,
		Status:      authmodel.AuthChallengeStatusConsumed,
	}
	receipt, err := auth.IssueActionAssuranceReceipt(t.Context(), challenge)
	if err != nil || receipt.Token == "" || receipt.WorkspaceID != challenge.WorkspaceID || receipt.UserID != challenge.UserID {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	expiresAt, parseErr := time.Parse(time.RFC3339, receipt.ExpiresAt)
	if parseErr != nil || time.Until(expiresAt) <= 0 || time.Until(expiresAt) > 2*time.Minute+time.Second {
		t.Fatalf("expires_at=%q parse_err=%v", receipt.ExpiresAt, parseErr)
	}
	validated, err := auth.ValidateActionAssuranceReceipt(t.Context(), receipt.Token, challenge.WorkspaceID, challenge.UserID)
	if err != nil || validated.UserID != challenge.UserID || !authMethodPresent(validated.Methods, "otp") {
		t.Fatalf("validated=%#v err=%v", validated, err)
	}
	for name, scope := range map[string][2]string{
		"wrong workspace": {"workspace-other", challenge.UserID},
		"wrong user":      {challenge.WorkspaceID, "user-b"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := auth.ValidateActionAssuranceReceipt(t.Context(), receipt.Token, scope[0], scope[1]); err == nil {
				t.Fatal("cross-subject receipt was accepted")
			}
		})
	}
	parts := strings.Split(receipt.Token, ".")
	replacement := byte('A')
	if parts[1][0] == replacement {
		replacement = 'B'
	}
	parts[1] = string(replacement) + parts[1][1:]
	if _, err := auth.ValidateActionAssuranceReceipt(t.Context(), strings.Join(parts, "."), challenge.WorkspaceID, challenge.UserID); err == nil {
		t.Fatal("tampered receipt was accepted")
	}
	challenge.Status = authmodel.AuthChallengeStatusActive
	if _, err := auth.IssueActionAssuranceReceipt(t.Context(), challenge); err == nil {
		t.Fatal("unconsumed challenge issued an assurance receipt")
	}
}

func TestActionAssuranceChallengeCannotBeConsumedByLoginFlow(t *testing.T) {
	auth, identities, repository := newUserAdministrationFixture()
	identities.users = append(identities.users, identitymodel.IdentityUser{
		ID: "user-a", Name: "Action User", Email: "action@example.test", Phone: "+8613800000000", Status: identitymodel.IdentityStatusActive,
	})
	repository.mfaFactors = []identitymodel.IdentityMFAFactor{{ID: "factor-a", UserID: "user-a", Type: "otp", Provider: "sms", Status: "active", VerifiedAt: time.Now().UTC().Format(time.RFC3339)}}
	providers := NewAuthProviderDomainService([]map[string]any{{
		"key": "sms", "label": "SMS", "type": "otp", "enabled": true, "otp_provider": "mock",
	}}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	challenge, err := flows.BeginActionAssurance(t.Context(), "workspace-primary", "user-a")
	if err != nil || challenge.State == "" || challenge.Code == "" || challenge.Purpose != authmodel.AuthChallengePurposeAction || challenge.Status != authmodel.AuthChallengeStatusActive {
		t.Fatalf("challenge=%#v err=%v", challenge, err)
	}
	if _, err := flows.VerifyOTPOutcome(t.Context(), "workspace-primary", "sms", challenge.State, challenge.Code); err == nil {
		t.Fatal("action-assurance challenge was accepted as login OTP")
	}
	receipt, err := flows.VerifyActionAssurance(t.Context(), "workspace-primary", "user-a", "sms", challenge.State, challenge.Code)
	if err != nil || receipt.Token == "" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if _, err := auth.ValidateActionAssuranceReceipt(t.Context(), receipt.Token, "workspace-primary", "user-a"); err != nil {
		t.Fatalf("validate receipt: %v", err)
	}
	if _, err := flows.VerifyActionAssurance(t.Context(), "workspace-primary", "user-a", "sms", challenge.State, challenge.Code); err == nil {
		t.Fatal("action-assurance challenge replay was accepted")
	}
}

func TestActionAssuranceRequiresAnActiveVerifiedOTPFactor(t *testing.T) {
	auth, identities, repository := newUserAdministrationFixture()
	identities.users = append(identities.users, identitymodel.IdentityUser{
		ID: "user-a", Name: "Action User", Phone: "+8613800000000", Status: identitymodel.IdentityStatusActive,
	})
	providers := NewAuthProviderDomainService([]map[string]any{{
		"key": "sms", "type": "otp", "enabled": true, "otp_provider": "mock",
	}}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	for _, factor := range []identitymodel.IdentityMFAFactor{
		{},
		{ID: "unverified", UserID: "user-a", Type: "otp", Provider: "sms", Status: "active"},
		{ID: "revoked", UserID: "user-a", Type: "otp", Provider: "sms", Status: "revoked", VerifiedAt: time.Now().UTC().Format(time.RFC3339)},
	} {
		repository.mfaFactors = nil
		if factor.ID != "" {
			repository.mfaFactors = []identitymodel.IdentityMFAFactor{factor}
		}
		if _, err := flows.BeginActionAssurance(t.Context(), "workspace-primary", "user-a"); err == nil {
			t.Fatalf("factor=%#v started an action assurance challenge", factor)
		}
	}
}

func TestOTPAllowedPurposesSeparatePasswordLoginFromActionStepUp(t *testing.T) {
	auth, identities, repository := newUserAdministrationFixture()
	const password = "Password@2026"
	identities.users = append(identities.users, identitymodel.IdentityUser{
		ID: "user-a", Name: "Action User", Email: "action@example.test", Phone: "+8613800000000", Status: identitymodel.IdentityStatusActive,
	})
	repository.credentials = map[string]identitymodel.IdentityCredential{"user-a": passwordCredential(t, "user-a", password)}
	repository.mfaFactors = []identitymodel.IdentityMFAFactor{{ID: "factor-a", UserID: "user-a", Type: "otp", Provider: "sms", Status: "active", VerifiedAt: time.Now().UTC().Format(time.RFC3339)}}
	providers := NewAuthProviderDomainService([]map[string]any{{
		"key": "sms", "type": "otp", "enabled": true, "otp_provider": "mock", "allowed_purposes": []any{authmodel.AuthChallengePurposeAction},
	}}, false)
	flows := NewAuthProviderFlowDomainService(auth, providers)
	outcome, err := flows.LoginWithPasswordOutcome(t.Context(), "workspace-primary", "action@example.test", password, "domainry-admin")
	if err != nil || outcome.Status != authmodel.AuthenticationStatusAuthenticated || outcome.Session == nil || outcome.Challenge != nil {
		t.Fatalf("password outcome=%#v err=%v", outcome, err)
	}
	if _, err := flows.Start(t.Context(), "workspace-primary", "sms", "POST", "+8613800000000"); authProviderTestErrorCode(err) != "auth.provider_purpose_not_enabled" {
		t.Fatalf("action-only provider started passwordless login: %v", err)
	}
	challenge, err := flows.BeginActionAssurance(t.Context(), "workspace-primary", "user-a")
	if err != nil || challenge.Purpose != authmodel.AuthChallengePurposeAction {
		t.Fatalf("action challenge=%#v err=%v", challenge, err)
	}
}

func TestLoginOnlyOTPProviderCannotIssueActionChallenge(t *testing.T) {
	auth, identities, repository := newUserAdministrationFixture()
	identities.users = append(identities.users, identitymodel.IdentityUser{ID: "user-a", Phone: "+8613800000000", Status: identitymodel.IdentityStatusActive})
	repository.mfaFactors = []identitymodel.IdentityMFAFactor{{ID: "factor-a", UserID: "user-a", Type: "otp", Provider: "sms", Status: "active", VerifiedAt: time.Now().UTC().Format(time.RFC3339)}}
	providers := NewAuthProviderDomainService([]map[string]any{{
		"key": "sms", "type": "otp", "enabled": true, "otp_provider": "mock", "allowed_purposes": []any{authmodel.AuthChallengePurposeLoginMFA},
	}}, false)
	if _, err := NewAuthProviderFlowDomainService(auth, providers).BeginActionAssurance(t.Context(), "workspace-primary", "user-a"); authProviderTestErrorCode(err) != "auth.mfa_factor_unavailable" {
		t.Fatalf("login-only provider issued action challenge: %v", err)
	}
}

func TestActionAssuranceReceiptFailsClosedWhenEntropyFails(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	auth.readRandomBytes = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	_, err := auth.IssueActionAssuranceReceipt(t.Context(), authmodel.AuthProviderChallenge{
		WorkspaceID: "workspace-primary", UserID: "user-a", State: "challenge-a",
		Purpose: authmodel.AuthChallengePurposeAction, Status: authmodel.AuthChallengeStatusConsumed,
	})
	if err == nil {
		t.Fatal("entropy failure issued an assurance receipt")
	}
}
