package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	authservice "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"golang.org/x/crypto/bcrypt"
)

type totpIdentity struct {
	authcontract.AuthIdentityPort
	user identitymodel.IdentityUser
}

func (i totpIdentity) UserByID(_ context.Context, id string) (identitymodel.IdentityUser, bool, error) {
	return i.user, id == i.user.ID, nil
}
func (i totpIdentity) UserByLogin(_ context.Context, login string) (identitymodel.IdentityUser, bool, error) {
	return i.user, login == i.user.Email, nil
}
func (i totpIdentity) ActiveRolesForUser(context.Context, string) ([]identitymodel.IdentityRole, error) {
	return nil, nil
}
func (i totpIdentity) ResolveEffectivePermissions(context.Context, string) ([]string, error) {
	return nil, nil
}
func (i totpIdentity) ResolvePrincipal(context.Context, string) (identitymodel.Principal, error) {
	return identitymodel.Principal{Known: true, UserID: i.user.ID, WorkspaceID: "workspace-primary"}, nil
}

func authenticatorCode(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], uint64(step))
	hash := hmac.New(sha1.New, key)
	_, _ = hash.Write(data[:])
	digest := hash.Sum(nil)
	offset := digest[19] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
}

func TestTOTPFlowPreservesPINPolicyAndAuthenticatesWithoutPhone(t *testing.T) {
	repository := newTOTPRepository(t)
	user := identitymodel.IdentityUser{ID: "totp-user", Email: "totp@example.test", Status: identitymodel.IdentityStatusActive}
	const password = "VerifiedPassword@2026"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.UpsertIdentityCredential(t.Context(), "workspace-primary", identitymodel.IdentityCredential{UserID: user.ID, PasswordHash: string(passwordHash)}); err != nil {
		t.Fatal(err)
	}
	auth := authservice.NewAuthDomainService(totpIdentity{user: user}, repository, "test-signing-key", "", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
	if err := auth.ConfigureTokenMetadata("https://identity.example.test", "domainry-admin"); err != nil {
		t.Fatal(err)
	}
	providers := authservice.NewAuthProviderDomainService(nil, false)
	flows := authservice.NewAuthProviderFlowDomainService(auth, providers)
	if _, err := auth.ManageTOTP(t.Context(), "workspace-primary", user.ID, authmodel.TOTPRequest{Operation: "enroll", CurrentPassword: "wrong"}); err == nil {
		t.Fatal("binding without password accepted")
	}
	enrollment, err := auth.ManageTOTP(t.Context(), "workspace-primary", user.ID, authmodel.TOTPRequest{Operation: "enroll", CurrentPassword: password})
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(enrollment.OTPAuthURL)
	if err != nil || uri.Scheme != "otpauth" || uri.Host != "totp" || uri.Query().Get("secret") != enrollment.SetupKey || uri.Query().Get("period") != "30" || uri.Query().Get("digits") != "6" {
		t.Fatal("invalid authenticator provisioning URI")
	}
	step := time.Now().Unix() / 30
	confirm, err := auth.ManageTOTP(t.Context(), "workspace-primary", user.ID, authmodel.TOTPRequest{Operation: "confirm", State: enrollment.State, Code: authenticatorCode(t, enrollment.SetupKey, step-1)})
	if err != nil || !confirm.Enabled || confirm.SetupKey != "" {
		t.Fatalf("confirmation: %+v %v", confirm, err)
	}
	status, err := auth.ManageTOTP(t.Context(), "workspace-primary", user.ID, authmodel.TOTPRequest{Operation: "status"})
	if err != nil || !status.Enabled || status.SetupKey != "" || status.OTPAuthURL != "" {
		t.Fatal("status exposed provisioning material")
	}
	// Binding a verifier must not introduce a new login challenge policy.
	outcome, err := flows.LoginWithPasswordOutcome(t.Context(), "workspace-primary", user.Email, password, "domainry-admin")
	if err != nil || outcome.Status != authmodel.AuthenticationStatusAuthenticated {
		t.Fatalf("binding changed login policy: %v", err)
	}
	if err := repository.UpsertIdentityMFAFactor(t.Context(), "workspace-primary", identitymodel.IdentityMFAFactor{ID: "existing-pin", UserID: user.ID, Type: "otp", Provider: "sms", Status: "active", VerifiedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	providers.AddConfig(authmodel.AuthProviderConfig{Key: "sms", Type: "otp", Enabled: true, AllowedPurposes: []string{authmodel.AuthChallengePurposeLoginMFA, authmodel.AuthChallengePurposeAction}})
	outcome, err = flows.LoginWithPasswordOutcome(t.Context(), "workspace-primary", user.Email, password, "domainry-admin")
	if err != nil || outcome.Challenge == nil || outcome.Challenge.Type != "totp" || outcome.Session != nil {
		t.Fatalf("existing PIN policy did not select TOTP: %+v %v", outcome, err)
	}
	loggedIn, err := flows.VerifyOTPOutcome(t.Context(), "workspace-primary", outcome.Challenge.Provider, outcome.Challenge.State, authenticatorCode(t, enrollment.SetupKey, step))
	if err != nil || loggedIn.Session == nil || !strings.Contains(strings.Join(loggedIn.Session.AuthenticationMethods, ","), "totp") {
		t.Fatalf("TOTP login failed: %v", err)
	}
	challenge, err := flows.BeginActionAssurance(t.Context(), "workspace-primary", user.ID)
	if err != nil || challenge.Type != "totp" || challenge.Code != "" {
		t.Fatalf("action challenge failed: %v", err)
	}
	if _, err := flows.VerifyOTPOutcome(t.Context(), "workspace-primary", challenge.Provider, challenge.State, authenticatorCode(t, enrollment.SetupKey, step+1)); err == nil {
		t.Fatal("action challenge was accepted for login")
	}
	receipt, err := flows.VerifyActionAssurance(t.Context(), "workspace-primary", user.ID, challenge.Provider, challenge.State, authenticatorCode(t, enrollment.SetupKey, step+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ValidateActionAssuranceReceipt(t.Context(), receipt.Token, "workspace-primary", user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := flows.VerifyActionAssurance(t.Context(), "workspace-primary", user.ID, challenge.Provider, challenge.State, authenticatorCode(t, enrollment.SetupKey, step+1)); err == nil {
		t.Fatal("action proof was replayed")
	}
}
