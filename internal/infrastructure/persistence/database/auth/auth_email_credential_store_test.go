package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-identity/credentialemail"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	authservice "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"golang.org/x/crypto/bcrypt"
)

type emailDeliveryProbe struct {
	messages []credentialemail.Message
	fail     bool
}

func (*emailDeliveryProbe) Ready(context.Context, string) error { return nil }
func (d *emailDeliveryProbe) Send(_ context.Context, message credentialemail.Message) error {
	d.messages = append(d.messages, message)
	if d.fail {
		return errors.New("delivery unavailable")
	}
	return nil
}
func emailCredentialFixture(t *testing.T) (AuthStore, *authservice.AuthDomainService, *emailDeliveryProbe, identitymodel.IdentityUser) {
	t.Helper()
	repository := newTOTPRepository(t)
	user := identitymodel.IdentityUser{ID: "email-user", Name: "Email User", Email: "email@example.test", Status: identitymodel.IdentityStatusActive, AccountType: identitymodel.IdentityAccountHuman}
	if err := repository.store.UpsertIdentityUser(t.Context(), "workspace-primary", user); err != nil {
		t.Fatal(err)
	}
	auth := authservice.NewAuthDomainService(totpIdentity{user: user}, repository, "email-test-secret", "UnusedDefault!2026", 0, 0, 0, 0, time.Nanosecond, 5, authpolicy.AuthPasswordPolicy{})
	delivery := &emailDeliveryProbe{}
	if err := auth.ConfigureCredentialEmail(delivery, "https://crm.example.test/set-password"); err != nil {
		t.Fatal(err)
	}
	return repository, auth, delivery, user
}
func invitationState(t *testing.T, message credentialemail.Message) string {
	t.Helper()
	for _, line := range strings.Split(message.Text, "\n") {
		if strings.HasPrefix(line, "https://") {
			u, err := url.Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			value, _ := url.ParseQuery(u.Fragment)
			return value.Get("token")
		}
	}
	t.Fatal("invitation has no setup link")
	return ""
}
func TestEmailInvitationUsesThirtyMinuteSingleUseLinkAndAtomicSessionRevocation(t *testing.T) {
	repository, auth, delivery, user := emailCredentialFixture(t)
	receipt, err := auth.SendPasswordInvitation(t.Context(), "workspace-primary", user.ID)
	if err != nil {
		t.Fatal(err)
	}
	expiry, _ := time.Parse(time.RFC3339Nano, receipt.ExpiresAt)
	if receipt.Status != "sent" || time.Until(expiry) < 29*time.Minute || time.Until(expiry) > 30*time.Minute {
		t.Fatal("invitation lifetime is not thirty minutes")
	}
	if _, found, err := repository.GetIdentityCredential(t.Context(), "workspace-primary", user.ID); err != nil || found {
		t.Fatal("invitation issued an initial/default password")
	}
	state := invitationState(t, delivery.messages[0])
	if state == "" || strings.Contains(delivery.messages[0].ID, state) {
		t.Fatal("invitation token leaked into delivery identity")
	}
	now := time.Now().UTC()
	if err := repository.CreateAuthRefreshToken(t.Context(), "workspace-primary", identitymodel.AuthRefreshToken{ID: "old", UserID: user.ID, SessionID: "old-session", TokenHash: "old-hash", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", state, authservice.PasswordSetupPurpose, "", "short"); err == nil {
		t.Fatal("invalid password consumed invitation")
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", state, authservice.PasswordSetupPurpose, "", "NewSecure!2026"); err != nil {
		t.Fatal(err)
	}
	credential, found, err := repository.GetIdentityCredential(t.Context(), "workspace-primary", user.ID)
	if err != nil || !found || credential.MustChangePassword || bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte("NewSecure!2026")) != nil {
		t.Fatal("setup did not establish the selected password")
	}
	if state, err := repository.AuthSessionState(t.Context(), "workspace-primary", user.ID, "old-session", time.Now()); err != nil || state != "revoked" {
		t.Fatalf("prior session survived: %s %v", state, err)
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", state, authservice.PasswordSetupPurpose, "", "Different!2026"); err == nil {
		t.Fatal("invitation was reusable")
	}
}
func TestEmailInvitationRejectsExpiredCrossWorkspaceAndWrongPurpose(t *testing.T) {
	repository, auth, delivery, user := emailCredentialFixture(t)
	receipt, err := auth.SendPasswordInvitation(t.Context(), "workspace-primary", user.ID)
	if err != nil {
		t.Fatal(err)
	}
	state := invitationState(t, delivery.messages[0])
	expiry, _ := time.Parse(time.RFC3339Nano, receipt.ExpiresAt)
	for _, input := range []struct {
		workspace, purpose string
		now                time.Time
	}{{"workspace-other", authservice.PasswordSetupPurpose, time.Now()}, {"workspace-primary", authservice.PasswordRecoveryPurpose, time.Now()}, {"workspace-primary", authservice.PasswordSetupPurpose, expiry}} {
		if _, accepted, err := repository.CompleteEmailCredential(t.Context(), input.workspace, state, input.purpose, "", "unused-hash", 5, input.now); err != nil || accepted {
			t.Fatal("invalid grant accepted", err)
		}
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", state, authservice.PasswordSetupPurpose, "", "StillValid!2026"); err != nil {
		t.Fatal("invalid attempts consumed valid invitation", err)
	}
}
func TestEmailCredentialWriteFailureRollsBackGrantConsumption(t *testing.T) {
	repository, auth, delivery, user := emailCredentialFixture(t)
	if _, err := auth.SendPasswordInvitation(t.Context(), "workspace-primary", user.ID); err != nil {
		t.Fatal(err)
	}
	state := invitationState(t, delivery.messages[0])
	// SQLite trigger DDL has no ORM counterpart; this disposable fixture injects
	// a failure after the grant UPDATE to verify the owner transaction rollback.
	if _, err := repository.db.ExecContext(t.Context(), `CREATE TEMP TRIGGER fail_email_password BEFORE INSERT ON _identity_credentials BEGIN SELECT RAISE(ABORT, 'injected credential failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", state, authservice.PasswordSetupPurpose, "", "AtomicPassword!2026"); err == nil {
		t.Fatal("injected write failure reported success")
	}
	if _, err := repository.db.ExecContext(t.Context(), `DROP TRIGGER fail_email_password`); err != nil {
		t.Fatal(err)
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", state, authservice.PasswordSetupPurpose, "", "AtomicPassword!2026"); err != nil {
		t.Fatal("rolled-back grant could not retry", err)
	}
}
func TestEmailRecoveryCodesAreLimitedAndInvitationsSuperseded(t *testing.T) {
	_, auth, delivery, user := emailCredentialFixture(t)
	if _, err := auth.SendPasswordInvitation(t.Context(), "workspace-primary", user.ID); err != nil {
		t.Fatal(err)
	}
	first := invitationState(t, delivery.messages[0])
	if _, err := auth.SendPasswordInvitation(t.Context(), "workspace-primary", user.ID); err != nil {
		t.Fatal(err)
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", first, authservice.PasswordSetupPurpose, "", "FirstLink!2026"); err == nil {
		t.Fatal("resend retained old invitation")
	}
	challenge, err := auth.StartPasswordRecovery(t.Context(), "workspace-primary", user.Email)
	if err != nil {
		t.Fatal(err)
	}
	body := delivery.messages[len(delivery.messages)-1].Text
	code := strings.Split(strings.Split(body, "验证码：")[1], "\n")[0]
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < 5; i++ {
		if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", challenge.State, authservice.PasswordRecoveryPurpose, wrong, "Recovery!2026"); err == nil {
			t.Fatal("wrong recovery code accepted")
		}
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", challenge.State, authservice.PasswordRecoveryPurpose, code, "Recovery!2026"); err == nil {
		t.Fatal("exhausted code became valid")
	}
	challenge, err = auth.StartPasswordRecovery(t.Context(), "workspace-primary", user.Email)
	if err != nil {
		t.Fatal(err)
	}
	body = delivery.messages[len(delivery.messages)-1].Text
	code = strings.Split(strings.Split(body, "验证码：")[1], "\n")[0]
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", challenge.State, authservice.PasswordRecoveryPurpose, code, "Recovery!2026"); err != nil {
		t.Fatal(err)
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", invitationState(t, delivery.messages[1]), authservice.PasswordSetupPurpose, "", "OldGrant!2026"); err == nil {
		t.Fatal("password change did not invalidate earlier invitation")
	}
}
func TestUnknownRecoveryNeverSendsAndDeliveryFailureCannotActivateLink(t *testing.T) {
	_, auth, delivery, user := emailCredentialFixture(t)
	challenge, err := auth.StartPasswordRecovery(t.Context(), "workspace-primary", "unknown@example.test")
	if err != nil || challenge.State == "" || len(delivery.messages) != 0 {
		t.Fatal("unknown recovery exposed account state or sent mail", err)
	}
	delivery.fail = true
	if _, err := auth.SendPasswordInvitation(t.Context(), "workspace-primary", user.ID); err == nil {
		t.Fatal("delivery failure reported sent")
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", invitationState(t, delivery.messages[0]), authservice.PasswordSetupPurpose, "", "NotDelivered!2026"); err == nil {
		t.Fatal("failed email invitation remained active")
	}
	knownFailure, err := auth.StartPasswordRecovery(t.Context(), "workspace-primary", user.Email)
	if err != nil || knownFailure.State == "" {
		t.Fatal("recovery delivery failure exposed account existence", err)
	}
	if err := auth.CompleteEmailPassword(t.Context(), "workspace-primary", knownFailure.State, authservice.PasswordRecoveryPurpose, "000000", "NotDelivered!2026"); err == nil {
		t.Fatal("failed recovery email remained active")
	}
}
